using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlers;

namespace PandaAuth.Server.Features.Authorization;

internal static class NativeLoginRoute
{
    private const string Path = "/connect/native/authorize-challenge";
    private const string Callback = "connect/native/callback";
    private static readonly TimeSpan AuthorizationCodeLifetime = TimeSpan.FromMinutes(1);

    internal sealed record Settings(string ClientId);

    internal static Settings? ReadSettings(IConfiguration configuration, IHostEnvironment environment, TenantRoutingOptions routing)
    {
        if (!configuration.GetValue<bool>("Auth:NativeLogin:Enabled")) return null;
        var clientId = configuration["Auth:NativeLogin:ClientId"];
        if (!environment.IsDevelopment() || !routing.Enabled || string.IsNullOrWhiteSpace(clientId)
            || clientId.Length > BusinessInputLimits.ClientId)
            throw new InvalidOperationException("Native login requires Development, tenant routing and an explicit client registration.");
        return new Settings(clientId);
    }

    internal static void Configure(OpenIddictServerBuilder options)
    {
        var defaultExtraction = ExtractGetOrPostRequest<ExtractAuthorizationRequestContext>.Descriptor;
        options.Configure(server => server.AuthorizationEndpointUris.Add(new Uri(Path, UriKind.Relative)));
        options.RemoveEventHandler(defaultExtraction);
        options.AddEventHandler<ExtractAuthorizationRequestContext>(handler => handler
            .UseScopedHandler<ExtractNativeRequest>()
            .AddFilter<OpenIddictServerAspNetCoreHandlerFilters.RequireHttpRequest>()
            .SetOrder(defaultExtraction.Order));
        options.AddEventHandler<ApplyAuthorizationResponseContext>(handler => handler
            .UseSingletonHandler<WriteNativeResponse>()
            .SetOrder(int.MinValue + 200_000));
    }

    internal static void Map(WebApplication app) => app.MapPost(Path, HandleAsync);

    private static async Task<IResult> HandleAsync(
        HttpContext http, NativeLoginChallengeService flow, AuthorizationController authorization,
        ITenantContextAccessor tenant, TimeProvider clock, CancellationToken ct)
    {
        if (http.Items[typeof(PendingRequest)] is not PendingRequest pending
            || tenant.Current?.TenantId != pending.Binding.TenantId || http.GetOpenIddictServerRequest() is not { } protocol)
            return Json(http, 400, new { error = Errors.InvalidRequest });
        http.Items.Remove(typeof(PendingRequest));

        var ip = http.Connection.RemoteIpAddress?.ToString();
        var result = pending.Step switch
        {
            "password" => await flow.StartAsync(pending.Binding, pending.UserName!, pending.Secret!, ip, http.Request.Headers.UserAgent.ToString(), ct),
            "totp" => await flow.VerifyTotpAsync(pending.Binding, pending.Handle, pending.Secret!, ip, ct),
            _ => await flow.CancelAsync(pending.Binding, pending.Handle, ip, ct),
        };

        if (result is { Status: NativeLoginStatus.Verified, User: { } user })
        {
            var now = clock.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            var authenticated = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(user)),
                new Claim(LoginSessionService.AuthenticatedAtClaim, now),
                new Claim(PandaAuthClaims.SsoSessionId, Guid.NewGuid().ToString("N")),
                new Claim(MfaClaimTypes.Method, MfaClaimTypes.Totp),
                new Claim(MfaClaimTypes.VerifiedAt, now),
            ], OpenIddictServerAspNetCoreDefaults.AuthenticationScheme));
            authorization.ControllerContext = new ControllerContext { HttpContext = http };
            var principal = await authorization.CreatePrincipalAsync(user, protocol.GetScopes(), authenticated);
            if (HasInvalidPandeskResources(principal))
                return Json(http, 400, new { error = Errors.InvalidScope });
            principal.SetAuthorizationCodeLifetime(AuthorizationCodeLifetime);
            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (result.Status == NativeLoginStatus.RateLimited) http.Response.Headers.RetryAfter = "60";
        return result switch
        {
            { Status: NativeLoginStatus.TotpRequired, Challenge: { } next } =>
                Json(http, 202, new { next_step = "totp", challenge = next.ToString("N") }),
            { Status: NativeLoginStatus.InvalidCredentials, Challenge: { } retry } =>
                Json(http, 401, new { error = "invalid_credentials", challenge = retry.ToString("N") }),
            { Status: NativeLoginStatus.InvalidCredentials } => Json(http, 401, new { error = "invalid_credentials" }),
            { Status: NativeLoginStatus.InvalidChallenge } => Json(http, 409, new { error = "invalid_challenge" }),
            { Status: NativeLoginStatus.Cancelled } => Json(http, 200, new { status = "cancelled" }),
            { Status: NativeLoginStatus.RateLimited } => Json(http, 429, new { error = "rate_limited" }),
            _ => throw new InvalidOperationException("Unexpected native login result."),
        };
    }

    private static IResult Json(HttpContext http, int status, object body)
    {
        http.Response.Headers.CacheControl = "no-store";
        return Results.Json(body, statusCode: status);
    }

    internal static bool HasInvalidPandeskResources(ClaimsPrincipal principal)
    {
        if (!principal.HasScope(PandeskCustomerRead.Scope)) return false;
        var resources = principal.GetResources();
        return resources.Length != 2 || !resources.Contains(PandeskCustomerRead.Audience, StringComparer.Ordinal)
            || !resources.Contains(PandeskCustomerRead.IntrospectionAudience, StringComparer.Ordinal);
    }

    private sealed class ExtractNativeRequest(Settings settings, ITenantHostResolver hosts, IOpenIddictApplicationManager applications)
        : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
    {
        private readonly ExtractGetOrPostRequest<ExtractAuthorizationRequestContext> webExtraction = new();

        public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
        {
            var request = context.Transaction.GetHttpRequest()!;
            if (request.Path != Path)
            {
                await webExtraction.HandleAsync(context);
                if (string.Equals(context.Transaction.Request?.ClientId, settings.ClientId, StringComparison.Ordinal))
                    context.Reject(Errors.InvalidRequest);
                return;
            }

            if (!HttpMethods.IsPost(request.Method) || !request.IsHttps || request.QueryString.HasValue
                || request.ContentLength is null or < 1 or > 8192
                || !MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
                || !string.Equals(contentType.MediaType.Value, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }

            TenantContext tenant;
            try { tenant = hosts.Resolve(request); }
            catch (TenantContextException)
            {
                await RejectHostAsync();
                return;
            }
            var expectedIssuer = new Uri($"https://{tenant.CanonicalHost}/");
            if (request.Host.Port is not (null or 443) || context.Options.Issuer != expectedIssuer)
            {
                await RejectHostAsync();
                return;
            }

            IFormCollection form;
            try { form = await request.ReadFormAsync(context.CancellationToken); }
            catch (InvalidDataException)
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }
            request.Form = FormCollection.Empty;
            if (form.Any(field => field.Value.Count != 1)
                || !string.Equals(form["client_id"], settings.ClientId, StringComparison.Ordinal)
                || form["code_challenge_method"] != CodeChallengeMethods.Sha256
                || !IsBase64Url256(form["code_challenge"].ToString()) || !IsBase64Url256(form["nonce"].ToString()))
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }

            if (await applications.FindByClientIdAsync(settings.ClientId, context.CancellationToken) is not { } application
                || !await applications.HasClientTypeAsync(application, ClientTypes.Public, context.CancellationToken)
                || !await applications.HasRequirementAsync(application, Requirements.Features.ProofKeyForCodeExchange, context.CancellationToken))
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }

            var scope = await applications.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + PandeskCustomerRead.Scope, context.CancellationToken)
                ? $"{Scopes.OpenId} {PandeskCustomerRead.Scope}"
                : Scopes.OpenId;
            var callback = new Uri(expectedIssuer, Callback).AbsoluteUri;
            var binding = new NativeLoginBinding(tenant.TenantId, expectedIssuer, settings.ClientId,
                form["code_challenge"].ToString(), scope, [], callback, form["nonce"].ToString());
            if (ReadStep(form, binding) is not { } pending)
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }

            request.HttpContext.Items[typeof(PendingRequest)] = pending;
            context.Transaction.Request = new OpenIddictRequest
            {
                ClientId = binding.ClientId,
                CodeChallenge = binding.CodeChallenge,
                CodeChallengeMethod = CodeChallengeMethods.Sha256,
                Nonce = binding.Nonce,
                RedirectUri = binding.RedirectUri,
                ResponseType = ResponseTypes.Code,
                Scope = binding.Scope,
            };

            async Task RejectHostAsync()
            {
                await Json(request.HttpContext, 421, new { error = "invalid_issuer" }).ExecuteAsync(request.HttpContext);
                context.HandleRequest();
            }
        }

        private static bool IsBase64Url256(string value)
            => value.Length == 43 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

        private static PendingRequest? ReadStep(IFormCollection form, NativeLoginBinding binding)
        {
            var step = form["step"].ToString();
            if (step == "password" && form.Count == 7)
            {
                var userName = form["username"].ToString().Trim();
                var password = form["password"].ToString();
                return userName.Length is > 0 and <= BusinessInputLimits.Name && password.Length is > 0 and <= BusinessInputLimits.NewPassword
                    ? new PendingRequest(binding, step, Guid.Empty, userName, password) : null;
            }
            if (!Guid.TryParseExact(form["challenge"].ToString(), "N", out var handle)) return null;
            if (step == "cancel" && form.Count == 6) return new(binding, step, handle, null, null);
            var otp = form["otp"].ToString();
            return step == "totp" && form.Count == 7 && otp.Length is > 0 and <= 16
                ? new PendingRequest(binding, step, handle, null, otp) : null;
        }
    }

    private sealed class WriteNativeResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
    {
        public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
        {
            var request = context.Transaction.GetHttpRequest();
            if (request?.Path != Path) return;
            request.HttpContext.Items.Remove(typeof(PendingRequest));
            var response = context.AuthorizationCode is { } code
                ? Json(request.HttpContext, 200, new { authorization_code = code })
                : Json(request.HttpContext, 400, new { error = context.Error ?? Errors.InvalidRequest });
            await response.ExecuteAsync(request.HttpContext);
            context.HandleRequest();
        }
    }

    private sealed class PendingRequest(NativeLoginBinding binding, string step, Guid handle, string? userName, string? secret)
    {
        internal NativeLoginBinding Binding { get; } = binding;
        internal string Step { get; } = step;
        internal Guid Handle { get; } = handle;
        internal string? UserName { get; } = userName;
        internal string? Secret { get; } = secret;
    }
}

using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
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
    internal const string Callback = "connect/native/callback";
    private static readonly TimeSpan AuthorizationCodeLifetime = TimeSpan.FromMinutes(1);

    internal const string PilotConfig = "Auth:NativeLogin:T0000Pilot";
    internal const string PilotRevisionClaim = "urn:pandaauth:internal:pandesk-t0000-revision";
    private static readonly TenantId PilotTenant = TenantId.Parse("t0000");
    internal static readonly string PilotIssuer = $"https://{TenantCanonicalHost.For(PilotTenant, TenantProduct.PandaAuth, "")}/";

    internal sealed record Settings(string ClientId, IReadOnlySet<string>? PilotSubjects = null, string? PilotRevision = null,
        ApiResource? ResourceAccess = null, NativeResourceClient? DedicatedResource = null)
    {
        internal bool AllowsSubject(string subject, IConfiguration configuration)
            => PilotRevision is null || (PilotSubjects!.Contains(subject)
                && PilotRevisionIsCurrent(configuration, PilotRevision)
                && PilotSubjectIsCurrent(configuration, subject));
    }

    internal sealed record ApiResource(string Scope, IReadOnlySet<string> Audiences)
    {
        internal bool HasInvalidAudience(ClaimsPrincipal principal)
            => principal.HasScope(Scope) && !Audiences.SetEquals(principal.GetResources());
    }

    internal static ApiResource? ReadResourceAccess(IConfiguration configuration)
    {
        var section = configuration.GetSection(NativeResourceClient.SectionName);
        var scope = section["Scope"];
        var audiences = section.GetSection("Audiences").Get<string[]>();
        if (scope is null && audiences is null) return null;

        if (string.IsNullOrEmpty(scope) || scope.Length > BusinessInputLimits.Name
            || scope.Any(character => character is < '!' or > '~' or '"' or '\\')
            || scope is Scopes.OpenId or Scopes.OfflineAccess or Scopes.Profile or Scopes.Email
                or Scopes.Address or Scopes.Phone or Scopes.Roles or PandeskCustomerRead.Scope
            || audiences is not { Length: > 0 }
            || audiences.Any(audience => string.IsNullOrEmpty(audience)
                || audience.Length > BusinessInputLimits.Identifier
                || audience.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            || audiences.Distinct(StringComparer.Ordinal).Count() != audiences.Length)
            throw new InvalidOperationException("Native resource access requires a dedicated scope and unique audience identifiers.");

        return new ApiResource(scope, audiences.ToHashSet(StringComparer.Ordinal));
    }

    internal static Settings? ReadSettings(IConfiguration configuration, IHostEnvironment environment, TenantRoutingOptions routing)
    {
        var resourceAccess = ReadResourceAccess(configuration);
        if (!configuration.GetValue<bool>("Auth:NativeLogin:Enabled")) return null;
        var pilot = configuration.GetSection(PilotConfig);
        var pilotEnabled = pilot.GetValue<bool>("Enabled");
        var isPilotIssuer = string.Equals(configuration["Auth:Issuer"], PilotIssuer, StringComparison.Ordinal);
        if (!pilotEnabled && isPilotIssuer) return null;

        var clientId = configuration["Auth:NativeLogin:ClientId"];
        if ((!environment.IsDevelopment() && !(environment.IsProduction() && pilotEnabled))
            || !routing.Enabled || string.IsNullOrWhiteSpace(clientId)
            || clientId.Length > BusinessInputLimits.ClientId)
            throw new InvalidOperationException("Native login requires an eligible environment, tenant routing and an explicit client registration.");
        if (!pilotEnabled)
            return new Settings(clientId, ResourceAccess: resourceAccess);

        var revision = pilot["Revision"];
        var subjects = ReadPilotSubjects(pilot);
        // The resolver uses the first matching binding. A later Ready row cannot
        // activate a host shadowed by a Pending route.
        var binding = routing.Bindings.FirstOrDefault(binding => string.Equals(binding.TenantId, PilotTenant.Value, StringComparison.Ordinal)
            && binding.Product == TenantProduct.PandaAuth && binding.Zone == "");
        if (!Guid.TryParseExact(revision, "D", out var parsedRevision) || parsedRevision == Guid.Empty
            || !isPilotIssuer || binding is not { RouteRevision: > 0, State: TenantRouteState.Ready }
            || subjects is null)
        {
            throw new InvalidOperationException("The t0000 native pilot requires the exact issuer, a ready apex route, a revision and a nonempty subject allowlist.");
        }
        return new Settings(clientId, subjects, revision,
            DedicatedResource: NativeResourceClient.Read(configuration, clientId, resourceAccess));
    }

    internal static bool HasPilotRequestOrigin(HttpRequest request)
        => request.IsHttps && request.Host.Port is null or 443
            && string.Equals($"https://{request.Host.Host}/", PilotIssuer, StringComparison.OrdinalIgnoreCase);

    private static bool PilotRevisionIsCurrent(IConfiguration configuration, string revision)
        => bool.TryParse(configuration["Auth:NativeLogin:Enabled"], out var nativeEnabled) && nativeEnabled
            && bool.TryParse(configuration[$"{PilotConfig}:Enabled"], out var pilotEnabled) && pilotEnabled
            && string.Equals(configuration["Auth:Issuer"], PilotIssuer, StringComparison.Ordinal)
            && string.Equals(configuration[$"{PilotConfig}:Revision"], revision, StringComparison.Ordinal);

    private static bool PilotSubjectIsCurrent(IConfiguration configuration, string subject)
        => ReadPilotSubjects(configuration.GetSection(PilotConfig))?.Contains(subject) == true;

    private static HashSet<string>? ReadPilotSubjects(IConfigurationSection pilot)
    {
        var indexed = pilot.GetSection("AllowedSubjects");
        var json = pilot["AllowedSubjectsJson"];
        string?[]? configured;
        if (string.IsNullOrEmpty(json))
        {
            configured = indexed.GetChildren().Select(entry => entry.Value).ToArray();
        }
        else
        {
            if (indexed.GetChildren().Any()) return null;
            try { configured = JsonSerializer.Deserialize<string?[]>(json); }
            catch (JsonException) { return null; }
        }

        if (configured is not { Length: > 0 }) return null;
        var subjects = new HashSet<string>(StringComparer.Ordinal);
        foreach (var subject in configured)
        {
            if (string.IsNullOrEmpty(subject)
                || subject.Any(character => char.IsWhiteSpace(character) || char.IsControl(character))
                || !subjects.Add(subject))
                return null;
        }
        return subjects;
    }

    internal static bool RejectInactivePilotPrincipal(ClaimsPrincipal principal, IConfiguration configuration)
    {
        var revisions = principal.FindAll(PilotRevisionClaim).ToArray();
        if (revisions.Length == 0 && !(principal.HasScope(PandeskCustomerRead.Scope)
            && (string.Equals(principal.GetClaim(PandaAuthClaims.TenantId), PilotTenant.Value, StringComparison.Ordinal)
                || string.Equals(configuration["Auth:Issuer"], PilotIssuer, StringComparison.Ordinal))))
            return false;

        return revisions.Length != 1 || !PilotRevisionIsCurrent(configuration, revisions[0].Value)
            || principal.GetClaim(Claims.Subject) is not { Length: > 0 } subject
            || !PilotSubjectIsCurrent(configuration, subject);
    }

    internal static void SetPilotRevision(ClaimsPrincipal principal, string revision)
    {
        var identity = (ClaimsIdentity)principal.Identity!;
        identity.AddClaim(new Claim(PilotRevisionClaim, revision).SetDestinations(Destinations.AccessToken));
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
        ITenantContextAccessor tenant, TimeProvider clock, Settings settings, CancellationToken ct)
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
            if (pending.Binding.ResourceRevision is not null)
            {
                if (settings.DedicatedResource is not { } resource
                    || !resource.IsCurrent(http.RequestServices.GetRequiredService<IConfiguration>()) || !resource.Allows(principal))
                    return Json(http, 400, new { error = Errors.InvalidScope });
                resource.Mark(principal);
            }
            else
            {
                if (HasInvalidPandeskResources(principal) || settings.ResourceAccess?.HasInvalidAudience(principal) == true)
                    return Json(http, 400, new { error = Errors.InvalidScope });
                if (settings.PilotRevision is { } revision) SetPilotRevision(principal, revision);
            }
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
            var configuration = request.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            if (request.Path != Path)
            {
                await webExtraction.HandleAsync(context);
                var webClient = context.Transaction.Request?.ClientId;
                if (webClient == settings.ClientId || NativeResourceClient.IsConfiguredClient(configuration, webClient))
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
            if (request.Host.Port is not (null or 443) || context.Options.Issuer != expectedIssuer
                || (settings.PilotSubjects is not null && !HasPilotRequestOrigin(request)))
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
            var clientId = form["client_id"].ToString();
            var dedicated = settings.DedicatedResource is { } candidate && candidate.ClientId == clientId ? candidate : null;
            if (form.Any(field => field.Value.Count != 1)
                || (dedicated is null && clientId != settings.ClientId)
                || (dedicated is not null && !dedicated.IsCurrent(configuration))
                || (dedicated is null && settings.PilotRevision is { } revision && !PilotRevisionIsCurrent(configuration, revision))
                || form["code_challenge_method"] != CodeChallengeMethods.Sha256
                || !IsBase64Url256(form["code_challenge"].ToString()) || !IsBase64Url256(form["nonce"].ToString()))
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }

            if (await applications.FindByClientIdAsync(clientId, context.CancellationToken) is not { } application
                || !await applications.HasClientTypeAsync(application, ClientTypes.Public, context.CancellationToken)
                || !await applications.HasRequirementAsync(application, Requirements.Features.ProofKeyForCodeExchange, context.CancellationToken))
            {
                context.Reject(Errors.InvalidRequest);
                return;
            }

            var hasCustomerRead = await applications.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + PandeskCustomerRead.Scope, context.CancellationToken);
            var resource = dedicated?.Resource ?? settings.ResourceAccess;
            var hasResource = resource is not null && await applications.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + resource.Scope, context.CancellationToken);
            if (dedicated is not null ? (!hasResource || hasCustomerRead) : settings.PilotSubjects is not null && !hasCustomerRead)
            {
                context.Reject(Errors.InvalidScope);
                return;
            }

            var scopes = new List<string> { Scopes.OpenId };
            if (hasCustomerRead) scopes.Add(PandeskCustomerRead.Scope);
            if (hasResource) scopes.Add(resource!.Scope);
            var scope = string.Join(' ', scopes);
            var callback = new Uri(expectedIssuer, Callback).AbsoluteUri;
            var binding = new NativeLoginBinding(tenant.TenantId, expectedIssuer, clientId,
                form["code_challenge"].ToString(), scope, [], callback, form["nonce"].ToString(), dedicated?.Revision);
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

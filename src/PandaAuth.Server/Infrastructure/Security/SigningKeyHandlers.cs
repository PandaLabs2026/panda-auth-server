using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;

namespace PandaAuth.Server.Infrastructure.Security;

internal sealed class SelectLiveSigningKey(SigningKeyRing ring)
    : IOpenIddictServerHandler<OpenIddictServerEvents.GenerateTokenContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.GenerateTokenContext context)
    {
        var start = context.Principal.GetCreationDate();
        var end = context.Principal.GetExpirationDate();
        if (!ring.IsReady(out _) || start is null || end is null || end <= start
            || end - start > SigningKeyRing.MaximumTokenLifetime)
        {
            context.Reject(OpenIddictConstants.Errors.ServerError, "Token signing is unavailable.");
            return ValueTask.CompletedTask;
        }
        context.SigningCredentials = ring.Signer();
        return ValueTask.CompletedTask;
    }
}

internal sealed class LiveServerVerificationKeys(SigningKeyRing ring)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenContext context)
    {
        if (!context.ValidTokenTypes.Contains(OpenIddictConstants.TokenTypeIdentifiers.Private.ClientAssertion))
        {
            context.TokenValidationParameters.IssuerSigningKey = null;
            context.TokenValidationParameters.IssuerSigningKeys = ring.VerificationKeys();
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class LiveLocalVerificationKeys(SigningKeyRing ring)
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ValidateTokenContext>
{
    public ValueTask HandleAsync(OpenIddictValidationEvents.ValidateTokenContext context)
    {
        context.TokenValidationParameters.IssuerSigningKey = null;
        context.TokenValidationParameters.IssuerSigningKeys = ring.VerificationKeys();
        return ValueTask.CompletedTask;
    }
}

internal sealed class PublishLiveSigningKeys(SigningKeyRing ring)
    : IOpenIddictServerHandler<OpenIddictServerEvents.HandleJsonWebKeySetRequestContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.HandleJsonWebKeySetRequestContext context)
    {
        context.Keys.Clear();
        foreach (var key in ring.VerificationKeys())
        {
            var publicKey = JsonWebKeyConverter.ConvertFromRSASecurityKey((RsaSecurityKey)key);
            publicKey.Use = "sig";
            publicKey.Alg = SecurityAlgorithms.RsaSha256;
            context.Keys.Add(publicKey);
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class SigningKeyHealthCheck(SigningKeyRing ring) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(ring.IsReady(out var reason) ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy(reason));
}

internal sealed class SigningKeyRefreshService(SigningKeyRing ring, ILogger<SigningKeyRefreshService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60), ring.Clock);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await ring.RefreshAsync(stoppingToken);
                var snapshot = ring.Snapshot;
                ring.IsReady(out var status);
                logger.LogInformation("Signing key refresh: status={Status} kid={KeyId} nextSwitch={NextSwitch} snapshotAgeSeconds={Age}",
                    status, status == "ready" ? ring.Signer().Key.KeyId : null,
                    snapshot.Keys.Where(key => key.StartsAt > ring.Clock.GetUtcNow()).MinBy(key => key.StartsAt)?.StartsAt,
                    (ring.Clock.GetUtcNow() - snapshot.RefreshedAt).TotalSeconds);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception exception)
            {
                logger.LogError("Signing key refresh failed: errorType={ErrorType} snapshotAgeSeconds={Age}",
                    exception.GetType().Name, (ring.Clock.GetUtcNow() - ring.Snapshot.RefreshedAt).TotalSeconds);
            }
        }
    }
}

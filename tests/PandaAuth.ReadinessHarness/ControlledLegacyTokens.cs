using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace PandaAuth.ReadinessHarness;

/// <summary>Offline OpenIddict generation/validation; caller supplies only an admitted isolated service scope.</summary>
public static class ControlledLegacyTokens
{
    private static void Require(bool value)=>ControlledProtocolContext.Require(value);
    private static void Admit(ControlledTransportSpec spec,string type)
    {ControlledTransport.Validate(spec);Require(type is TokenTypeIdentifiers.AccessToken or TokenTypeIdentifiers.RefreshToken);}
    public static async Task<string> Generate(IServiceProvider services,ControlledTransportSpec spec,string type)
    {
        Admit(spec,type);var client=ControlledActors.Names(spec)[3];var now=DateTimeOffset.UtcNow;
        var principal=new ClaimsPrincipal(new ClaimsIdentity("legacy-offline"));
        principal.SetClaim(Claims.Subject,ControlledActors.Subject(spec,1));
        principal.SetClaim(Claims.Name,ControlledActors.Names(spec)[1]);
        principal.SetClaim(Claims.Private.Issuer,spec.Issuer);principal.SetCreationDate(now);principal.SetExpirationDate(now.AddHours(1));
        principal.SetPresenters(client);principal.SetScopes(Scopes.OpenId,Scopes.Profile,Scopes.OfflineAccess);principal.SetResources("api");
        var factory=services.GetRequiredService<IOpenIddictServerFactory>();
        var transaction=await factory.CreateTransactionAsync();
        var context=new OpenIddictServerEvents.GenerateTokenContext(transaction){ClientId=client,Principal=principal,
            TokenType=type,TokenFormat=TokenFormats.Private.JsonWebToken,CreateTokenEntry=true,IsReferenceToken=false,PersistTokenPayload=false};
        await services.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);
        Require(!context.IsRejected&&!string.IsNullOrEmpty(context.Token));
        await Verify(services,spec,type,context.Token!);return context.Token!;
    }
    public static async Task Verify(IServiceProvider services,ControlledTransportSpec spec,string type,string token)
    {
        Admit(spec,type);Require(token.Length is >100 and <=65536);
        var transaction=await services.GetRequiredService<IOpenIddictServerFactory>().CreateTransactionAsync();
        var context=new OpenIddictServerEvents.ValidateTokenContext(transaction){Token=token};context.ValidTokenTypes.Add(type);
        await services.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);
        var principal=context.Principal;
        if(context.IsRejected||principal is null)throw new InvalidOperationException("legacy_token_validation_rejected");
        if(principal.GetClaim(Claims.Subject)!=ControlledActors.Subject(spec,1))throw new InvalidOperationException("legacy_token_subject_invalid");
        if(principal.HasClaim(claim=>claim.Type==PandaAuthClaims.SecurityVersion))throw new InvalidOperationException("legacy_token_version_present");
        if(!principal.GetPresenters().Contains(ControlledActors.Names(spec)[3]))throw new InvalidOperationException("legacy_token_presenter_invalid");
        if(!(principal.GetCreationDate()<=DateTimeOffset.UtcNow&&principal.GetExpirationDate()>DateTimeOffset.UtcNow))throw new InvalidOperationException("legacy_token_dates_invalid");
        if(string.IsNullOrEmpty(principal.GetTokenId()))throw new InvalidOperationException("legacy_token_entry_missing");
        var manager=services.GetRequiredService<IOpenIddictTokenManager>();
        var entry=await manager.FindByIdAsync(principal!.GetTokenId()!);
        Require(entry is not null&&await manager.HasStatusAsync(entry,Statuses.Valid)&&await manager.HasTypeAsync(entry,type)&&
            await manager.GetSubjectAsync(entry)==ControlledActors.Subject(spec,1));
    }
}
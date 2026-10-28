using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace PandaAuth.ReadinessHarness;
internal sealed record ControlledLegacyTokenSnapshot(int Schema,string SpecSha256,string DatabaseFingerprint,string AccessToken,string RefreshToken);
public static class ControlledLegacyTokenProtocol
{
    private const string LegacySql="SELECT count(*) AS \"Value\" FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\"='20261025074425_OnlineSigningKeyLifecycle'";
    public static async Task<int> Dispatch(string command,string line)
    {
        var keys=new List<RSA>();var stage="admission";
        try
        {
            ControlledProtocolContext.Require(command is "--controlled-legacy-tokens-create-stdin" or "--controlled-legacy-tokens-verify-stdin");
            var input=ControlledTransport.Decode<ControlledCryptoInput>(line);var context=await ControlledProtocolContext.Open(input);
            var create=command=="--controlled-legacy-tokens-create-stdin";
            context.Write(create?"legacy-tokens-create-started.json":"legacy-tokens-verify-started.json",new{schema=1,specSha256=context.Binding});
            var bearerStatus=0;var refreshStatus=0;
            if(create)
            {
                stage="legacy-keys";
                ControlledProtocolContext.Require(context.DataFingerprint==input.RestoredDatabaseFingerprint&&string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDA_AUTH_CONTROLLED_PARENT_SHA256")));
                var credentials=new Dictionary<string,RsaSecurityKey>();
                await using(var connection=new NpgsqlConnection(ControlledCryptography.Connection(input.ConnectionString).ConnectionString))
                {
                    await connection.OpenAsync();
                    await using(var query=new NpgsqlCommand(LegacySql,connection))ControlledProtocolContext.Require((long)(await query.ExecuteScalarAsync())! ==0);
                    await using var queryKeys=new NpgsqlCommand("SELECT \"KeyId\",\"Use\",\"Algorithm\",\"PrivateKey\" FROM signing_keys WHERE \"NotBefore\"<=now() AND \"NotAfter\">now()+interval '1 hour' AND NOT \"Retired\" ORDER BY \"NotBefore\" DESC,\"KeyId\" LIMIT 512",connection);
                    await using var reader=await queryKeys.ExecuteReaderAsync();
                    while(await reader.ReadAsync())
                    {
                        var use=reader.GetString(1);if(credentials.ContainsKey(use))continue;
                        var bytes=reader.GetFieldValue<byte[]>(3);
                        try
                        {
                            ControlledCryptography.InspectRsa(use,reader.GetString(2),bytes);
                            var rsa=RSA.Create();keys.Add(rsa);rsa.ImportPkcs8PrivateKey(bytes,out var read);ControlledProtocolContext.Require(read==bytes.Length);
                            credentials.Add(use,new RsaSecurityKey(rsa){KeyId=reader.GetString(0)});
                        }
                        finally{CryptographicOperations.ZeroMemory(bytes);}
                    }
                }
                ControlledProtocolContext.Require(credentials.Count==2&&credentials.ContainsKey(KeyUse.Signing)&&credentials.ContainsKey(KeyUse.Encryption));
                var services=new ServiceCollection().AddLogging(logging=>logging.ClearProviders());
                services.AddDbContext<PandaAuthDbContext>(options=>options.UseNpgsql(ControlledCryptography.Connection(input.ConnectionString).ConnectionString).UseOpenIddict());
                services.AddOpenIddict().AddCore(options=>options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>())
                    .AddServer(options=>{options.SetIssuer(input.Spec.Issuer).SetTokenEndpointUris(PandaAuthEndpoints.Token).AllowRefreshTokenFlow();
                        options.AddSigningKey(credentials[KeyUse.Signing]);options.AddEncryptionKey(credentials[KeyUse.Encryption]);});
                await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
                var db=scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                await using var transaction=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
                ControlledProtocolContext.Require(await db.Database.SqlQueryRaw<long>(LegacySql).SingleAsync()==0);
                var subject=ControlledActors.Subject(input.Spec,1);
                ControlledProtocolContext.Require(await db.Users.AnyAsync(user=>user.Id==subject&&user.UserName==context.Actors.Names[1]));
                stage="generate";
                var access=await ControlledLegacyTokens.Generate(scope.ServiceProvider,input.Spec,TokenTypeIdentifiers.AccessToken);
                var refresh=await ControlledLegacyTokens.Generate(scope.ServiceProvider,input.Spec,TokenTypeIdentifiers.RefreshToken);
                ControlledProtocolContext.Require(await db.Database.SqlQueryRaw<long>(LegacySql).SingleAsync()==0);
                await transaction.CommitAsync();
                context.Write("legacy-tokens.json",new ControlledLegacyTokenSnapshot(1,context.Binding,context.DataFingerprint,access,refresh));
            }
            else
            {
                stage="http";
                var stored=ControlledProtocolContext.Read<ControlledLegacyTokenSnapshot>(context.Root,"legacy-tokens.json",131072);
                ControlledProtocolContext.Require(stored.Schema==1&&stored.SpecSha256==context.Binding&&stored.DatabaseFingerprint==context.DataFingerprint);
                using var root=context.Certificate();using var browser=ProtocolUser.CreateBrowser(new Uri(input.Spec.Issuer),root,new CookieContainer());
                using var request=new HttpRequestMessage(HttpMethod.Get,PandaAuthEndpoints.Userinfo);request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",stored.AccessToken);
                using var bearer=await browser.SendAsync(request);bearerStatus=(int)bearer.StatusCode;
                using var form=new FormUrlEncodedContent(new Dictionary<string,string>{{"grant_type","refresh_token"},{"refresh_token",stored.RefreshToken},
                    {"client_id",context.Actors.Names[3]},{"client_secret",context.Actors.ClientSecret}});
                using var refresh=await browser.PostAsync(PandaAuthEndpoints.Token,form);refreshStatus=(int)refresh.StatusCode;
                ControlledProtocolContext.Require(bearer.StatusCode==HttpStatusCode.Unauthorized&&refresh.StatusCode==HttpStatusCode.BadRequest);
                using var response=JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
                ControlledProtocolContext.Require(response.RootElement.GetProperty("error").GetString()=="invalid_grant");
            }
            Console.WriteLine(JsonSerializer.Serialize(new{schema=1,scope="controlled-legacy-token-component",valid=true,operation=create?"create":"verify",bearerStatus,refreshStatus}));return 0;
        }
        catch(Exception error){Console.WriteLine(JsonSerializer.Serialize(new{schema=1,valid=false,error="controlled_legacy_token_failed",stage,kind=error.GetType().Name}));return 2;}
        finally{foreach(var rsa in keys)rsa.Dispose();}
    }
}
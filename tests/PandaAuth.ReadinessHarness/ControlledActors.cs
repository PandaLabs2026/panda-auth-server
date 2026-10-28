using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.ReadinessHarness;

public sealed record ControlledActorsInput(ControlledCryptoInput Crypto,string MigrationConnection);
internal sealed record ControlledActorSecrets(int Schema,string SpecSha256,string DatabaseFingerprint,string[] Names,
    string Password,string ClientSecret,string TotpSecret);

/// <summary>Clone-only nonce actors after original-state cryptographic admission. Never a production seeder.</summary>
public static class ControlledActors
{
    private static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    private static void Require(bool condition)
    { if(!condition) throw new InvalidOperationException("controlled_actors_failed"); }
    public static string[] Names(ControlledTransportSpec spec)
    {
        ControlledTransport.Validate(spec);
        return ["r1-controlled-admin-"+spec.Attempt+"@example.invalid","r1-controlled-"+spec.Attempt+"-0",
            "r1-controlled-"+spec.Attempt+"-1","r1-controlled-client-"+spec.Attempt];
    }
    public static string Subject(ControlledTransportSpec spec,int index)
    {
        ControlledTransport.Validate(spec);Require(index is >=0 and <3);
        return new Guid(SHA256.HashData(Encoding.UTF8.GetBytes("r1-controlled\0"+spec.Attempt+"\0"+index))[..16]).ToString("D");
    }
    internal static void Write(string path,byte[] bytes)
    {
        if(!OperatingSystem.IsLinux())throw new InvalidOperationException("controlled_actors_failed");
        using var output=new FileStream(path,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,
            UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});output.Write(bytes);output.Flush(true);
    }
    public static async Task<int> Dispatch(string line)
    {
        try
        {
            if(!OperatingSystem.IsLinux())throw new InvalidOperationException("controlled_actors_failed");
            var input=ControlledTransport.Decode<ControlledActorsInput>(line);var crypto=input.Crypto;
            var root=ControlledTransport.Guard(crypto.Spec);
            Require(Directory.Exists(root) && new DirectoryInfo(root).LinkTarget is null);
            var current=await ControlledCryptoSnapshot.Read(crypto);
            var key=Convert.FromBase64String(crypto.TotpKey);
            try
            {
                var protector=new TotpSecretProtector(key,crypto.TotpKeyVersion);
                ControlledCryptoCommand.VerifyBaseline(root,crypto,current,protector);
                var runtime=ControlledCryptography.Connection(crypto.ConnectionString);
                var migration=new NpgsqlConnectionStringBuilder(input.MigrationConnection);
                Require(migration.Host==runtime.Host && migration.Port==runtime.Port && migration.Database==runtime.Database &&
                    migration.Username==runtime.Database+"_migrator" && !string.IsNullOrEmpty(migration.Password));
                migration.Pooling=false;migration.Timeout=10;migration.CommandTimeout=30;
                var binding=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ControlledTransport.Canonical(crypto.Spec))));
                Write(Path.Combine(root,"actors-started.json"),JsonSerializer.SerializeToUtf8Bytes(new{schema=1,specSha256=binding},Json));
                var services=new ServiceCollection().AddLogging(logging=>logging.ClearProviders());
                services.AddDbContext<PandaAuthDbContext>(options=>options.UseNpgsql(migration.ConnectionString).UseOpenIddict());
                services.AddUserStore();services.AddOpenIddict().AddCore(options=>options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
                await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
                var db=scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                await using var transaction=await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
                var names=Names(crypto.Spec);var users=scope.ServiceProvider.GetRequiredService<UserService>();
                var subjects=Enumerable.Range(0,3).Select(index=>Subject(crypto.Spec,index)).ToArray();
                var apps=scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                Require(await db.Roles.AnyAsync(role=>role.NormalizedName==PandaAuthRoles.Admin.ToUpperInvariant()));
                Require(!await db.Users.AnyAsync(user=>names.Take(3).Contains(user.UserName!) || subjects.Contains(user.Id)) &&
                    await apps.FindByClientIdAsync(names[3]) is null);
                var password="R1!a"+Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                var clientSecret=Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
                var totpSecret=RandomNumberGenerator.GetBytes(20);
                for(var index=0;index<3;index++)
                {
                    var user=new PandaUser{Id=subjects[index],UserName=names[index],
                        Email=index==0?names[index]:names[index]+"@example.invalid",EmailConfirmed=true};
                    Require((await users.CreateAsync(user,password)).Succeeded);
                    if(index==0)
                    {
                        Require((await users.AddToRoleAsync(user,PandaAuthRoles.Admin)).Succeeded);
                        var id=Guid.NewGuid();var cipher=protector.Protect(user.Id,id,totpSecret);
                        db.TotpFactors.Add(new MfaTotpFactor{Id=id,UserId=user.Id,KeyVersion=cipher.KeyVersion,Nonce=cipher.Nonce,
                            Ciphertext=cipher.Ciphertext,Tag=cipher.Tag,ConfirmedAt=DateTimeOffset.UtcNow});
                        user.TwoFactorEnabled=true;await db.SaveChangesAsync();
                    }
                }
                await apps.CreateAsync(new OpenIddictApplicationDescriptor{ClientId=names[3],ClientSecret=clientSecret,
                    ClientType=ClientTypes.Confidential,ConsentType=ConsentTypes.Implicit,RedirectUris={new Uri(new Uri(crypto.Spec.Issuer),"/callback")},
                    Permissions={Permissions.Endpoints.Authorization,Permissions.Endpoints.Token,Permissions.Endpoints.Revocation,
                        Permissions.GrantTypes.AuthorizationCode,Permissions.GrantTypes.RefreshToken,Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Profile,Permissions.Prefixes.Scope+Scopes.OfflineAccess}});
                await transaction.CommitAsync();
                Write(Path.Combine(root,"actors.json"),JsonSerializer.SerializeToUtf8Bytes(new ControlledActorSecrets(1,binding,
                    crypto.RestoredDatabaseFingerprint,names,password,clientSecret,Convert.ToBase64String(totpSecret)),Json));
                CryptographicOperations.ZeroMemory(totpSecret);
                Console.WriteLine(JsonSerializer.Serialize(new{schema=1,scope="controlled-actors-component",valid=true,specSha256=binding,users=3,clients=1},Json));
                return 0;
            }
            finally{CryptographicOperations.ZeroMemory(key);}
        }
        catch{Console.WriteLine("{\"schema\":1,\"valid\":false,\"error\":\"controlled_actors_failed\"}");return 2;}
    }
}

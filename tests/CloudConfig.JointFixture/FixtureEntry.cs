using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
namespace PandaAuth.CloudConfig.JointFixture;

public sealed record JointHostPolicy(string Root,string PgSocket,string RunId,string CertificateBase64,string UserPassword,string IntrospectionSecret,string ConsoleSecret);
public static class FixtureEntry
{
    [DllImport("libc")]private static extern uint geteuid();
    public static async Task<int> Main(string[] args)
    {
        if (args is ["--account-security-stdin"]) return await AccountSecurityProbe.RunAsync();
        if (args is ["--signing-key-refresh-stdin"]) return await AccountSecurityProbe.RunAsync(keyRefresh: true);
        string? database=null;string? baseConnection=null;string? content=null;string? nonce=null;var exit=0;var createdDatabase=false;string? diagnosticsRoot=null;string? previousDirectory=null;var stage="admission";
        try
        {
            if(!OperatingSystem.IsLinux()||geteuid()==0||args.Length!=1||args[0]!="--fixture-stdin")throw new InvalidOperationException();
            var line=new StringBuilder();var one=new char[1];
            while(await Console.In.ReadAsync(one)==1){if(one[0]=='\n')break;if(line.Length>=131072)throw new InvalidOperationException();line.Append(one[0]);}
            using var document=JsonDocument.Parse(line.ToString(),new JsonDocumentOptions{MaxDepth=16});
            if(document.RootElement.EnumerateObject().Select(p=>p.Name).Distinct().Count()!=document.RootElement.EnumerateObject().Count())throw new InvalidOperationException();
            var p=JsonSerializer.Deserialize<JointHostPolicy>(line.ToString(),new JsonSerializerOptions{UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,RespectRequiredConstructorParameters=true})??throw new InvalidOperationException();
            nonce=p.RunId;var temporary=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"dev","tmp");
            if(!Regex.IsMatch(p.RunId,"\\A[a-f0-9]{32}\\z")||!Regex.IsMatch(p.PgSocket,"\\A"+Regex.Escape(temporary)+"/(authpg|cfgpg)-[A-Za-z0-9]+/socket\\z")||Path.GetFullPath(p.Root)!=p.Root||!p.Root.StartsWith(temporary+"/",StringComparison.Ordinal)||p.UserPassword.Length<20||p.IntrospectionSecret.Length<32||p.ConsoleSecret.Length<32)throw new InvalidOperationException();
            for(var directory=p.Root;directory!=temporary;directory=Path.GetDirectoryName(directory)!)
                if(new DirectoryInfo(directory).LinkTarget is not null||(File.GetUnixFileMode(directory)&(UnixFileMode)0x3f)!=0||(File.GetUnixFileMode(directory)&(UnixFileMode)0x1c0)!=(UnixFileMode)0x1c0)throw new InvalidOperationException();
            var environment=Environment.GetEnvironmentVariables().Keys.Cast<string>();
            if(environment.Any(name=>name.StartsWith("ConnectionStrings__",StringComparison.OrdinalIgnoreCase)||name.StartsWith("Auth__",StringComparison.OrdinalIgnoreCase)||name.StartsWith("Kestrel__",StringComparison.OrdinalIgnoreCase)||name is "ASPNETCORE_URLS" or "DOTNET_URLS"))throw new InvalidOperationException();
            diagnosticsRoot=p.Root;stage="database";var connection=new NpgsqlConnectionStringBuilder{Host=p.PgSocket,Database="postgres",Username="auth_config_fixture_owner",Pooling=false,Timeout=5,CommandTimeout=15,IncludeErrorDetail=false};baseConnection=connection.ConnectionString;
            await using(var root=new NpgsqlConnection(baseConnection))
            {await root.OpenAsync();await Proof(root,p.RunId);database="auth_config_test_"+Guid.NewGuid().ToString("N");await using var create=new NpgsqlCommand("create database \""+database+"\"",root);await create.ExecuteNonQueryAsync();createdDatabase=true;await using var restrict=new NpgsqlCommand("revoke connect on database \""+database+"\" from public",root);await restrict.ExecuteNonQueryAsync();}
            connection.Database=database;stage="migration";
            await using(var db=new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>().UseNpgsql(connection.ConnectionString).UseOpenIddict().Options))await db.Database.MigrateAsync();
            stage="seed";var services=new ServiceCollection();services.AddLogging();services.AddSingleton(Options.Create(new AuthOptions{Issuer=CloudConfigScopes.Issuer,Seed=new SeedOptions{Enabled=true,Admin=new(){Password=""},Me=new(){Enabled=false},AdminWeb=new(){Enabled=false},CloudConfig=new(){Enabled=true,ClientSecret=p.IntrospectionSecret},CloudConsoleWeb=new(){Enabled=true,ClientSecret=p.ConsoleSecret,RedirectUris=["https://localhost/callback","https://localhost/callback/pandaauth"],PostLogoutRedirectUris=["https://localhost/logout"]}}}));
            services.AddDbContext<PandaAuthDbContext>(options=>options.UseNpgsql(connection.ConnectionString).UseOpenIddict());services.AddUserStore();services.AddOpenIddict().AddCore(options=>options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            await using(var provider=services.BuildServiceProvider())
            {
                var users=provider.GetRequiredService<UserService>();
                var user=new PandaUser{UserName="config-joint-user",Email="config-joint@example.test",EmailConfirmed=true};
                if(!(await users.CreateAsync(user,p.UserPassword)).Succeeded)throw new InvalidOperationException();
                await DbSeeder.SeedAsync(provider);
                var roles=provider.GetRequiredService<RoleService>();
                if(!await roles.RoleExistsAsync("cloud-admin")&&!(await roles.CreateAsync(new PandaRole{Name="cloud-admin"})).Succeeded)throw new InvalidOperationException();
                if(!(await users.AddToRoleAsync(user,"cloud-admin")).Succeeded)throw new InvalidOperationException();
            }
            stage="content";content=Path.Combine(p.Root,"content");if(Directory.Exists(content))throw new InvalidOperationException();Directory.CreateDirectory(content);File.SetUnixFileMode(content,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);Directory.CreateDirectory(Path.Combine(content,"wwwroot","brand"));
            var json=JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,"fixture-defaults.json")))!.AsObject();
            foreach(var setting in new Dictionary<string,string>{{"ConnectionStrings:Default",connection.ConnectionString},{"Auth:Issuer",CloudConfigScopes.Issuer},{"Auth:HttpsRequired","true"},{"Auth:Seed:Enabled","false"},{"Auth:Seed:CloudConfig:Enabled","true"},{"Auth:Seed:CloudConfig:ClientSecret",p.IntrospectionSecret}})
            {var keys=setting.Key.Split(':');var parent=json;foreach(var key in keys[..^1]){if(parent[key] is not JsonObject child)parent[key]=child=new JsonObject();parent=child;}parent[keys[^1]]=setting.Value;}
            var settings=Path.Combine(content,"appsettings.json");await File.WriteAllTextAsync(settings,json.ToJsonString());File.SetUnixFileMode(settings,UnixFileMode.UserRead|UnixFileMode.UserWrite);
            using var certificate=X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(p.CertificateBase64),null,X509KeyStorageFlags.EphemeralKeySet);if(!certificate.HasPrivateKey)throw new InvalidOperationException();
            // WAF reads this private bootstrap manifest before ConfigureWebHost.
            // Do not add environment settings that become unsupported real Server CLI arguments.
            await using(var manifest=new FileStream(Path.Combine(content,"MvcTestingAppManifest.json"),new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))
                await JsonSerializer.SerializeAsync(manifest,new Dictionary<string,string>{{typeof(global::Program).Assembly.GetName().FullName,content}});
            previousDirectory=Environment.CurrentDirectory;Directory.SetCurrentDirectory(content);
            stage="host";await using(var factory=new Host(content))
            {factory.UseKestrel(options=>options.ListenUnixSocket(Path.Combine(p.Root,"auth.sock"),listen=>listen.UseHttps(certificate)));factory.StartServer();stage="metadata";await using(var metadata=new FileStream(Path.Combine(p.Root,"client.json"),new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))await JsonSerializer.SerializeAsync(metadata,new{ConsoleClientId=FirstPartyClients.CloudConsoleWeb,ConsoleCallback="https://localhost/callback/pandaauth",ConsoleRole="cloud-admin"});Console.WriteLine("AUTH_CONFIG_JOINT_READY");await Console.Out.FlushAsync();await Console.In.ReadLineAsync();}
        }
        catch(Exception failure)
        {
            if(diagnosticsRoot is not null)
            {try{await using var diagnostic=new FileStream(Path.Combine(diagnosticsRoot,"failure.json"),new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});await JsonSerializer.SerializeAsync(diagnostic,new{stage,type=failure.GetType().FullName,sqlState=(failure as PostgresException)?.SqlState,stack=failure.StackTrace});}catch{}}
            Console.Error.WriteLine("AUTH_CONFIG_JOINT_NOT_ADMITTED");exit=78;
        }
        finally
        {
            try{if(previousDirectory is not null)Directory.SetCurrentDirectory(previousDirectory);if(content is not null&&Directory.Exists(content))Directory.Delete(content,true);}catch{exit=75;}
            if(createdDatabase&&database is not null&&baseConnection is not null)
            {try{await using var c=new NpgsqlConnection(baseConnection);await c.OpenAsync();await Proof(c,nonce!);await using var drop=new NpgsqlCommand("drop database \""+database+"\" with(force)",c);await drop.ExecuteNonQueryAsync();}catch{exit=75;}}
        }
        return exit;
    }
    private static async Task Proof(NpgsqlConnection c,string nonce)
    {await using var q=new NpgsqlCommand("select current_setting('pandalabs.fixture_id',true)",c);if(!Equals(await q.ExecuteScalarAsync(),nonce))throw new InvalidOperationException();}
    private sealed class Host(string root):WebApplicationFactory<global::Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {builder.UseEnvironment("Development");builder.UseContentRoot(root);builder.ConfigureLogging(logging=>logging.ClearProviders());builder.ConfigureTestServices(services=>services.AddDataProtection().UseEphemeralDataProtectionProvider());}
    }
}

using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

// Synthetic fixture provisioning only. Strictly bounded to this task's disposable PostgreSQL.
try
{
    if (!OperatingSystem.IsLinux()) throw new InvalidOperationException();
    if (args.Length != 1 || args[0] is not ("create" or "inspect" or "cleanup" or "negative-clients")) throw new InvalidOperationException();
    var root = Environment.GetEnvironmentVariable("PANDAMADE_FIXTURE_ROOT") ?? "";
    if (!Path.IsPathFullyQualified(root) || !Path.GetFullPath(root).StartsWith(Path.Combine(Path.GetTempPath(),"pandamade-business-test")+Path.DirectorySeparatorChar,StringComparison.Ordinal) ||
        !Directory.Exists(root) || new DirectoryInfo(root).LinkTarget is not null) throw new InvalidOperationException();
    var baseConnection = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDAMADE_TEST_POSTGRES"));
    if (baseConnection.Host != "127.0.0.1" || (baseConnection.Port != 43853 && !(baseConnection.Port == 5432 && Environment.GetEnvironmentVariable("PANDAMADE_TEST_SHARED_INSTANCE") == "1")) || baseConnection.Database != "postgres" || baseConnection.Username != "pandamade_fixture") throw new InvalidOperationException();
    if (args[0] != "create")
    {
        using var stored=JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root,"state.json")));
        var saved=new NpgsqlConnectionStringBuilder(stored.RootElement.GetProperty("identityConnection").GetString());
        var nameToUse=saved.Database ?? "";
        if (saved.Host != "127.0.0.1" || (saved.Port != 43853 && !(saved.Port == 5432 && Environment.GetEnvironmentVariable("PANDAMADE_TEST_SHARED_INSTANCE") == "1")) || saved.Username != "pandamade_fixture" ||
            !System.Text.RegularExpressions.Regex.IsMatch(nameToUse,"^panda_auth_pandamade_test_[a-f0-9]{32}$")) throw new InvalidOperationException();
        await using var context=new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>().UseNpgsql(saved.ConnectionString).UseOpenIddict().Options);
        if (args[0] == "negative-clients")
        {
            var origin=new Uri(Environment.GetEnvironmentVariable("PANDAMADE_FIXTURE_ADMIN_ORIGIN") ?? "",UriKind.Absolute);
            if (origin.Scheme != "https" || !origin.IsLoopback || origin.AbsolutePath != "/" || origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0) throw new InvalidOperationException();
            var services=new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            services.AddLogging(logging=>logging.ClearProviders());
            services.AddDbContext<PandaAuthDbContext>(o=>o.UseNpgsql(saved.ConnectionString).UseOpenIddict());
            services.AddOpenIddict().AddCore(o=>o.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            using var provider=services.BuildServiceProvider(); await using var scope=provider.CreateAsyncScope();
            var applications=scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
            var scopes=scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictScopeManager>();
            var secret=stored.RootElement.GetProperty("adminSecret").GetString()!;
            foreach(var (suffix,resource) in new[]{("aud","other-fixture-api"),("scope","pandamade-api")})
            {
                var scopeName="pandamade.fixture."+suffix;
                await scopes.CreateAsync(new OpenIddict.Abstractions.OpenIddictScopeDescriptor { Name=scopeName,Resources={resource} });
                await applications.CreateAsync(new OpenIddict.Abstractions.OpenIddictApplicationDescriptor {
                    ClientId="pandamade-fixture-"+suffix, ClientType=OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential, ClientSecret=secret,
                    ConsentType=OpenIddict.Abstractions.OpenIddictConstants.ConsentTypes.Implicit,
                    RedirectUris={new Uri(origin,"fixture-callback")},
                    Permissions={ OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Authorization, OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddict.Abstractions.OpenIddictConstants.Permissions.ResponseTypes.Code,
                        OpenIddict.Abstractions.OpenIddictConstants.Permissions.Scopes.Profile,OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope+scopeName },
                    Requirements={ OpenIddict.Abstractions.OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange } });
            }
            Console.WriteLine("pandamade-negative-fixture-clients-created"); return;
        }
        if (args[0] == "cleanup") { await context.Database.EnsureDeletedAsync(); Console.WriteLine("pandamade-identity-fixture-cleaned"); return; }
        var tokens=context.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken>();
        Console.WriteLine(JsonSerializer.Serialize(new { refreshIssued=await tokens.CountAsync(x=>x.Type==OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.RefreshToken),refreshRedeemed=await tokens.CountAsync(x=>x.Type==OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.RefreshToken && x.Status=="redeemed"), types=await tokens.GroupBy(x=>new{x.Type,x.Status}).Select(g=>new{g.Key.Type,g.Key.Status,count=g.Count()}).ToArrayAsync() })); return;
    }
    if (File.Exists(Path.Combine(root,"state.json"))) throw new InvalidOperationException();
    var name="panda_auth_pandamade_test_"+Guid.NewGuid().ToString("N");
    await using (var admin=new NpgsqlConnection(baseConnection.ConnectionString))
    { await admin.OpenAsync(); await using var command=new NpgsqlCommand($"CREATE DATABASE \"{name}\"",admin); await command.ExecuteNonQueryAsync(); }
    baseConnection.Database=name;
    await using var db=new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>().UseNpgsql(baseConnection.ConnectionString).UseOpenIddict().Options);
    await db.Database.MigrateAsync();
    var password="Fixture-aA1!"+Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    var users=new UserService(db,new Argon2idPasswordHasher(),TimeProvider.System);
    var team=new PandaUser { UserName="team@pandamade.test", Email="team@pandamade.test", EmailConfirmed=true, Nickname="Team fixture" };
    var ungranted=new PandaUser { UserName="ungranted@pandamade.test", Email="ungranted@pandamade.test", EmailConfirmed=true, Nickname="Ungrant fixture" };
    foreach (var user in new[]{team,ungranted}) if (!(await users.CreateAsync(user,password)).Succeeded) throw new InvalidOperationException();
    var state=new { identityDatabase=name, identityConnection=baseConnection.ConnectionString, password,
        username=team.UserName,subject=team.Id,ungrantedUsername=ungranted.UserName,ungrantedSubject=ungranted.Id,
        adminSecret=Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),apiSecret=Convert.ToHexString(RandomNumberGenerator.GetBytes(32)) };
    var path=Path.Combine(root,"state.json");
    await using (var file=new FileStream(path,new FileStreamOptions { Mode=FileMode.CreateNew,Access=FileAccess.Write,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite }))
        await JsonSerializer.SerializeAsync(file,state);
    Console.WriteLine("pandamade-protocol-fixture-created");
}
catch { Console.Error.WriteLine("pandamade-protocol-fixture-closed"); Environment.ExitCode=1; }

using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
namespace PandaAuth.ReadinessHarness;

public sealed record ControlledHumanInput(ControlledCryptoInput Crypto,string Case);
internal sealed record ControlledHumanSession(int Schema,string SpecSha256,string DatabaseFingerprint,SessionSnapshot Session,bool Revoked);

public static class ControlledHumanProtocol
{
    private static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    public static int CaseIndex(string value)=>value switch{"valid"=>0,"revoked"=>1,_=>throw new InvalidOperationException("controlled_human_failed")};
    public static async Task<int> Dispatch(string command,string line)
    {
        var stage="admission";
        try
        {
            ControlledProtocolContext.Require(command is "--controlled-human-create-stdin" or "--controlled-human-verify-stdin");
            var input=ControlledTransport.Decode<ControlledHumanInput>(line);var index=CaseIndex(input.Case);
            var context=await ControlledProtocolContext.Open(input.Crypto);var revoked=index==1;
            using var root=context.Certificate();var subject=ControlledActors.Subject(input.Crypto.Spec,index+1);
            var file="human-"+input.Case+".json";
            object? statuses=null;
            context.Write("human-"+input.Case+(command=="--controlled-human-create-stdin"?"-create-started.json":"-verify-started.json"),new{schema=1,specSha256=context.Binding});
            stage="protocol";
            if(command=="--controlled-human-create-stdin")
            {
                var settings=new ProtocolActorSettings(input.Crypto.Spec.Attempt,input.Crypto.Spec.Issuer,context.Actors.Password,
                    context.Actors.Names[3],context.Actors.ClientSecret,new Uri(new Uri(input.Crypto.Spec.Issuer),"/callback").AbsoluteUri,
                    context.Actors.Names[index+1],"cookie");
                using var actor=new ProtocolUser(settings,index,root);await actor.InitializeAsync(CancellationToken.None);
                ControlledProtocolContext.Require(await actor.StepAsync(CancellationToken.None)==HttpStatusCode.OK);
                context.Write(file,new ControlledHumanSession(1,context.Binding,input.Crypto.RestoredDatabaseFingerprint,actor.Snapshot(),revoked));
                if(revoked)
                {
                    stage="revoke";
                    var services=new ServiceCollection().AddLogging(logging=>logging.ClearProviders());
                    services.AddDbContext<PandaAuthDbContext>(options=>options.UseNpgsql(ControlledCryptography.Connection(input.Crypto.ConnectionString).ConnectionString).UseOpenIddict());
                    services.AddUserStore();await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
                    var users=scope.ServiceProvider.GetRequiredService<UserService>();var user=await users.FindByIdAsync(subject);
                    ControlledProtocolContext.Require(user is not null&&user.UserName==context.Actors.Names[index+1]);
                    ControlledProtocolContext.Require((await users.UpdateSecurityStampAsync(user!)).Succeeded);
                }
            }
            else
            {
                var stored=ControlledProtocolContext.Read<ControlledHumanSession>(context.Root,file,131072);var snapshot=stored.Session;
                var now=DateTimeOffset.UtcNow;
                ControlledProtocolContext.Require(stored.Schema==1&&stored.SpecSha256==context.Binding&&stored.DatabaseFingerprint==input.Crypto.RestoredDatabaseFingerprint&&
                    stored.Revoked==revoked&&snapshot.RunId==input.Crypto.Spec.Attempt&&snapshot.BaseUri==input.Crypto.Spec.Issuer&&snapshot.UserIndex==index&&
                    snapshot.CreatedAt<=now&&now-snapshot.CreatedAt<=TimeSpan.FromDays(1)&&!string.IsNullOrEmpty(snapshot.AccessToken)&&!string.IsNullOrEmpty(snapshot.RefreshToken));
                var cookies=context.Cookies(snapshot.Cookies);using var browser=ProtocolUser.CreateBrowser(new Uri(input.Crypto.Spec.Issuer),root,cookies);
                string nextAccess="",nextRefresh="";
                statuses=await ProtocolSnapshot.VerifyCoreAsync(browser,snapshot,context.Actors.Names[3],context.Actors.ClientSecret,revoked,subject,
                    (access,refresh)=>{nextAccess=access;nextRefresh=refresh;});
                if(!revoked)
                    context.Write("human-valid-renewed.json",stored with{Session=snapshot with{AccessToken=nextAccess,RefreshToken=nextRefresh,Cookies=ControlledProtocolContext.Capture(cookies)}});
            }
            Console.WriteLine(JsonSerializer.Serialize(new{schema=1,scope="controlled-human-component",valid=true,specSha256=context.Binding,
                @case=input.Case,operation=command=="--controlled-human-create-stdin"?"create":"verify",revoked,subjectSha256=ControlledProtocolContext.Hash(subject),statuses},Json));return 0;
        }
        catch(Exception error)
        {
            Console.WriteLine(JsonSerializer.Serialize(new{schema=1,valid=false,error="controlled_human_failed",stage,kind=error.GetType().Name,
                cookieStatus=error is SnapshotProtocolException p?p.CookieStatus:0,bearerStatus=error is SnapshotProtocolException b?b.BearerStatus:0,
                refreshStatus=error is SnapshotProtocolException r?r.RefreshStatus:0},Json));return 2;
        }
    }
}

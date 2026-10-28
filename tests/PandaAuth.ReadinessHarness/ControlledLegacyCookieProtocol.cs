using System.Net;
using System.Text.Json;
using Npgsql;
namespace PandaAuth.ReadinessHarness;
internal sealed record ControlledLegacyCookieSnapshot(int Schema,string SpecSha256,string DatabaseFingerprint,SnapshotCookie[] Cookies);
public static class ControlledLegacyCookieProtocol
{
    public static async Task<int> Dispatch(string command,string line)
    {
        try
        {
            ControlledProtocolContext.Require(command is "--controlled-legacy-cookies-create-stdin" or "--controlled-legacy-cookies-verify-stdin");
            var input=ControlledTransport.Decode<ControlledCryptoInput>(line);var context=await ControlledProtocolContext.Open(input);
            var create=command=="--controlled-legacy-cookies-create-stdin";
            context.Write(create?"legacy-cookies-create-started.json":"legacy-cookies-verify-started.json",new{schema=1,specSha256=context.Binding});
            int[] statuses=[];
            if(create)
            {
                ControlledProtocolContext.Require(context.DataFingerprint==input.RestoredDatabaseFingerprint&&string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDA_AUTH_CONTROLLED_PARENT_SHA256")));
                await using var connection=new NpgsqlConnection(ControlledCryptography.Connection(input.ConnectionString).ConnectionString);await connection.OpenAsync();
                await using var transaction=await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead);
                await using(var query=new NpgsqlCommand("SET TRANSACTION READ ONLY",connection,transaction))await query.ExecuteNonQueryAsync();
                await using(var query=new NpgsqlCommand("SELECT count(*) FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\"='20261025074425_OnlineSigningKeyLifecycle'",connection,transaction))
                    ControlledProtocolContext.Require((long)(await query.ExecuteScalarAsync())! ==0);
                await using var user=new NpgsqlCommand("SELECT \"SecurityStamp\" FROM panda_users WHERE \"Id\"=@id AND \"UserName\"=@name",connection,transaction);
                user.Parameters.AddWithValue("id",ControlledActors.Subject(input.Spec,0));user.Parameters.AddWithValue("name",context.Actors.Names[0]);
                var stamp=(string?)await user.ExecuteScalarAsync();ControlledProtocolContext.Require(!string.IsNullOrEmpty(stamp));
                var cookies=ControlledLegacyCookies.Create(Path.Combine(context.Root,"dp"),input.Spec,stamp!);
                context.Write("legacy-cookies.json",new ControlledLegacyCookieSnapshot(1,context.Binding,context.DataFingerprint,cookies));
                await transaction.CommitAsync();
            }
            else
            {
                var snapshot=ControlledProtocolContext.Read<ControlledLegacyCookieSnapshot>(context.Root,"legacy-cookies.json",131072);
                ControlledProtocolContext.Require(snapshot.Schema==1&&snapshot.SpecSha256==context.Binding&&snapshot.DatabaseFingerprint==context.DataFingerprint&&
                    snapshot.Cookies.Select(cookie=>cookie.Name).SequenceEqual(new[]{"PandaAuth.Login","PandaAuth.Login.v2","PandaAuth.Admin"}));
                using var root=context.Certificate();var observed=new List<int>();
                foreach(var cookie in snapshot.Cookies)
                {
                    using var browser=ProtocolUser.CreateBrowser(new Uri(input.Spec.Issuer),root,context.Cookies([cookie]));
                    using var response=await browser.GetAsync(cookie.Name=="PandaAuth.Admin"?"/admin/api/session":"/account/change-password");
                    if(cookie.Name=="PandaAuth.Admin")ControlledProtocolContext.Require(response.StatusCode==HttpStatusCode.Unauthorized);
                    else ControlledProtocolContext.Require(response.StatusCode==HttpStatusCode.Unauthorized||
                        response.StatusCode==HttpStatusCode.Redirect&&response.Headers.Location is { } location&&
                        new Uri(new Uri(input.Spec.Issuer),location).Host==new Uri(input.Spec.Issuer).Host&&
                        new Uri(new Uri(input.Spec.Issuer),location).AbsolutePath=="/account/login");
                    observed.Add((int)response.StatusCode);
                }
                statuses=observed.ToArray();
            }
            Console.WriteLine(JsonSerializer.Serialize(new{schema=1,scope="controlled-legacy-cookie-component",valid=true,operation=create?"create":"verify",statuses}));return 0;
        }
        catch(Exception error)
        {Console.WriteLine(JsonSerializer.Serialize(new{schema=1,valid=false,error="controlled_legacy_cookie_failed",kind=error.GetType().Name}));return 2;}
    }
}
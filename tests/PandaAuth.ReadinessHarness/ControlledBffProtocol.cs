using System.Net;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using PandaAuth.Server.Infrastructure.Security.Mfa;
namespace PandaAuth.ReadinessHarness;

internal sealed record ControlledBffSession(int Schema,string SpecSha256,string DatabaseFingerprint,DateTimeOffset CreatedAt,
    SnapshotCookie[] Cookies,string SubjectSha256);

public static class ControlledBffProtocol
{
    private static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    private static void Require(bool value){if(!value)throw new InvalidOperationException("controlled_bff_failed");}
    public static async Task<int> Dispatch(string line)
    {
        var stage="admission";
        try
        {
            if(!OperatingSystem.IsLinux())throw new InvalidOperationException("controlled_bff_failed");
            var input=ControlledTransport.Decode<ControlledCryptoInput>(line);
            var root=ControlledTransport.Guard(input.Spec);
            Require(Directory.Exists(root) && new DirectoryInfo(root).LinkTarget is null);
            stage="baseline";
            var current=await ControlledCryptoSnapshot.Read(input);var key=Convert.FromBase64String(input.TotpKey);
            try
            {
                ControlledCryptoCommand.VerifyBaseline(root,input,current,new TotpSecretProtector(key,input.TotpKeyVersion));
                var binding=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ControlledTransport.Canonical(input.Spec))));
                stage="actors";
                var path=Path.Combine(root,"actors.json");var file=new FileInfo(path);
                Require(file.Exists && file.LinkTarget is null && file.Length is >0 and <=16384 &&
                    File.GetUnixFileMode(path)==(UnixFileMode.UserRead|UnixFileMode.UserWrite));
                var actors=ControlledTransport.Decode<ControlledActorSecrets>(File.ReadAllText(path));
                Require(actors.Schema==1 && actors.SpecSha256==binding && actors.DatabaseFingerprint==input.RestoredDatabaseFingerprint &&
                    actors.Names.SequenceEqual(ControlledActors.Names(input.Spec)) && actors.Password.Length>=32);
                ControlledActors.Write(Path.Combine(root,"bff-started.json"),JsonSerializer.SerializeToUtf8Bytes(new{schema=1,specSha256=binding},Json));
                stage="tls";
                using var certificate=X509CertificateLoader.LoadCertificateFromFile(Path.Combine(root,"root.pem"));
                Require(certificate.GetNameInfo(X509NameType.SimpleName,false)=="panda-auth-controlled-"+input.Spec.Attempt);
                var cookies=new CookieContainer();using var browser=ProtocolUser.CreateBrowser(new Uri(input.Spec.Issuer),certificate,cookies);
                var secret=Convert.FromBase64String(actors.TotpSecret);
                try
                {
                    Require(secret.Length==20);
                    stage="protocol";
                    var result=await BffLogin.VerifyCoreAsync(browser,actors.Names[0],actors.Password,secret);
                    var expected=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ControlledActors.Subject(input.Spec,0))));
                    Require(result.SubjectSha256==expected);
                    var snapshot=new ControlledBffSession(1,binding,input.RestoredDatabaseFingerprint,DateTimeOffset.UtcNow,
                        cookies.GetAllCookies().Cast<Cookie>().Select(cookie=>new SnapshotCookie(cookie.Name,cookie.Value,cookie.Domain,
                            cookie.Path,cookie.Secure,cookie.HttpOnly,cookie.Expires)).ToArray(),expected);
                    var bytes=JsonSerializer.SerializeToUtf8Bytes(snapshot,Json);Require(bytes.Length<=131072);
                    ControlledActors.Write(Path.Combine(root,"bff-session.json"),bytes);
                    Console.WriteLine(JsonSerializer.Serialize(new{schema=1,scope="controlled-bff-component",valid=true,specSha256=binding,
                        mfa=true,sharedSso=true,subjectSha256=expected},Json));return 0;
                }
                finally{CryptographicOperations.ZeroMemory(secret);}
            }
            finally{CryptographicOperations.ZeroMemory(key);}
        }
        catch(Exception error)
        {
            var frame=new StackTrace(error,true).GetFrames()?.FirstOrDefault(item=>item.GetMethod()?.DeclaringType==typeof(BffLogin));
            Console.WriteLine(JsonSerializer.Serialize(new{schema=1,valid=false,error="controlled_bff_failed",stage,
                kind=error.GetType().Name,line=error.Data["bffLine"] is int operationLine?operationLine:frame?.GetFileLineNumber() ?? 0,
                status=error.Data["bffStatus"] is int status?status:0},Json));return 2;
        }
    }
}

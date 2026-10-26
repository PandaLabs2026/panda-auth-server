using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.ReadinessHarness;

internal sealed record ControlledCryptoBaseline(int Schema, string SpecSha256, string DatabaseFingerprint,
    Dictionary<string,string> Dp, ControlledCryptoState Original, Guid FactorId, ProtectedTotpSecret Totp);

public static class ControlledCryptoCommand
{
    private static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    private static void Require(bool condition)
    { if(!condition) throw new CryptographicException("controlled_crypto_failed"); }
    private static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string Binding(ControlledTransportSpec spec)=>Hash(ControlledTransport.Canonical(spec));
    private static byte[] Canary(ControlledTransportSpec spec)=>SHA256.HashData(Encoding.UTF8.GetBytes("controlled-totp\0"+Binding(spec)))[..20];

    public static async Task<int> Dispatch(string command,string line)
    {
        try
        {
            if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("controlled_crypto_failed");
            Require(command is "--controlled-crypto-baseline-stdin" or "--controlled-crypto-verify-stdin");
            var input=ControlledTransport.Decode<ControlledCryptoInput>(line);
            var root=ControlledTransport.Guard(input.Spec);
            Require(Directory.Exists(root) && new DirectoryInfo(root).LinkTarget is null);
            var path=Path.Combine(root,"crypto-baseline.json");
            var current=await ControlledCryptoSnapshot.Read(input);
            var key=Convert.FromBase64String(input.TotpKey);
            try
            {
                var protector=new TotpSecretProtector(key,input.TotpKeyVersion);
                if(command=="--controlled-crypto-baseline-stdin")
                {
                    Require(!File.Exists(path));
                    var factor=Guid.NewGuid();
                    var totp=protector.Protect("controlled-"+Binding(input.Spec),factor,Canary(input.Spec));
                    ControlledCryptography.InspectTotp(protector,"controlled-"+Binding(input.Spec),factor,totp);
                    var baseline=new ControlledCryptoBaseline(1,Binding(input.Spec),input.RestoredDatabaseFingerprint,
                        ControlledCryptography.CaptureDp(Path.Combine(root,"dp"),input.Spec),current,factor,totp);
                    var bytes=JsonSerializer.SerializeToUtf8Bytes(baseline,Json);
                    Require(bytes.Length<=4*1024*1024);
                    using var output=new FileStream(path,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,
                        Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});
                    output.Write(bytes);output.Flush(true);
                }
                else
                {
                    var file=new FileInfo(path);
                    Require(file.Exists && file.LinkTarget is null && file.Length is >0 and <=4*1024*1024 &&
                        File.GetUnixFileMode(path)==(UnixFileMode.UserRead|UnixFileMode.UserWrite));
                    var baseline=ControlledTransport.DecodeBounded<ControlledCryptoBaseline>(File.ReadAllText(path),4*1024*1024);
                    Require(baseline.Schema==1 && baseline.SpecSha256==Binding(input.Spec) &&
                        baseline.DatabaseFingerprint==input.RestoredDatabaseFingerprint);
                    ControlledCryptography.RequireOriginals(baseline.Original.Keys,current.Keys);
                    ControlledCryptography.RequireOriginals(baseline.Original.Factors,current.Factors);
                    ControlledCryptography.VerifyDp(Path.Combine(root,"dp"),input.Spec,baseline.Dp);
                    Require(ControlledCryptography.InspectTotp(protector,"controlled-"+Binding(input.Spec),baseline.FactorId,baseline.Totp)==
                        Convert.ToHexStringLower(SHA256.HashData(Canary(input.Spec))));
                }
            }
            finally { CryptographicOperations.ZeroMemory(key); }
            Console.WriteLine(JsonSerializer.Serialize(new{schema=1,scope="controlled-crypto-component",valid=true,
                specSha256=Binding(input.Spec),keys=current.Keys.Count,factors=current.Factors.Count},Json));
            return 0;
        }
        catch
        {
            Console.WriteLine("{\"schema\":1,\"valid\":false,\"error\":\"controlled_crypto_failed\"}");
            return 2;
        }
    }
}

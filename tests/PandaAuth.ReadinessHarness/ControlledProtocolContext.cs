using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using PandaAuth.Server.Infrastructure.Security.Mfa;
namespace PandaAuth.ReadinessHarness;

internal sealed class ControlledProtocolContext
{
    internal ControlledCryptoInput Input { get; }
    internal string Root { get; }
    internal string Binding { get; }
    internal ControlledActorSecrets Actors { get; }
    internal string DataFingerprint { get; }
    private static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    internal static void Require(bool condition){if(!condition)throw new InvalidOperationException("controlled_protocol_failed");}
    private ControlledProtocolContext(ControlledCryptoInput input,string root,string binding,ControlledActorSecrets actors,string fingerprint)
    {Input=input;Root=root;Binding=binding;Actors=actors;DataFingerprint=fingerprint;}
    internal static async Task<ControlledProtocolContext> Open(ControlledCryptoInput input)
    {
        if(!OperatingSystem.IsLinux())throw new InvalidOperationException("controlled_protocol_failed");
        var root=ControlledTransport.Guard(input.Spec);Require(Directory.Exists(root)&&new DirectoryInfo(root).LinkTarget is null);
        var current=await ControlledCryptoSnapshot.Read(input);var key=Convert.FromBase64String(input.TotpKey);
        try{ControlledCryptoCommand.VerifyBaseline(root,input,current,new TotpSecretProtector(key,input.TotpKeyVersion),allowParent:true);}
        finally{CryptographicOperations.ZeroMemory(key);}
        var binding=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ControlledTransport.Canonical(input.Spec))));
        var actors=Read<ControlledActorSecrets>(root,"actors.json",16384);
        var fingerprint=ControlledParent.DataFingerprint(root,input);
        Require(actors.Schema==1&&actors.SpecSha256==binding&&actors.DatabaseFingerprint==fingerprint&&
            actors.Names.SequenceEqual(ControlledActors.Names(input.Spec))&&actors.Password.Length>=32);
        return new(input,root,binding,actors,fingerprint);
    }
    internal static T Read<T>(string root,string name,int limit)
    {
        if(!OperatingSystem.IsLinux())throw new InvalidOperationException("controlled_protocol_failed");
        Require(Path.GetFileName(name)==name);var path=Path.Combine(root,name);var file=new FileInfo(path);
        Require(file.Exists&&file.LinkTarget is null&&file.Length>0&&file.Length<=limit&&
            File.GetUnixFileMode(path)==(UnixFileMode.UserRead|UnixFileMode.UserWrite));
        return ControlledTransport.DecodeBounded<T>(File.ReadAllText(path),limit);
    }
    internal void Write(string name,object value)
    {
        Require(Path.GetFileName(name)==name);var bytes=JsonSerializer.SerializeToUtf8Bytes(value,Json);Require(bytes.Length<=131072);
        ControlledActors.Write(Path.Combine(Root,name),bytes);
    }
    internal X509Certificate2 Certificate()
    {
        var certificate=X509CertificateLoader.LoadCertificateFromFile(Path.Combine(Root,"root.pem"));
        if(certificate.GetNameInfo(X509NameType.SimpleName,false)!="panda-auth-controlled-"+Input.Spec.Attempt)
        {certificate.Dispose();throw new InvalidOperationException("controlled_protocol_failed");}
        return certificate;
    }
    internal CookieContainer Cookies(SnapshotCookie[] stored)
    {
        Require(stored is {Length:>=1 and <=64});var owner=new Uri(Input.Spec.Issuer);var cookies=new CookieContainer();
        foreach(var cookie in stored)
        {
            Require(string.Equals(cookie.Domain.TrimStart('.'),owner.Host,StringComparison.OrdinalIgnoreCase)&&cookie.Path.StartsWith('/'));
            cookies.Add(new Cookie(cookie.Name,cookie.Value,cookie.Path,cookie.Domain){Secure=cookie.Secure,HttpOnly=cookie.HttpOnly,Expires=cookie.Expires});
        }
        return cookies;
    }
    internal static SnapshotCookie[] Capture(CookieContainer cookies)=>cookies.GetAllCookies().Cast<Cookie>()
        .Select(cookie=>new SnapshotCookie(cookie.Name,cookie.Value,cookie.Domain,cookie.Path,cookie.Secure,cookie.HttpOnly,cookie.Expires)).ToArray();
    internal static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

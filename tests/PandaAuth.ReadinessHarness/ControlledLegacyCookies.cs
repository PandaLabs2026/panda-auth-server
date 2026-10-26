using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
namespace PandaAuth.ReadinessHarness;

/// <summary>Offline native tickets from existing original stores; no key manager or application startup.</summary>
public static class ControlledLegacyCookies
{
    public static SnapshotCookie[] Create(string dpRoot,ControlledTransportSpec spec,string stamp)
    {
        ControlledTransport.Validate(spec);
        ControlledProtocolContext.Require(!string.IsNullOrEmpty(stamp)&&stamp.Length<=256);
        var now=DateTimeOffset.UtcNow;var subject=ControlledActors.Subject(spec,0);var name=ControlledActors.Names(spec)[0];
        var claims=new[]{new Claim(ClaimTypes.NameIdentifier,subject),new Claim(ClaimTypes.Name,name),
            new Claim("sub",subject),new Claim(ClaimTypes.Role,"admin"),new Claim(LoginSessionService.StampClaim,stamp)};
        var result=new List<SnapshotCookie>();
        foreach(var (component,scheme,cookie,path) in new[]{("server","PandaAuth.Login","PandaAuth.Login","/"),
            ("server",LoginSessionService.Scheme,LoginSessionService.Scheme,"/"),("admin","Cookies","PandaAuth.Admin","/admin")})
        {
            var directory=Path.Combine(dpRoot,component);
            ControlledProtocolContext.Require(Directory.Exists(directory)&&new DirectoryInfo(directory).LinkTarget is null&&
                Directory.GetFiles(directory,"*.xml").Length>0&&Directory.GetFiles(directory).All(file=>!File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint)));
            var provider=DataProtectionProvider.Create(new DirectoryInfo(directory),builder=>
            {builder.SetApplicationName(RecoveryCrypto.Applications[component]);builder.DisableAutomaticKeyGeneration();});
            var format=new TicketDataFormat(provider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",scheme,"v2"));
            var ticket=new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims,scheme)),
                new AuthenticationProperties{IssuedUtc=now,ExpiresUtc=now.AddHours(1),IsPersistent=false},scheme);
            var value=format.Protect(ticket);var decoded=format.Unprotect(value);
            ControlledProtocolContext.Require(decoded is not null&&decoded.AuthenticationScheme==scheme&&
                decoded.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value==subject&&decoded.Principal.FindFirst(LoginSessionService.StampClaim)?.Value==stamp&&
                !decoded.Principal.HasClaim(claim=>claim.Type==PandaAuthClaims.SecurityVersion));
            result.Add(new(cookie,value,new Uri(spec.Issuer).Host,path,true,true,now.AddHours(1).UtcDateTime));
        }
        return result.ToArray();
    }
}
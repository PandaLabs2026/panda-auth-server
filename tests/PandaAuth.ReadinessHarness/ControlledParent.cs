using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
namespace PandaAuth.ReadinessHarness;
internal sealed record ControlledParentBinding(int Schema,string Phase,string SpecSha256,string ParentFingerprint,
    string RestoredFingerprint,string MaterialSha256,string CaptureSha256);
internal static class ControlledParent
{
    internal static string DataFingerprint(string root,ControlledCryptoInput input)
    {
        var expected=Environment.GetEnvironmentVariable("PANDA_AUTH_CONTROLLED_PARENT_SHA256");
        if(string.IsNullOrEmpty(expected))return input.RestoredDatabaseFingerprint;
        ControlledProtocolContext.Require(Regex.IsMatch(expected,"\\A[a-f0-9]{64}\\z"));
        var path=Path.Combine(root,"parent-context.json");
        var parent=ControlledProtocolContext.Read<ControlledParentBinding>(root,"parent-context.json",16384);
        ControlledProtocolContext.Require(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)))==expected&&parent.Schema==1&&parent.Phase=="upgraded"&&
            parent.SpecSha256==Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ControlledTransport.Canonical(input.Spec))))&&
            parent.RestoredFingerprint==input.RestoredDatabaseFingerprint&&parent.ParentFingerprint!=parent.RestoredFingerprint&&
            new[]{parent.ParentFingerprint,parent.MaterialSha256,parent.CaptureSha256}.All(value=>Regex.IsMatch(value,"\\A[a-f0-9]{64}\\z")));
        return parent.ParentFingerprint;
    }
}

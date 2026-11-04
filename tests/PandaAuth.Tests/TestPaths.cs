using System.Diagnostics;
using System.Runtime.CompilerServices;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Tests;

internal static class TestPaths
{
    internal static string Repository([CallerFilePath] string sourceFile = "") =>
        Path.GetFullPath("../..", Path.GetDirectoryName(sourceFile)!);

    internal static ProcessStartInfo ServerCommand(params string[] arguments)
    {
        var start=new ProcessStartInfo("dotnet") { RedirectStandardOutput=true,RedirectStandardError=true };
        foreach(var item in new[]{"exec","--runtimeconfig",Path.Combine(AppContext.BaseDirectory,"PandaAuth.Tests.runtimeconfig.json"),
            "--depsfile",Path.Combine(AppContext.BaseDirectory,"PandaAuth.Tests.deps.json"),typeof(DbSeeder).Assembly.Location}.Concat(arguments))
            start.ArgumentList.Add(item);
        return start;
    }
}

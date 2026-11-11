using PandaAuth.Server.Features.Profile;

if (args is not ["--profile-avatar-decode"]) return 64;
try
{
    return await ProfileAvatarWorker.RunAsync(Console.OpenStandardInput(), Console.OpenStandardOutput(), CancellationToken.None);
}
catch { return 70; } // Preserve the worker protocol without exposing input/native exception details.

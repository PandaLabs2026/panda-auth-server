using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Features.Profile;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ProfileAvatarInputMemoryTests
{
    private const int Maximum = 2097152;

    private static Task<byte[]> Read(byte[] input, long? contentLength)
    {
        var context = new DefaultHttpContext();
        context.Request.ContentType = "image/png";
        context.Request.ContentLength = contentLength;
        context.Request.Body = new MemoryStream(input, writable: false);
        var controller = new SelfProfileController(null!, null!) { ControllerContext = new ControllerContext { HttpContext = context } };
        return (Task<byte[]>)typeof(SelfProfileController).GetMethod("ReadImageAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(controller, [CancellationToken.None])!;
    }

    [Fact]
    public async Task Maximum_known_length_upload_does_not_allocate_multiple_payload_copies()
    {
        var input = new byte[Maximum];
        input[^1] = 123;
        await Read([1], 1);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var read = Read(input, input.Length);
        Assert.True(read.IsCompletedSuccessfully); // MemoryStream keeps this allocation measurement on the same thread.
        var result = await read;
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(result.AsSpan().SequenceEqual(input));
        Assert.InRange(allocated, 0, Maximum + 65536L);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(2L)]
    [InlineData(8192L)]
    public async Task Actual_body_is_preserved_independent_of_declared_length(long? length)
    {
        var input = new byte[4096];
        input[^1] = 123;
        Assert.True((await Read(input, length)).AsSpan().SequenceEqual(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(2L)]
    public async Task Actual_body_limit_is_enforced_even_with_missing_or_small_declared_length(long? length)
    {
        var error = await Assert.ThrowsAsync<ProfileInputException>(() => Read(new byte[Maximum + 1], length));
        Assert.Equal(413, error.StatusCode);
    }
}

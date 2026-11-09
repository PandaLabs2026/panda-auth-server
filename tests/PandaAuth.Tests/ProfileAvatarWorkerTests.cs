using System.Buffers.Binary;
using PandaAuth.Server.Features.Profile;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ProfileAvatarWorkerTests
{
    [Theory]
    [InlineData("png", 64u, 32u)]
    [InlineData("jpg", 64u, 32u)]
    [InlineData("webp", 64u, 32u)]
    [InlineData("oriented.jpg", 32u, 64u)]
    public async Task Supported_input_is_normalized_to_bounded_metadata_free_png(string extension, uint width, uint height)
    {
        var bytes = await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "seed." + extension));
        using var output = new MemoryStream();
        Assert.Equal(0, await ProfileAvatarWorker.RunAsync(new MemoryStream(bytes), output, default));
        var png = output.ToArray();
        Assert.InRange(png.Length, 1, 262144);
        Assert.True(png.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }));
        Assert.Equal(width, BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(16, 4)));
        Assert.Equal(height, BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(20, 4)));
        var offset = 8;
        while (offset < png.Length)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(offset, 4)));
            var kind = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);
            Assert.Contains(kind, new[] { "IHDR", "PLTE", "IDAT", "IEND", "tRNS" });
            offset += checked(12 + length);
        }
        Assert.Equal(png.Length, offset);
    }

    [Theory]
    [InlineData("axis-overflow")]
    [InlineData("pixel-overflow")]
    [InlineData("animated")]
    [InlineData("one-frame-apng.png")]
    [InlineData("one-frame-webp.webp")]
    [InlineData("oversized-compressed-metadata.png")]
    public async Task Unsafe_dimensions_or_frames_are_rejected(string fixture)
    {
        var bytes = await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", fixture));
        using var output = new MemoryStream();
        Assert.Equal(65, await ProfileAvatarWorker.RunAsync(new MemoryStream(bytes), output, default));
        Assert.Equal(0, output.Length);
    }

    [Theory]
    [InlineData("max-Png")]
    [InlineData("max-Jpeg")]
    [InlineData("max-Webp")]
    public async Task Maximum_pixel_count_is_resized_to_512(string fixture)
    {
        var bytes = await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", fixture));
        using var output = new MemoryStream();
        Assert.Equal(0, await ProfileAvatarWorker.RunAsync(new MemoryStream(bytes), output, default));
        var png = output.ToArray();
        Assert.Equal(512u, BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(16, 4)));
        Assert.Equal(512u, BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(20, 4)));
    }

    [Fact]
    public async Task Metadata_is_removed_and_truncated_images_are_rejected()
    {
        var bytes = await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "metadata.png"));
        using var output = new MemoryStream();
        Assert.Equal(0, await ProfileAvatarWorker.RunAsync(new MemoryStream(bytes), output, default));
        Assert.DoesNotContain("SYNTHETIC_PRIVATE_METADATA", System.Text.Encoding.Latin1.GetString(output.ToArray()));
        using var rejected = new MemoryStream();
        Assert.Equal(65, await ProfileAvatarWorker.RunAsync(new MemoryStream(bytes[..(bytes.Length / 2)]), rejected, default));
        Assert.Equal(0, rejected.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2097153)]
    public async Task Invalid_upload_size_never_writes_output(int size)
    {
        using var output = new MemoryStream();
        Assert.Equal(65, await ProfileAvatarWorker.RunAsync(new MemoryStream(new byte[size]), output, default));
        Assert.Equal(0, output.Length);
    }
}

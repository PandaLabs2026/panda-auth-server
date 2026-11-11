using System.Buffers.Binary;
using ImageMagick;
using ImageMagick.Configuration;

namespace PandaAuth.Server.Features.Profile;

/// <summary>Invoked only by the isolated worker entry point. Parent enforces timeout by kill plus wait.</summary>
public static class ProfileAvatarWorker
{
    private static readonly Lazy<bool> Initialized = new(() =>
    {
        var configuration = ConfigurationFiles.Default;
        configuration.Policy.Data = """
            <policymap>
              <policy domain="delegate" rights="none" pattern="*"/>
              <policy domain="filter" rights="none" pattern="*"/>
              <policy domain="path" rights="none" pattern="*"/>
              <policy domain="module" rights="none" pattern="*"/>
              <policy domain="module" rights="read|write" pattern="{PNG,JPEG,WEBP}"/>
              <policy domain="coder" rights="none" pattern="*"/>
              <policy domain="coder" rights="read|write" pattern="{PNG,JPEG,WEBP}"/>
              <policy domain="resource" name="memory" value="64MiB"/>
              <policy domain="resource" name="map" value="0"/>
              <policy domain="resource" name="disk" value="0"/>
              <policy domain="resource" name="width" value="4096"/>
              <policy domain="resource" name="height" value="4096"/>
              <policy domain="resource" name="list-length" value="2"/>
              <policy domain="resource" name="thread" value="1"/>
            </policymap>
            """;
        MagickNET.Initialize(configuration);
        return true;
    });

    public static async Task<int> RunAsync(Stream input, Stream output, CancellationToken ct)
    {
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var count = await input.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, 2097153 - (int)body.Length)), ct);
            if (count == 0) break;
            body.Write(buffer, 0, count);
            if (body.Length > 2097152) return 65;
        }
        var bytes = body.ToArray();
        if (!IsSupported(bytes) || !IsStaticContainer(bytes)) return 65;
        _ = Initialized.Value;
        try
        {
            var settings = new MagickReadSettings();
            settings.SetDefine("png:chunk-cache-max", "16");
            settings.SetDefine("png:chunk-malloc-max", "262144");
            var warning = false;
            using var headers = new MagickImageCollection();
            headers.Warning += (_, _) => warning = true;
            headers.Ping(bytes, settings);
            if (warning || headers.Count != 1) return 65;
            var header = headers[0];
            if (header.Width is < 1 or > 4096 || header.Height is < 1 or > 4096
                || (ulong)header.Width * header.Height > 4194304) return 65;
            using var image = new MagickImage();
            image.Warning += (_, _) => warning = true;
            image.Read(bytes, settings);
            if (warning) return 65;
            image.AutoOrient();
            image.Resize(new MagickGeometry(512, 512) { Greater = true });
            image.Strip();
            image.Settings.SetDefine("png:exclude-chunks", "all");
            var png = WithoutAncillaryMetadata(image.ToByteArray(MagickFormat.Png));
            if (warning || png.Length is < 1 or > 262144 || image.Width > 512 || image.Height > 512) return 65;
            ct.ThrowIfCancellationRequested();
            await output.WriteAsync(png, ct);
            return 0;
        }
        catch (MagickException) { return 65; }
    }

    // The encoder adds its own orientation chunk even with Strip and exclude-chunks=all.
    // Retain only pixel structure/transparency; CRCs remain those of the freshly encoded chunks.
    private static byte[] WithoutAncillaryMetadata(byte[] png)
    {
        using var result = new MemoryStream();
        result.Write(png.AsSpan(0, 8));
        for (var offset = 8; offset < png.Length;)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(offset, 4)) + 12);
            var kind = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);
            if (kind is "IHDR" or "PLTE" or "IDAT" or "IEND" or "tRNS") result.Write(png.AsSpan(offset, length));
            offset = checked(offset + length);
        }
        return result.ToArray();
    }

    // Ping alone treats APNG and single-frame animated WebP as a static first frame.
    private static bool IsStaticContainer(byte[] bytes)
    {
        if (bytes.AsSpan().StartsWith(new byte[] {137,80,78,71,13,10,26,10}))
        {
            for (var offset = 8; offset <= bytes.Length - 12;)
            {
                var count = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4));
                if (count > bytes.Length - offset - 12) return false;
                var kind = bytes.AsSpan(offset + 4, 4);
                if (kind.SequenceEqual("acTL"u8) || kind.SequenceEqual("fcTL"u8) || kind.SequenceEqual("fdAT"u8)) return false;
                if (kind.SequenceEqual("IEND"u8)) return count == 0 && offset + 12 == bytes.Length;
                offset += 12 + (int)count;
            }
            return false;
        }
        if (bytes.AsSpan(0, Math.Min(4, bytes.Length)).SequenceEqual("RIFF"u8))
        {
            if ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4)) + 8 != (ulong)bytes.Length) return false;
            for (var offset = 12; offset < bytes.Length;)
            {
                if (offset > bytes.Length - 8) return false;
                var count = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4, 4));
                var padded = (ulong)count + (count & 1);
                if (padded > (ulong)(bytes.Length - offset - 8)) return false;
                var kind = bytes.AsSpan(offset, 4);
                if (kind.SequenceEqual("ANIM"u8) || kind.SequenceEqual("ANMF"u8)
                    || kind.SequenceEqual("VP8X"u8) && count > 0 && (bytes[offset + 8] & 2) != 0) return false;
                offset += 8 + (int)padded;
            }
        }
        return true;
    }

    private static bool IsSupported(byte[] bytes) =>
        bytes.AsSpan().StartsWith(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })
        || bytes.AsSpan().StartsWith(new byte[] { 255, 216, 255 })
        || bytes.Length >= 12 && bytes.AsSpan(0, 4).SequenceEqual("RIFF"u8) && bytes.AsSpan(8, 4).SequenceEqual("WEBP"u8);
}

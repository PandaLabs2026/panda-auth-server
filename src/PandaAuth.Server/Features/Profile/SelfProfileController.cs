using System.Buffers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Route("~" + PandaAuthProfileApi.Self)]
public sealed class SelfProfileController(SelfProfileService profiles, SecurityEventWriter audit) : ControllerBase
{
    [HttpGet, Authorize(Policy = ProfileAccess.ReadPolicy)]
    public async Task<IActionResult> Read(CancellationToken ct)
    {
        try { return Profile(await profiles.ReadAsync(ProfileAccess.ActorId(User)!, ct)); }
        catch (ProfileOperationException e) { return Error(e.Code, e.StatusCode); }
    }

    [HttpPatch, Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> Patch(CancellationToken ct)
    {
        try
        {
            var revision = RequiredRevision();
            var patch = SelfProfileInput.ParsePatch(await ReadJsonAsync(ct));
            return Profile(await profiles.PatchAsync(ProfileAccess.ActorId(User)!, revision, patch, HttpContext.TraceIdentifier, ct));
        }
        catch (ProfileInputException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
        catch (ProfileOperationException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
    }

    [HttpPost("~" + PandaAuthProfileApi.ContactEmailChallenges), Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> CreateContact([FromServices] ProfileContactService contacts, CancellationToken ct)
    {
        try
        {
            var revision = RequiredRevision();
            var values = await ContactFieldsAsync(["address"], ct);
            var result = await contacts.CreateAsync(ProfileAccess.ActorId(User)!, revision, values["address"], HttpContext.TraceIdentifier, ct);
            Response.Headers.ETag = result.Profile.Revision;
            return StatusCode(202, result);
        }
        catch (ProfileInputException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
        catch (ProfileOperationException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
    }

    [HttpPost("~" + PandaAuthProfileApi.ContactEmailConfirmation), Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> ConfirmContact([FromServices] ProfileContactService contacts, CancellationToken ct)
    {
        try
        {
            var values = await ContactFieldsAsync(["challengeId", "token"], ct);
            return Profile(await contacts.ConfirmAsync(ProfileAccess.ActorId(User)!, values["challengeId"], values["token"], HttpContext.TraceIdentifier, ct));
        }
        catch (ProfileInputException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
        catch (ProfileOperationException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
    }

    [HttpDelete("~" + PandaAuthProfileApi.ContactEmail), Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> DeleteContact([FromServices] ProfileContactService contacts, CancellationToken ct)
    {
        try { return Profile(await contacts.DeleteAsync(ProfileAccess.ActorId(User)!, RequiredRevision(), HttpContext.TraceIdentifier, ct)); }
        catch (ProfileInputException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
        catch (ProfileOperationException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
    }

    [HttpGet("~" + PandaAuthProfileApi.Avatar), Authorize(Policy = ProfileAccess.ReadPolicy)]
    public async Task<IActionResult> ReadAvatar([FromServices] ProfileAvatarService avatars, CancellationToken ct)
    {
        try
        {
            var result = await avatars.ReadAsync(ProfileAccess.ActorId(User)!, ct);
            Response.Headers.ETag = result.Revision;
            Response.Headers["X-Content-Type-Options"] = "nosniff";
            return File(result.Avatar.Bytes, PandaAuth.Server.Domain.ProfileAvatar.MediaType);
        }
        catch (ProfileOperationException e) { return Error(e.Code, e.StatusCode); }
    }

    [HttpPut("~" + PandaAuthProfileApi.Avatar), Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> PutAvatar([FromServices] ProfileAvatarService avatars, CancellationToken ct)
    {
        try { return Profile(await avatars.PutAsync(ProfileAccess.ActorId(User)!, RequiredRevision(), ReadImageAsync, HttpContext.TraceIdentifier, ct)); }
        catch (ProfileInputException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
        catch (ProfileOperationException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
    }

    [HttpDelete("~" + PandaAuthProfileApi.Avatar), Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> DeleteAvatar([FromServices] ProfileAvatarService avatars, CancellationToken ct)
    {
        try { return Profile(await avatars.DeleteAsync(ProfileAccess.ActorId(User)!, RequiredRevision(), HttpContext.TraceIdentifier, ct)); }
        catch (ProfileInputException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
        catch (ProfileOperationException e) { return await RejectedAsync(e.Code, e.StatusCode, ct); }
    }

    private async Task<byte[]> ReadImageAsync(CancellationToken ct)
    {
        const int maximum = 2097152;
        if (!Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(Request.ContentType, out var media)
            || media.MediaType.Value?.ToLowerInvariant() is not ("image/png" or "image/jpeg" or "image/webp")
            || Request.Headers.ContentEncoding.Any(value => !string.Equals(value, "identity", StringComparison.OrdinalIgnoreCase)))
            throw new ProfileInputException("profile_request_invalid", 415);
        if (Request.ContentLength > maximum) throw new ProfileInputException("profile_request_too_large", 413);
        using var body = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            while (true)
            {
                var count = await Request.Body.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, maximum - (int)body.Length + 1)), ct);
                if (count == 0) return body.ToArray();
                if (body.Length + count > maximum) throw new ProfileInputException("profile_request_too_large", 413);
                body.Write(buffer, 0, count);
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    private string RequiredRevision()
    {
        var etags = Request.Headers.IfMatch;
        if (etags.Count == 0) throw new ProfileOperationException("profile_revision_required", 428);
        if (etags.Count != 1 || !SelfProfileInput.IsRevision(etags[0]!))
            throw new ProfileInputException("profile_request_invalid", 400);
        return etags[0]!;
    }

    private async Task<Dictionary<string, string>> ContactFieldsAsync(string[] fields, CancellationToken ct)
    {
        var json = await ReadJsonAsync(ct);
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException();
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
                if (!fields.Contains(property.Name, StringComparer.Ordinal) || property.Value.ValueKind != JsonValueKind.String
                    || !result.TryAdd(property.Name, property.Value.GetString()!)) throw new JsonException();
            if (result.Count != fields.Length) throw new JsonException();
            return result;
        }
        catch (JsonException) { throw new ProfileInputException("profile_request_invalid", 400); }
        catch (InvalidOperationException) { throw new ProfileInputException("profile_request_invalid", 400); }
    }

    private async Task<string> ReadJsonAsync(CancellationToken ct)
    {
        if (!Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(Request.ContentType, out var media)
            || !string.Equals(media.MediaType.Value, "application/json", StringComparison.OrdinalIgnoreCase)
            || (media.Charset.HasValue && !string.Equals(media.Charset.Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase))
            || Request.Headers.ContentEncoding.Any(value => !string.Equals(value, "identity", StringComparison.OrdinalIgnoreCase)))
            throw new ProfileInputException("profile_request_invalid", 415);
        if (Request.ContentLength > SelfProfileInput.MaxJsonBytes)
            throw new ProfileInputException("profile_request_too_large", 413);
        using var body = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while (true)
            {
                var count = await Request.Body.ReadAsync(buffer.AsMemory(0,
                    Math.Min(buffer.Length, SelfProfileInput.MaxJsonBytes - (int)body.Length + 1)), ct);
                if (count == 0) break;
                if (body.Length + count > SelfProfileInput.MaxJsonBytes)
                    throw new ProfileInputException("profile_request_too_large", 413);
                body.Write(buffer, 0, count);
            }
            try { return new UTF8Encoding(false, true).GetString(body.GetBuffer(), 0, (int)body.Length); }
            catch (DecoderFallbackException) { throw new ProfileInputException("profile_request_invalid", 400); }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    private OkObjectResult Profile(SelfProfileDto profile)
    {
        Response.Headers.ETag = profile.Revision;
        return Ok(profile);
    }
    private ObjectResult Error(string code, int status) => StatusCode(status, new ProfileErrorDto(code, HttpContext.TraceIdentifier));
    private async Task<IActionResult> RejectedAsync(string code, int status, CancellationToken ct)
    {
        var actor = ProfileAccess.ActorId(User);
        await audit.RecordAsync(new SecurityEventEntry("profile.mutation.rejected", actor, actor, "profile", null, null,
            new { outcome = code }, null, null, HttpContext.TraceIdentifier), ct);
        return Error(code, status);
    }
}

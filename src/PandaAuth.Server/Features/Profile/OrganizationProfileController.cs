using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Data.Common;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Route("~" + PandaAuthProfileApi.SelfOrganization)]
public sealed class OrganizationProfileController(OrganizationProfileService profiles) : ControllerBase
{
    [HttpGet, Authorize(Policy = ProfileAccess.ReadPolicy)]
    public async Task<IActionResult> Selection(Guid organizationKey, CancellationToken ct)
    {
        try { return Selected(await profiles.ReadSelectionAsync(ProfileAccess.ActorId(User)!, organizationKey, ct)); }
        catch (ProfileOperationException e) { return Error(e.Code, e.StatusCode); }
        catch (Exception e) when (e is DbException or DbUpdateException) { return Error("profile_unavailable", 503); }
    }

    [HttpPut, Authorize(Policy = ProfileAccess.WritePolicy)]
    public async Task<IActionResult> Select(Guid organizationKey, CancellationToken ct)
    {
        try
        {
            var etags = Request.Headers.IfMatch;
            if (etags.Count == 0) throw new ProfileOperationException("profile_revision_required", 428);
            if (etags.Count != 1 || !SelfProfileInput.IsRevision(etags[0]!)) throw new ProfileInputException("profile_request_invalid", 400);
            var fields = OrganizationProfileInput.ParseSelection(await SelfProfileInput.ReadJsonAsync(Request, ct));
            return Selected(await profiles.WriteSelectionAsync(ProfileAccess.ActorId(User)!, organizationKey,
                etags[0]!, fields, HttpContext.TraceIdentifier, ct));
        }
        catch (ProfileInputException e) { return Error(e.Code, e.StatusCode); }
        catch (ProfileOperationException e) { return Error(e.Code, e.StatusCode); }
        catch (Exception e) when (e is DbException or DbUpdateException) { return Error("profile_unavailable", 503); }
    }

    [HttpGet("~" + PandaAuthProfileApi.OrganizationMember), Authorize(Policy = ProfileAccess.ReadPolicy)]
    public async Task<IActionResult> Member(Guid organizationKey, Guid memberKey, [FromQuery] string? fields, CancellationToken ct)
    {
        try
        {
            if (Request.Query.Count != 1 || Request.Query["fields"].Count != 1)
                throw new ProfileInputException("profile_request_invalid", 400);
            return Ok(await profiles.ReadMemberAsync(HttpContext, organizationKey, memberKey,
                OrganizationProfileInput.ParseRequestedFields(fields), ct));
        }
        catch (ProfileInputException e) { return Error(e.Code, e.StatusCode); }
        catch (ProfileOperationException e) { return Error(e.Code, e.StatusCode); }
        catch (Exception e) when (e is DbException or DbUpdateException) { return Error("profile_unavailable", 404); }
    }

    [HttpGet("~" + PandaAuthProfileApi.OrganizationAvatar), Authorize(Policy = ProfileAccess.ReadPolicy)]
    public async Task<IActionResult> MemberAvatar(Guid organizationKey, Guid memberKey, CancellationToken ct)
    {
        try
        {
            if (Request.Query.Count != 0) throw new ProfileInputException("profile_request_invalid", 400);
            var bytes = await profiles.ReadMemberAvatarAsync(HttpContext, organizationKey, memberKey, ct);
            Response.Headers["X-Content-Type-Options"] = "nosniff";
            return File(bytes, PandaAuth.Server.Domain.ProfileAvatar.MediaType);
        }
        catch (ProfileInputException e) { return Error(e.Code, e.StatusCode); }
        catch (ProfileOperationException e) { return Error(e.Code, e.StatusCode); }
        catch (Exception e) when (e is DbException or DbUpdateException) { return Error("profile_unavailable", 404); }
    }

    private OkObjectResult Selected(ProfileOrganizationSelectionDto result)
    {
        Response.Headers.ETag = result.Revision;
        return Ok(result);
    }
    private ObjectResult Error(string code, int status) => StatusCode(status, new ProfileErrorDto(code, HttpContext.TraceIdentifier));
}

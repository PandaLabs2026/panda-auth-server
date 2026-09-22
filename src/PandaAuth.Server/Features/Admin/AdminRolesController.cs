using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Admin;

[Route("~/admin-api/roles")]
[RequireConfirmedEmail]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
    Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminRolesController(PandaAuthDbContext db) : Controller
{
    internal const int DefaultPageSize = 20;
    internal const int MaxPageSize = 50;

    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] string? query,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var pageNumber = Math.Max(page ?? 1, 1);
        var size = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);
        var roles = db.Roles.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query))
        {
            var normalized = query.Trim().ToUpperInvariant();
            roles = roles.Where(role => role.NormalizedName!.Contains(normalized));
        }

        var total = await roles.CountAsync(cancellationToken);
        var items = await roles
            .OrderBy(role => role.NormalizedName)
            .ThenBy(role => role.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(role => new AdminRoleSummary(role.Id, role.Name!))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminRoleSummary>(items, total, pageNumber, size));
    }
}

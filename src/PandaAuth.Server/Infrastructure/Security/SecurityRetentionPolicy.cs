using System.Linq.Expressions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Domain;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Security;

internal static class SecurityRetentionPolicy
{
    internal static Expression<Func<SecurityEvent, bool>> EventsBefore(DateTimeOffset cutoff) => row => row.CreatedAt < cutoff;
    internal static Expression<Func<OpenIddictEntityFrameworkCoreToken, bool>> TokensBefore(DateTime cutoff) => token =>
        token.ExpirationDate != null && token.ExpirationDate < cutoff &&
        token.CreationDate != null && token.CreationDate < cutoff &&
        (token.RedemptionDate == null || token.RedemptionDate < cutoff) &&
        (token.Status != Statuses.Redeemed || token.RedemptionDate != null);
}

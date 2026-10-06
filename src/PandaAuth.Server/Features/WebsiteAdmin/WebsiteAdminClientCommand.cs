using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.PortalClients;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.WebsiteAdmin;

internal static class WebsiteAdminClientCommand
{
    private const string ClientId = FirstPartyClients.WebsiteAdmin;
    private const string Issuer = "https://auth.appliket.com/";
    private const string Root = "/etc/panda-auth/website-admin";
    [DllImport("libc")] private static extern uint geteuid();

    internal static async Task<int> RunAsync(IConfiguration configuration)
    {
        // 目标管理员邮箱与操作者标识由配置注入（Auth:WebsiteAdmin:AdministratorEmail / ActorUserName）：
        // 个人邮箱/个人账号名硬编码在代码里既不可审计也不可换人。一次性 CLI，缺失即拒绝执行——
        // 该命令本就只在特定宿主机上手工运行，明示缺失比默认值更安全。
        var administratorEmail = configuration["Auth:WebsiteAdmin:AdministratorEmail"];
        var actorUserName = configuration["Auth:WebsiteAdmin:ActorUserName"];
        if (string.IsNullOrWhiteSpace(administratorEmail) || string.IsNullOrWhiteSpace(actorUserName))
        {
            Console.Error.WriteLine(
                "website-admin-client-registration-closed: 缺少 Auth:WebsiteAdmin:AdministratorEmail / Auth:WebsiteAdmin:ActorUserName 配置（拒绝执行）。");
            return 1;
        }

        try
        {
            var uid = geteuid();
            if (uid < 1000) throw new InvalidOperationException();
            var marker = JsonDocument.Parse(PortalClientCommand.ReadProtectedFile(Root + "/machine.json", uid, false));
            if (marker.RootElement.GetProperty("machine_id").GetString() != "aliyun-sh-01" ||
                configuration["Auth:Issuer"]?.TrimEnd('/') + "/" != Issuer) throw new InvalidOperationException();
            using var input = JsonDocument.Parse(PortalClientCommand.ReadProtectedFile(Root + "/request.json", uid, true));
            var root = input.RootElement;
            var allowed = new HashSet<string> { "clientSecret", "administratorEmail", "validUntilUtc", "operationId", "expectedRedirectUris", "expectedPostLogoutRedirectUris", "expectedAdditionalPermissions" };
            if (root.EnumerateObject().Any(p => !allowed.Remove(p.Name)) || allowed.Count != 0) throw new InvalidOperationException();
            using var endpoints = JsonDocument.Parse(PortalClientCommand.ReadProtectedFile(Root + "/endpoints.json", uid, false));
            var baseUrl = endpoints.RootElement.GetProperty("adminPublicUrl").GetString()!;
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var adminUri) || adminUri.Scheme != "https" ||
                !string.IsNullOrEmpty(adminUri.UserInfo) || !string.IsNullOrEmpty(adminUri.Query) ||
                !string.IsNullOrEmpty(adminUri.Fragment) || adminUri.AbsolutePath == "/" || !baseUrl.EndsWith('/')) throw new InvalidOperationException();
            var callback = new Uri(adminUri, "signin-oidc"); var logout = new Uri(adminUri, "signout-callback-oidc");
            var expectedRedirect = root.GetProperty("expectedRedirectUris").EnumerateArray().Select(x => new Uri(x.GetString()!, UriKind.Absolute)).ToHashSet();
            var expectedLogout = root.GetProperty("expectedPostLogoutRedirectUris").EnumerateArray().Select(x => new Uri(x.GetString()!, UriKind.Absolute)).ToHashSet();
            var secret = root.GetProperty("clientSecret").GetString()!;
            var until = root.GetProperty("validUntilUtc").GetDateTimeOffset();
            var operation = root.GetProperty("operationId").GetGuid().ToString();
            if (secret.Length < 32 || until <= DateTimeOffset.UtcNow || until > DateTimeOffset.UtcNow.AddHours(1) ||
                root.GetProperty("administratorEmail").GetString() != administratorEmail) throw new InvalidOperationException();
            var connection = configuration.GetConnectionString("Default")!;
            var options = new NpgsqlConnectionStringBuilder(connection);
            if (options.Host != "127.0.0.1" || options.Port != 5432 || options.Database != "panda_auth_fleet" ||
                options.Username != "panda_auth_fleet_runtime") throw new InvalidOperationException();
            options.MaxPoolSize = 1; options.CommandTimeout = 10;
            using var services = PortalClientCommand.Services(options.ConnectionString);
            await using var scope = services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
            var normalizedAdminEmail = administratorEmail.Trim().ToUpperInvariant();
            var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedAdminEmail);
            if (user is null || !user.EmailConfirmed || user.Status != UserStatus.Active) throw new InvalidOperationException();
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId, ClientType = ClientTypes.Confidential, ClientSecret = secret,
                ConsentType = ConsentTypes.Implicit, DisplayName = "PandaLabs 官网运营后台",
                RedirectUris = { callback }, PostLogoutRedirectUris = { logout },
                Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession, Permissions.Endpoints.Introspection, Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code, Permissions.Scopes.Profile,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            };
            var existing = await manager.FindByClientIdAsync(ClientId);
            if (existing is null)
            {
                await manager.CreateAsync(descriptor);
                db.AdminAuditLogs.Add(new PandaAuth.Server.Domain.AdminAuditLog
                {
                    Action = "website-admin-client-register", TargetType = "client",
                    TargetId = ClientId, ActorUserId = "host-operator", ActorUserName = actorUserName,
                    Detail = JsonSerializer.Serialize(new { operationId = operation, issuer = Issuer }),
                    CreatedAt = DateTimeOffset.UtcNow,
                });
                await db.SaveChangesAsync();
            }
            else
            {
                var current = new OpenIddictApplicationDescriptor(); await manager.PopulateAsync(current, existing);
                if (current.ClientType != descriptor.ClientType || current.ConsentType != descriptor.ConsentType ||
                    !current.Requirements.SetEquals(descriptor.Requirements) ||
                    !await manager.ValidateClientSecretAsync(existing, secret)) throw new InvalidOperationException();
                var permissionsChanged = !current.Permissions.SetEquals(descriptor.Permissions);
                var redirectsChanged = !current.RedirectUris.SetEquals(descriptor.RedirectUris) || !current.PostLogoutRedirectUris.SetEquals(descriptor.PostLogoutRedirectUris);
                List<string> addedPermissions = [];
                if (permissionsChanged)
                {
                    // 受控权限升级:只允许追加——现有多出的权限(裁剪)与缺口之外的变化一律失败关闭;
                    // 缺口集合必须与 request.json 的 expectedAdditionalPermissions 逐项精确相等,
                    // 防止描述符漂移被顺带放行。升级路径与回调迁移同源:Populate+Update+再验 secret+审计。
                    var extra = current.Permissions.Except(descriptor.Permissions).ToHashSet(StringComparer.Ordinal);
                    var missing = descriptor.Permissions.Except(current.Permissions).ToHashSet(StringComparer.Ordinal);
                    var expectedAdditional = root.GetProperty("expectedAdditionalPermissions").EnumerateArray().Select(x => x.GetString()!).ToHashSet(StringComparer.Ordinal);
                    if (extra.Count != 0 || missing.Count == 0 || !missing.SetEquals(expectedAdditional)) throw new InvalidOperationException();
                    current.Permissions.Clear(); current.Permissions.UnionWith(descriptor.Permissions);
                    addedPermissions = [.. missing.OrderBy(x => x, StringComparer.Ordinal)];
                }
                if (redirectsChanged)
                {
                    if (expectedRedirect.Count != 1 || expectedLogout.Count != 1 ||
                        !current.RedirectUris.SetEquals(expectedRedirect) || !current.PostLogoutRedirectUris.SetEquals(expectedLogout)) throw new InvalidOperationException();
                    current.RedirectUris.Clear(); current.RedirectUris.UnionWith(descriptor.RedirectUris);
                    current.PostLogoutRedirectUris.Clear(); current.PostLogoutRedirectUris.UnionWith(descriptor.PostLogoutRedirectUris);
                }
                if (permissionsChanged || redirectsChanged)
                {
                    await manager.PopulateAsync(existing, current); await manager.UpdateAsync(existing);
                    if (!await manager.ValidateClientSecretAsync(existing, secret)) throw new InvalidOperationException();
                    if (permissionsChanged) db.AdminAuditLogs.Add(new PandaAuth.Server.Domain.AdminAuditLog {
                        Action = "website-admin-permission-migrate", TargetType = "client", TargetId = ClientId,
                        ActorUserId = "host-operator", ActorUserName = actorUserName,
                        Detail = JsonSerializer.Serialize(new { operationId = operation, addedPermissions }), CreatedAt = DateTimeOffset.UtcNow });
                    if (redirectsChanged) db.AdminAuditLogs.Add(new PandaAuth.Server.Domain.AdminAuditLog {
                        Action = "website-admin-callback-migrate", TargetType = "client", TargetId = ClientId,
                        ActorUserId = "host-operator", ActorUserName = actorUserName,
                        Detail = JsonSerializer.Serialize(new { operationId = operation, redirectUri = callback.AbsoluteUri, logoutUri = logout.AbsoluteUri }), CreatedAt = DateTimeOffset.UtcNow });
                    await db.SaveChangesAsync();
                }
            }
            await transaction.CommitAsync();
            Console.WriteLine(JsonSerializer.Serialize(new { clientId = ClientId, issuer = Issuer, subject = user.Id, operationId = operation }));
            return 0;
        }
        catch (Exception exception)
        {
            // 失败必须留下完整现场：该命令在宿主机上手工运行，吞异常会让一次性操作
            // 的排错只能靠猜（closed 只是对外统一口径，细节进 stderr）。
            Console.Error.WriteLine("website-admin-client-registration-closed");
            Console.Error.WriteLine(exception.ToString());
            return 1;
        }
    }
}

using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Management;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

internal static class BusinessInputLimits
{
    internal const int Name = 256, Identifier = 450, ClientId = 100, Nickname = 128,
        Region = 64, DisplayName = 256, ClaimType = 128, ClaimValue = 2048,
        Scope = 128, Url = 2048, RedirectCount = 32, PermissionCount = 128, NewPassword = 1024;

    public static IReadOnlyList<string> Validate(string name, object? value)
    {
        var errors = new List<string>();
        void Text(string field, string? text, int maximum, bool normalized = false)
        {
            if (text is null) return;
            if (text.Length > maximum) { errors.Add(field); return; }
            if (!normalized) return;
            try
            {
                if (UserService.Normalize(text)?.Length > maximum) errors.Add(field);
            }
            catch (ArgumentException) { errors.Add(field); }
        }
        void Uris(string field, IReadOnlyList<string>? items)
        {
            if (items is null) return;
            if (items.Count > RedirectCount) { errors.Add(field); return; }
            foreach (var item in items) Text(field, item, Url);
        }
        void Profile(string? email, string? nickname, string? region)
        {
            Text("Email", email, Name, true);
            Text("Nickname", nickname, Nickname);
            Text("Region", region, Region);
        }
        switch (value)
        {
            case string text:
                switch (name.ToLowerInvariant())
                {
                    case "id": case "userid": case "roleid": Text(name, text, Identifier); break;
                    case "clientid": Text(name, text, ClientId); break;
                    case "query": case "username": case "actor": case "action":
                        Text(name, text, Name, true); break;
                    case "returnurl": Text(name, text, Url); break;
                }
                break;
            case AdminCreateUserRequest request:
                Text("UserName", request.UserName, Name, true);
                Profile(request.Email, request.Nickname, request.Region);
                Text("Password", request.Password, NewPassword);
                break;
            case AdminUserProfileRequest request: Profile(request.Email, request.Nickname, request.Region); break;
            case AdminResetPasswordRequest request: Text("NewPassword", request.NewPassword, NewPassword); break;
            case AdminDeactivateRequest request: Text("ConfirmUserName", request.ConfirmUserName, Name, true); break;
            case AdminUserRolesRequest request:
                if (request.Roles is not null)
                    foreach (var role in request.Roles) Text("Roles", role, Name, true);
                break;
            case AdminClaimRequest request:
                Text("ClaimType", request.ClaimType, ClaimType);
                Text("ClaimValue", request.ClaimValue, ClaimValue);
                Text("Scope", request.Scope, Scope);
                break;
            case AdminRedirectUrisRequest request:
                Uris("RedirectUris", request.RedirectUris);
                Uris("PostLogoutRedirectUris", request.PostLogoutRedirectUris);
                break;
            case AdminPermissionsRequest request:
                if (request.Permissions?.Count > PermissionCount) errors.Add("Permissions");
                else if (request.Permissions is not null)
                    foreach (var permission in request.Permissions) Text("Permissions", permission, Name);
                break;
            case ManagementCreateClientRequest request:
                Text("ClientId", request.ClientId, ClientId);
                Text("DisplayName", request.DisplayName, DisplayName);
                Uris("RedirectUris", request.RedirectUris);
                Uris("PostLogoutRedirectUris", request.PostLogoutRedirectUris);
                break;
            case ManagementUpdateClientRequest request:
                Text("DisplayName", request.DisplayName, DisplayName);
                Uris("RedirectUris", request.RedirectUris);
                Uris("PostLogoutRedirectUris", request.PostLogoutRedirectUris);
                break;
            case LoginViewModel model:
                Text("UserName", model.UserName, Name, true);
                Text("ReturnUrl", model.ReturnUrl, Url);
                break;
            case ForgotPasswordViewModel model:
                Text("Email", model.Email, Name, true);
                Text("ReturnUrl", model.ReturnUrl, Url);
                break;
            case ResetPasswordViewModel model:
                Text("Email", model.Email, Name, true);
                Text("NewPassword", model.NewPassword, NewPassword);
                Text("ReturnUrl", model.ReturnUrl, Url);
                break;
            case ChangePasswordViewModel model:
                Text("NewPassword", model.NewPassword, NewPassword);
                Text("ReturnUrl", model.ReturnUrl, Url);
                break;
            case ChangeEmailViewModel model:
                Text("NewEmail", model.NewEmail, Name, true);
                Text("ReturnUrl", model.ReturnUrl, Url);
                break;
            case ConfirmEmailChangeViewModel model:
                Text("NewEmail", model.NewEmail, Name, true);
                Text("ReturnUrl", model.ReturnUrl, Url);
                break;
        }
        return errors.Distinct(StringComparer.Ordinal).ToArray();
    }
}

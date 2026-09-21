using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace PandaAuth.Server.Features.Account;

public sealed class LoginViewModel
{
    [Required(ErrorMessage = "请输入用户名。")]
    public string UserName { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入密码。")]
    [DataType(DataType.Password)]
    public string Password { get; init; } = string.Empty;

    [HiddenInput]
    public string? ReturnUrl { get; init; }
}

public sealed class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "请输入邮箱。")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确。")]
    public string Email { get; init; } = string.Empty;

    /// <summary>发起方上下文（如 /connect/authorize?...）：贯穿忘记→重置→登录，完成后回到原发起方。</summary>
    [HiddenInput]
    public string? ReturnUrl { get; init; }
}

public sealed class ResetPasswordViewModel
{
    [Required(ErrorMessage = "请输入邮箱。")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确。")]
    public string Email { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入邮件中的一次性令牌。")]
    public string Token { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入新密码。")]
    [DataType(DataType.Password)]
    public string NewPassword { get; init; } = string.Empty;

    [HiddenInput]
    public string? ReturnUrl { get; init; }
}

public sealed class ChangePasswordViewModel
{
    [Required(ErrorMessage = "请输入当前密码。")]
    [DataType(DataType.Password)]
    public string CurrentPassword { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入新密码。")]
    [DataType(DataType.Password)]
    public string NewPassword { get; init; } = string.Empty;

    [HiddenInput]
    public string ReturnUrl { get; init; } = "/";
}

public sealed class ConfirmEmailViewModel
{
    [Required]
    public string Token { get; init; } = string.Empty;
}

public sealed class ChangeEmailViewModel
{
    [Required]
    [EmailAddress]
    public string NewEmail { get; init; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string CurrentPassword { get; init; } = string.Empty;

    [HiddenInput]
    public string? ReturnUrl { get; init; }
}

public sealed class ConfirmEmailChangeViewModel
{
    [Required]
    [EmailAddress]
    public string NewEmail { get; init; } = string.Empty;

    [Required]
    public string Token { get; init; } = string.Empty;

    [HiddenInput]
    public string? ReturnUrl { get; init; }
}

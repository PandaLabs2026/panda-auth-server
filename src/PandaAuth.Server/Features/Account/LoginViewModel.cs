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
}

public sealed class ResetPasswordViewModel
{
    [Required(ErrorMessage = "请输入邮箱。")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确。")]
    public string Email { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入验证码。")]
    public string Code { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入新密码。")]
    [DataType(DataType.Password)]
    public string NewPassword { get; init; } = string.Empty;
}

public sealed class ChangePasswordViewModel
{
    [Required(ErrorMessage = "请输入当前密码。")]
    [DataType(DataType.Password)]
    public string CurrentPassword { get; init; } = string.Empty;

    [Required(ErrorMessage = "请输入新密码。")]
    [DataType(DataType.Password)]
    public string NewPassword { get; init; } = string.Empty;
}

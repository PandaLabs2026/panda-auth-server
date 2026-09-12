using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

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

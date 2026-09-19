namespace PandaAuth.Server.Infrastructure.Messaging;

public sealed class EmailOptions
{
    public const string SectionName = "Email";

    public string ApiKey { get; set; } = "";

    /// <summary>RFC 5322 发件人（如 "PandaAuth &lt;noreply@pandalabs.cc&gt;"）。生产由 compose 注入。</summary>
    public string FromAddress { get; set; } = "";
}

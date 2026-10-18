namespace PandaAuth.Server.Infrastructure.Messaging;

public sealed class EmailOptions
{
    public const string SectionName = "Email";

    /// <summary>Resend (default) or Notify. Notify is the P1 transport-first migration path.</summary>
    public string Transport { get; set; } = "Resend";

    public string ApiKey { get; set; } = "";

    /// <summary>RFC 5322 发件人（如 "PandaAuth &lt;noreply@example.com&gt;"）。生产由 compose 注入。</summary>
    public string FromAddress { get; set; } = "";

    public string NotifyUrl { get; set; } = "";
    public string NotifyTenantId { get; set; } = "";
    public string NotifyProducer { get; set; } = "panda-auth-server";
    public string NotifyTokenFile { get; set; } = "";
    public string NotifyClientCertificateFile { get; set; } = "";
    public string NotifyClientCertificatePasswordFile { get; set; } = "";
    public string NotifyServerCaFile { get; set; } = "";
}

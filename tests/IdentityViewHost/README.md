# Isolated identity view preview

Test-only host for actual compiled Server Razor views and existing static assets. Product startup, authentication, database, SMTP, configuration/env loading and production actions are not executed. A fixed synthetic model selects each view; production route metadata remains available only for correct form action generation. A request boundary prevents all production endpoints from executing. Never submit these forms as an authentication test.

`dotnet run --project tests/IdentityViewHost/PandaAuth.Server.IdentityViewHost.csproj -- <absolute-Server-root> <fresh-private-metadata-path>` starts random HTTPS loopback with an ephemeral certificate and DP. Stop with Ctrl-C. The Auth coordinator owns the optional Playwright browser driver `scripts/tests/server-identity-browser.py`; rendering/browser results prove presentation only, not credential/MFA/tenant authorization or human acceptance.

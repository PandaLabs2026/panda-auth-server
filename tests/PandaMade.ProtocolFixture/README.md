# PandaMade disposable protocol fixture

This console provisions synthetic users in a new `panda_auth_pandamade_test_<uuid>` database. It never runs against production or an existing identity pool. The guarded base connection must be loopback port 43853, database `postgres`, role `pandamade_fixture`; `PANDAMADE_TEST_POSTGRES` supplies only disposable test credentials. `PANDAMADE_FIXTURE_ROOT` must be a private directory under `/tmp/pandamade-business-test/`.

Modes: `create`, `inspect` (aggregate token counts only), `negative-clients` (isolated audience/scope clients), `cleanup` (only the recorded fixture database). State is created mode0600 and must never be printed or committed.

Build with `dotnet build tests/PandaMade.ProtocolFixture/PandaMade.ProtocolFixture.csproj`. The PandaMade Admin `test/protocol/auth.e2e.mjs` driver publishes and starts real application artifacts with a private CA, registers clients through the actual guarded command, and cleans its own processes/databases. Build/publish prerequisites are documented in the PandaMade Admin repository.

The fixture-only `IHostingStartup` shortens access-token lifetime to ten seconds to observe real refresh. Production has no reference to this test assembly. The driver copies this assembly alongside a complete published Auth artifact and opts into hosting startup with an additional dependency manifest; copying the server DLL alone is insufficient.

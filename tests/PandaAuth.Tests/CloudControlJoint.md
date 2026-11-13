# Cloud control-plane joint fixture

`CloudControlServiceJointTests` runs the actual Auth Program and a separate
Service test executable hosting the actual Service Program. Each creates its
own database in the explicitly admitted isolated PostgreSQL provider. Auth and
Service keep their own OpenIddict dependency graphs (currently 7.7.0 and 7.7.2).
The test never constructs a successful principal or changes production inputs.

Build the matching Service candidate first:

```sh
dotnet build tests/PandaCloud.Service.Integration.Tests/PandaCloud.Service.Integration.Tests.csproj --configuration Release --no-restore -m:1
```

In the Auth Server candidate, explicitly supply `PANDA_AUTH_TEST_POSTGRES` and
`FLEET_TEST_DATABASE` for the owning fixtures' admitted isolated provider, and
`CLOUD_CONTROL_SERVICE_FIXTURE_DIRECTORY` for that Service build's absolute
`bin/Release/net10.0` directory. Use the organization capacity wrapper and task
temporary directory, then run:

```sh
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj --no-restore -m:1 --filter FullyQualifiedName~CloudControlServiceJointTests
```

Missing opt-in inputs skip this test; an ordinary Server profile does not prove
joint validation. The Service directory must include its generated
`MvcTestingAppManifest.json` and matching source checkout. Separate ephemeral
loopback TLS bridges pin a run-specific certificate; discovery/introspection
still use the original issuer and the production authentication registrations.
No installed certificate, DNS, trust store or production listener is changed.

The scenario covers real PKCE-issued tokens, wrong audience, ordinary Console
denial, current application/user/object grants, tenant and shared-resource
isolation, safe Operation summaries, application/grant/token revocation and
IdP outage/recovery. With the isolated lifecycle gate open, Console's resource
permissions plus `fleet.approve` still cannot approve a tenant action or claim
its idempotency key. This does not enable any production lifecycle adapter.

The private child entry accepts only fixed fixture commands over stdin, uses
the restricted runtime database role for HTTP requests, and disposes its host,
database and role on EOF. A nonzero child exit fails the parent scenario. This
is protocol/Service evidence, not BFF/browser, formal-image or recovery evidence.

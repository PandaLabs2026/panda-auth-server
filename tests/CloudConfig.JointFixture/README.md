# Disposable Cloud Config joint IdP host

This fixture starts the real PandaAuth Server in a separate process with a
private Unix TLS listener. It uses the existing login, authorization-code/PKCE,
encrypted access-token and introspection pipeline. It is never referenced by
the production Server and supplies no production listener or registration.

The sole admitted argument is `--fixture-stdin`. The first bounded stdin line
is a serialized `JointHostPolicy`: private root, guarded fixture PG socket,
run nonce, ephemeral TLS certificate and synthetic user/client credentials.
The process requires non-root Linux, an owner-private tree under `~/dev/tmp`,
`authpg-*`/`cfgpg-*` socket and the database's matching fixture nonce. It creates
only its own `auth_config_test_<uuid>` database as `auth_config_fixture_owner`,
revokes PUBLIC connect and seeds only the synthetic user and existing Cloud
Console/config clients. The parent must provide that disposable role; there
is no production connection/environment fallback. Production Auth/connection
and listener environment overrides are refused.

After startup stdout contains only `AUTH_CONFIG_JOINT_READY`. Keeping stdin
open retains the host; EOF or the next line stops it. The process then disposes
the actual Server and removes its confirmed fixture database/private content.
Unadmitted input returns78 without echo; unresolved cleanup returns75. Tokens,
private keys and credentials must not be logged. The parent owns the remaining
private fixture root and socket cleanup after confirming process termination.

`CloudConfigJointHostTests` covers default/hostile input refusal and the real
Unix TLS discovery, browser login, PKCE, encrypted token and introspection path.
The Cloud Config caller remains responsible for its own BFF/Worker certificate,
target grants and API transaction checks; this IdP fixture is not that joint
acceptance by itself.

Bootstrap uses a new owner-only `MvcTestingAppManifest.json` in the private
content root, so it works from a caller outside the Auth checkout. It does not
add host settings that the real Server CLI allowlist would reject. The private
`client.json` supplies the owning `FirstPartyClients` client ID to callers.
Startup failure diagnostics contain only stage, exception type, SQL state and
stack frames in owner-only `failure.json`; request/policy values are omitted.

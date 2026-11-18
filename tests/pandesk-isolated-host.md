# Pandesk dual-issuer development fixture

Run from the registered Auth Server checkout on SH-01. Use the existing native NuGet restore and a verified, extracted PostgreSQL 18 Linux package root with `usr/lib/postgresql/18/bin` and `usr/share/postgresql/18`. The task temporary directory must already exist and have mode `0700`.

```bash
export PANDALABS_TEMP_ROOT="$HOME/dev/tmp/pandesk-auth-127"
pandalabs-dev run --workspace-root "$HOME/dev/worktrees/pandesk-auth-127" \
  --repo panda-auth-server --storage native -- \
  bash tests/run-pandesk-isolated-host.sh /path/to/verified/extracted/postgresql18
```

The command prints the private handoff directory at startup. Wait for `handoff.json` to appear before using either issuer. PostgreSQL and both Auth HTTPS listeners bind to IPv4 loopback. PostgreSQL uses port `43823` and startup fails if that port is occupied. The Auth issuer ports are assigned at startup. The two development tenant hosts use independent databases, certificates and client secrets.

The mode-`0600` manifest contains issuer URLs, local public certificate filenames, synthetic human subject IDs and credentials, and server-side introspection credentials. The synthetic users have MFA enabled and no Auth administrator role. Each issuer's `.totp` file contains the current short-lived code. Keep these files in the task directory and out of shared logs, source control and client builds. Give the native client only the user inputs and public issuer information it needs. The service consuming introspection uses its issuer's server-side credential.

For a local TLS and discovery check, take the hostname and port from the chosen issuer URL and pin the connection to loopback using its public PEM file.

```bash
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$issuer_host:$issuer_port:127.0.0.1" \
  --cacert "$handoff_dir/t9841.pem" \
  "https://$issuer_host:$issuer_port/.well-known/openid-configuration"
```

From a second local shell, request a clean stop with `touch -- "$handoff_dir/stop"`. The fixture also stops 15 minutes after it becomes ready. On orderly shutdown the harness removes the handoff credentials and shuts down its disposable database and both HTTPS listeners. PostgreSQL diagnostic logs stay under the path printed at startup.

The registered entry point holds the shared development lock while the fixture is running. For a joint run, launch Auth and any other registered local test commands from the same bounded development scope. Treat the discovery probe and stop marker as local controls for the running scope.

# Pandesk App issuer fixture on SH-03

The fixture starts two loopback HTTPS issuers with separate Auth databases, certificate authorities, synthetic human accounts and introspection registrations. It uses the same App challenge and registration as the business-token regression.

Use the registered native Linux workspace as a non-root developer. Restore the test project's locked dependencies through `pandalabs-env` before starting a fresh worktree. The launcher uses the locally verified PostgreSQL 18.6 image by digest and requires free loopback port 43823.

```bash
export PANDALABS_TEMP_ROOT
PANDALABS_TEMP_ROOT=$(mktemp -d "$HOME/dev/tmp/pandesk-app-127.XXXXXXXX")
export TMPDIR="$PANDALABS_TEMP_ROOT" TMP="$PANDALABS_TEMP_ROOT" TEMP="$PANDALABS_TEMP_ROOT"
pandalabs-env run --repo panda-auth-server --storage docker --workspace-root "$workspace" -- \
  bash tests/run-pandesk-app-issuer-handoff.sh
```

The launcher prints the location of `handoff.json` before the issuer tests start. Read it after the file appears. Each entry gives the exact issuer, its actual loopback port, the public CA file and its SHA-256 fingerprint. Use the issuer URL for TLS and discovery, and direct the connection to that issuer's loopback listener. For example, with values read from one entry:

```bash
curl --fail --silent --show-error --noproxy '*' \
  --connect-to "$issuer_host:443:127.0.0.1:$loopback_port" \
  --cacert "$handoff_dir/$ca_file" "${issuer}.well-known/openid-configuration"
```

Keep the task directory private. Each issuer's login and rotating TOTP files are for the App test driver. Its introspection file is for the Oasis test host. Supply each consumer only the files it needs and keep the contents out of logs, test reports and source control. The manifest contains isolated Auth fixture metadata. The organization directory owner confirms dossier issuance and trust, and Oasis confirms the Host, tenant, Sales application and isolated database binding.

Create `"$handoff_dir/stop"` to end the run. The fixture also stops 15 minutes after the manifest is published. Teardown removes the handoff files, both listeners and the task's PostgreSQL container and network. The TRX stays in the task directory.

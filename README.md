# Lenso Secrets Plugins

Replaceable secret-reference resolution for Lenso applications.

This repository owns one Capability, `lenso.secrets@1`, and four Provider
Plugins:

| Plugin ID | Source | Intended use |
| --- | --- | --- |
| `lenso.secrets.env` | allowlisted environment variables | local development and controlled deployments |
| `lenso.secrets.keychain` | macOS Generic Password items | local macOS agents |
| `lenso.secrets.encrypted-file` | a passphrase-encrypted age file | portable local and headless agents |
| `lenso.secrets.command` | a bounded external resolver | 1Password CLI and remote Secret Manager CLIs |

An application selects exactly one Provider for the `secrets` slot. Consumers
only request logical references such as `model/openai-api-key`; they do not know
which Provider supplies them. Changing Profile can therefore change both the
Provider and its configuration without changing the consumer Plugin.

Secret values never belong in an App Plan, Plugin configuration, diagnostics,
errors, logs, snapshots, or `Debug` output. Configuration contains logical
references and provider-local source names only. Preparation verifies every
configured source, and resolution reads the source again so rotation is
observed without creating another durable authority.

## Plugin configuration

Put the selected Provider's TOML file in the application's standard `plugins/`
configuration tree. These are complete configuration examples; adapt the file
name to the Plugin Instance name selected by the Profile.

### Environment

```toml
[references]
"model/openai-api-key" = "OPENAI_API_KEY"
"database/url" = "APP_DATABASE_URL"
```

### macOS Keychain

```toml
service = "com.lenso.agent"

[references]
"model/openai-api-key" = "openai-api-key"
```

Create or update the corresponding Generic Password without putting the value
in shell history. `security` prompts because `-w` is the final argument:

```sh
security add-generic-password -U \
  -s com.lenso.agent \
  -a openai-api-key \
  -w
```

The Keychain Provider is available only on macOS. A Profile selecting it fails
preparation on other operating systems.

### Encrypted local file

```toml
path = ".lenso/secrets.age"
key_environment_variable = "LENSO_SECRETS_FILE_PASSPHRASE"
max_file_bytes = 1048576
max_plaintext_bytes = 1048576
max_records = 100

[references]
"model/openai-api-key" = "openai"
```

The decrypted document is a versioned JSON map:

```json
{
  "version": 1,
  "secrets": {
    "openai": "the-secret-value"
  }
}
```

Encrypt it with the standard age passphrase format
(`age -p -o .lenso/secrets.age secrets.json`). Supply the passphrase through
the configured environment variable and remove the plaintext source after
checking the age file. The Provider rejects symlinks, malformed containers,
excessive sizes, unknown versions, and missing records. It decrypts afresh on
each resolution.

### 1Password or another remote Secret Manager

```toml
program = "/opt/homebrew/bin/op"
arguments = ["read", "--no-newline", "{source}"]
environment_allowlist = ["OP_SERVICE_ACCOUNT_TOKEN", "HOME"]
timeout_ms = 30000
max_output_bytes = 65536

[references]
"model/openai-api-key" = "op://agent/openai/password"
```

`{source}` must be one standalone argument and appears exactly once. The
Provider executes the canonical absolute program directly without a shell,
clears its environment, restores only allowlisted variables, applies a timeout
and output bound, and never includes stdout or stderr in failures. Each resolve
starts a fresh command, so the remote manager remains authoritative.

This Plugin is an integration boundary for trusted resolver programs, not a
process sandbox. The configured command must return one secret on stdout and
must not daemonize or leave descendant processes holding its output pipes. Use
a vendor-specific Provider when its authentication, leasing, renewal, or audit
semantics need first-class lifecycle support.

## Failure model

- malformed or unbound logical references are typed Domain Errors;
- a missing configured source fails Plugin preparation;
- source loss after preparation is a Runtime Failure;
- there is no Provider fallback or global secret discovery.

## Verify

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --locked --workspace --all-targets
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --locked --workspace
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo clippy --locked --workspace --all-targets -- -D warnings
```

Crates.io publication must publish `lenso-capability-secrets` before the
Provider crates can complete registry-backed package verification.

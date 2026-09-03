# Release process

Publication is manual-only from reviewed `main` through
`.github/workflows/release-plz.yml`. Repository pushes do not run release
automation. A live run additionally requires `live=true`, the literal
confirmation `publish`, and `main`.

## Current provider release

`lenso-capability-secrets` 0.1.2 and `lenso-secrets-env-plugin` 0.1.2 are
already available from crates.io. Publish the new Provider crates in this
order; each depends only on the published Capability and platform crates:

1. `lenso-secrets-command-plugin` 0.1.0
2. `lenso-secrets-encrypted-file-plugin` 0.1.0
3. `lenso-secrets-keychain-plugin` 0.1.0

Before the first release, allocate each new crate name on crates.io, then
configure a separate Trusted Publisher for it:

- owner: `LioRael`
- repository: `lenso-secrets-plugin`
- workflow: `release-plz.yml`
- environment: unset

Only the confirmed live job receives `id-token: write`. There is no registry
token fallback in the workflow. If initial name allocation requires a
temporary new-package-only token, revoke it immediately after allocation; all
reviewed releases use OIDC.

## Required evidence

```sh
cargo fmt --all -- --check
lenso-contract-codegen workspace check --manifest-path Cargo.toml
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
./scripts/check-repository-boundary.sh
cargo package --locked -p lenso-capability-secrets
cargo package --locked --list -p lenso-secrets-env-plugin
cargo package --locked --list -p lenso-secrets-command-plugin
cargo package --locked --list -p lenso-secrets-encrypted-file-plugin
cargo package --locked --list -p lenso-secrets-keychain-plugin
```

The Keychain Provider's macOS behavior must also pass on a macOS runner before
publication. Generated Capability projections are locked artifacts and must
not be edited by hand.

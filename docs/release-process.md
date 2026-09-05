# Release process

Publication is manual-only from reviewed `main` through
`.github/workflows/release-plz.yml`. Repository pushes do not run release
automation. A live run additionally requires `live=true`, the literal
confirmation `publish`, and `main`.

The commit selected for a live release must come from a reviewed pull request
whose source branch starts with `release-plz-`; release-plz uses that branch
identity as its release-commit proof.

## Current provider release

The native-linkage release publishes in dependency order:

1. `lenso-capability-secrets` 0.1.4
2. `lenso-secrets-env-plugin` 0.1.7
3. `lenso-secrets-command-plugin` 0.1.4
4. `lenso-secrets-encrypted-file-plugin` 0.1.4
5. `lenso-secrets-keychain-plugin` 0.1.4

These versions use App Plan 0.4, Kernel 0.3, Native Adapter 0.3.6, and the
generated `lenso.secrets@1` descriptor digest. They form one compatibility
cohort for consumers such as the Agent Host. Each Provider exports an explicit,
non-elidable `link()` anchor so optimized Host binaries retain its native
inventory registration through an indirect linkage-set dependency.
The workspace link smoke test exercises that same two-crate aggregation path.
These releases delegate to Native Adapter 0.3.6's generated factory anchors.

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

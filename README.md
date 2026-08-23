# Lenso Secrets Module

Explicit secret-reference resolution for Lenso vNext applications.

This repository owns:

- the generated `lenso.secrets@1` Capability contract; and
- `lenso-secrets-env-module`, a linked Rust development Provider backed by an
  immutable logical-reference to environment-variable allowlist.

It does not own application configuration, business authorization, cloud
secret lifecycle, a global secret registry, or automatic Provider fallback.
Secret values never belong in an App Plan, Module configuration, diagnostics,
errors, or `Debug` output.

## First useful workflow

The App author binds a consumer's `lenso.secrets@1` requirement to one Env
Secrets Module Instance. The host configures an allowlist such as
`database/url -> APP_DATABASE_URL`. App preparation fails if any configured
source is unavailable. A configured reference resolves through the immutable
binding; invalid and unknown references remain typed Domain Errors.

The Module Instance configuration is ordinary non-secret Plan data:

```json
{
  "references": {
    "database/url": "APP_DATABASE_URL",
    "auth/signing-key": "APP_AUTH_SIGNING_KEY"
  }
}
```

The Env Provider is for local development and controlled host deployments. A
production cloud Provider should implement the same Capability in its own
crate and own its authentication, rotation, availability, and audit policy.

## Verify

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Publication remains parked until repository review and crates.io Trusted
Publishers are configured. The initial release must publish
`lenso-capability-secrets` before `lenso-secrets-env-module` can complete its
registry-backed package verification.

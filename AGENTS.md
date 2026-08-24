# Agent instructions

This repository owns `lenso.secrets@1` and explicit Secrets Provider Modules
for Lenso vNext.

Keep secret values out of App Plans, configuration documents, generated
artifacts, diagnostics, errors, logs, snapshots, and `Debug` output. Provider
configuration may contain logical references and provider-local source names,
never resolved values.

Bindings are immutable before boot. Do not add global discovery, fallback
Providers, ambient environment scanning, Auth policy, business authorization,
or persistence ownership here. Missing configured sources fail preparation;
runtime source loss remains a truthful Runtime Failure.

The Capability descriptor is authoritative. This native Capability crate owns
only its Rust projection; the supported Bun SDK owns the TypeScript projection.
Regenerate both through `lenso-contract-codegen`; never hand-edit them.

Create task worktrees with `wt switch --create`. Run Cargo through
`/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo` when
available. Preserve unrelated work and stage only requested files.

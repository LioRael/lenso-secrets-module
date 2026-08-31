# Plan 001: Read encrypted files through one bounded no-follow handle

> Drift check: `git diff --stat 967fa0d..HEAD -- crates/lenso-secrets-encrypted-file-plugin`.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `967fa0d`, 2026-08-30

## Why this matters

`load_document` checks path metadata and then reopens by path, leaving a replacement
race and allocating the complete file before the final size check. The README promises
symlink and excessive-size rejection.

## Current state

- `src/lib.rs:168-181` calls `symlink_metadata`, then `fs::read`.
- `README.md:86-91` documents no symlinks and bounded input.

## Scope

In scope: encrypted-file plugin source, minimal platform dependency if required, and
filesystem tests. Out of scope: AGE format, key sources, or command secrets.

## Steps

1. Add tests for direct symlink, oversized file, bounded allocation behavior, and a
   deterministic replacement hook/race where feasible.
2. Open once with no-follow semantics, inspect metadata from that handle, require a
   regular nonempty file within the configured bound, then `take(max+1)` from the same
   handle and reject overflow.
3. Keep all errors sanitized and preserve zeroization of decrypted material.

## Verification

- `cargo test -p lenso-secrets-encrypted-file-plugin` -> all pass.
- `cargo check -p lenso-secrets-encrypted-file-plugin --all-targets` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop if a supported target lacks a safe no-follow primitive; use target-specific code
with tests rather than silently falling back to the original race.

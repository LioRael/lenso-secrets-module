#!/usr/bin/env bash
set -euo pipefail

if rg -n 'path\s*=\s*"(\.\./\.\./|/)' --glob 'Cargo.toml' .; then
  echo "cross-repository or absolute path dependencies are not allowed" >&2
  exit 1
fi

if rg -n 'lenso-platform-|lenso 0\.3|lenso::host' \
  --glob '!Cargo.lock' \
  --glob '!scripts/check-repository-boundary.sh' \
  .; then
  echo "legacy Lenso platform dependencies are not allowed" >&2
  exit 1
fi

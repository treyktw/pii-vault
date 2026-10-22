#!/usr/bin/env bash
# Regenerates testdata/vectors.json: Node seals first, then Go adds its half.
# Both test suites read the result, so a change to either side's AAD, HKDF
# info or base64 handling shows up as a failing interop test.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/testdata/vectors.json"
(cd "$root/ts" && npx tsx scripts/generate-vectors.ts "$out")
(cd "$root/go" && go run ./cmd/gen-vectors "$out")

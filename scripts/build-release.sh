#!/usr/bin/env bash
# Build deterministic dproxy release binaries, archives, and SHA256SUMS.
#
# Usage: scripts/build-release.sh <tag> [output-directory] [targets]
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <tag> [output-directory] [targets]" >&2
    exit 2
fi

tag="$1"
output="${2:-dist}"
targets="${3:-darwin/arm64,darwin/amd64,linux/arm64,linux/amd64}"

go run ./tools/releasebuilder/main.go \
    -tag "$tag" \
    -output "$output" \
    -targets "$targets"

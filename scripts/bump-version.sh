#!/usr/bin/env bash
# Update VERSION, the source-build version, and CHANGELOG.md.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <major|minor|patch|x.y.z>" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
go -C "$repo_root/tools" run ./versionbump -root "$repo_root" "$1"

#!/usr/bin/env bash
# Fail if any Go source is not gofmt-formatted or goimports-organized.
#
# Both tools are checked because they disagree: gofmt does not group or sort
# imports the way goimports does, so a file can be gofmt-clean and still be
# unformatted by this repository's standard.
#
# Usage: scripts/check-format.sh [path-to-goimports]
set -euo pipefail

cd "$(dirname "$0")/.."

goimports="${1:-bin/goimports}"
if [ ! -x "$goimports" ]; then
    echo "$goimports is missing; run 'make tools'" >&2
    exit 1
fi

status=0

unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
    echo "these files are not gofmt-formatted (run 'make fmt'):" >&2
    echo "$unformatted" >&2
    status=1
fi

unorganized="$("$goimports" -l .)"
if [ -n "$unorganized" ]; then
    echo "these files have unorganized imports (run 'make fmt'):" >&2
    echo "$unorganized" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "formatting: ok"
fi
exit "$status"

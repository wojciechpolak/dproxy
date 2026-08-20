#!/usr/bin/env bash
# Fail if "go mod tidy" would change either module.
#
# A dependency that is present but unrecorded, or recorded but unused, makes
# the vulnerability check report on a set that differs from what is built.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

check_module() {
    local dir="$1"
    local work
    work="$(mktemp -d)"
    cp "$dir/go.mod" "$work/"
    [ -f "$dir/go.sum" ] && cp "$dir/go.sum" "$work/"

    go -C "$dir" mod tidy

    local dirty=0
    diff -q "$work/go.mod" "$dir/go.mod" >/dev/null || dirty=1
    if [ -f "$work/go.sum" ] || [ -f "$dir/go.sum" ]; then
        diff -q "$work/go.sum" "$dir/go.sum" >/dev/null 2>&1 || dirty=1
    fi

    if [ "$dirty" -ne 0 ]; then
        echo "$dir is not tidy (run 'go -C $dir mod tidy' and commit the result):" >&2
        diff -u "$work/go.mod" "$dir/go.mod" >&2 || true
        # Restore what the check rewrote so a failing run leaves no changes.
        cp "$work/go.mod" "$dir/go.mod"
        [ -f "$work/go.sum" ] && cp "$work/go.sum" "$dir/go.sum"
        status=1
    fi
    rm -rf "$work"
}

check_module .
check_module tools

if [ "$status" -eq 0 ]; then
    echo "modules: tidy"
fi
exit "$status"

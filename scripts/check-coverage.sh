#!/usr/bin/env bash
# Run the unit suite with statement coverage and enforce an aggregate floor.
set -euo pipefail

cd "$(dirname "$0")/.."

minimum="${1:-90.0}"
if ! awk -v minimum="$minimum" 'BEGIN {
    valid = minimum ~ /^[0-9]+([.][0-9]+)?$/ && minimum >= 0 && minimum <= 100
    exit !valid
}'; then
    echo "coverage minimum must be a number from 0 through 100: $minimum" >&2
    exit 2
fi

profile="$(mktemp)"
trap 'rm -f "$profile"' EXIT

go_command="${GO:-go}"
"$go_command" test -covermode=atomic -coverprofile="$profile" ./...
report="$("$go_command" tool cover -func="$profile")"

total="$(printf '%s\n' "$report" | awk '/^total:/ {
    sub(/%$/, "", $3)
    print $3
}')"
if [ -z "$total" ]; then
    echo "coverage report did not contain an aggregate total" >&2
    exit 1
fi

awk -v total="$total" -v minimum="$minimum" 'BEGIN {
    if (total + 0 < minimum + 0) {
        printf "coverage %.1f%% is below the %.1f%% minimum\n", total, minimum > "/dev/stderr"
        exit 1
    }
    printf "coverage %.1f%% meets the %.1f%% minimum\n", total, minimum
}'

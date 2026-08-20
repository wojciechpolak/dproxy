#!/usr/bin/env bash
# Rebuild one release target twice and compare every byte.
set -euo pipefail

tag="${1:-v0.0.0-test}"
target="${2:-darwin/arm64}"
first="$(mktemp -d)"
second="$(mktemp -d)"
trap 'rm -rf "$first" "$second"' EXIT

./scripts/build-release.sh "$tag" "$first" "$target"
./scripts/build-release.sh "$tag" "$second" "$target"
diff -r "$first" "$second"

archive="$(find "$first" -name '*.tar.gz' -type f -print -quit)"
tar -tzf "$archive" | diff -u - <(printf 'LICENSE\ndproxy\n')
test -x "$first/dproxy-darwin-arm64"
cmp "$first/dproxy-darwin-arm64" <(tar -xOzf "$archive" dproxy)

(
    cd "$first"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum --check SHA256SUMS
    else
        shasum -a 256 --check SHA256SUMS
    fi
)

formula="$first/dproxy.rb"
zero="$(printf '0%.0s' {1..64})"
one="$(printf '1%.0s' {1..64})"
two="$(printf '2%.0s' {1..64})"
three="$(printf '3%.0s' {1..64})"
./scripts/render-homebrew-formula.sh \
    v0.0.0 "$zero" "$one" "$two" "$three" "$formula"
ruby -c "$formula"
grep -F 'dproxy_v0.0.0_darwin_arm64.tar.gz' "$formula"
grep -F 'dproxy_v0.0.0_darwin_amd64.tar.gz' "$formula"
grep -F 'dproxy_v0.0.0_linux_arm64.tar.gz' "$formula"
grep -F 'dproxy_v0.0.0_linux_amd64.tar.gz' "$formula"
! grep -F 'depends_on :macos' "$formula"
grep -F 'run [opt_bin/"dproxy", "client"]' "$formula"
grep -F 'keep_alive true' "$formula"
grep -F 'error_log_path var/"log/dproxy.log"' "$formula"
grep -F 'stop_timeout 35' "$formula"

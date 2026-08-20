#!/bin/sh

set -eu

for command in awk grep sudo tcpdump uname; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "$command is required for the Cloudflare privacy test" >&2
		exit 1
	fi
done

capture_interface=${DPROXY_CF_CAPTURE_INTERFACE:-}
if [ -z "$capture_interface" ]; then
	case $(uname -s) in
		Linux)
			capture_interface=any
			;;
		Darwin)
			capture_interface=$(route -n get default 2>/dev/null | awk '$1 == "interface:" { print $2; exit }')
			;;
		*)
			echo "DPROXY_CF_CAPTURE_INTERFACE is required on this operating system" >&2
			exit 1
			;;
	esac
fi
if [ -z "$capture_interface" ]; then
	echo "could not determine the packet-capture interface; set DPROXY_CF_CAPTURE_INTERFACE" >&2
	exit 1
fi

require_variable() {
	if [ -z "$2" ]; then
		echo "$1 is required for the Cloudflare privacy test" >&2
		exit 1
	fi
}
require_variable DPROXY_CF_URL "${DPROXY_CF_URL:-}"
require_variable DPROXY_CF_PIN "${DPROXY_CF_PIN:-}"
require_variable DPROXY_CF_TOKEN_FILE "${DPROXY_CF_TOKEN_FILE:-}"

capture=$(mktemp "${TMPDIR:-/tmp}/dproxy-capture.XXXXXX")
capture_log=$(mktemp "${TMPDIR:-/tmp}/dproxy-tcpdump.XXXXXX")
tcpdump_pid=

cleanup() {
	if [ -n "$tcpdump_pid" ]; then
		sudo -n kill -INT "$tcpdump_pid" >/dev/null 2>&1 || true
		wait "$tcpdump_pid" >/dev/null 2>&1 || true
	fi
	rm -f "$capture" "$capture_log"
}
trap cleanup EXIT HUP INT TERM

sudo -v
sudo -n tcpdump -i "$capture_interface" -n -U -s 0 -w "$capture" \
	'tcp port 443 or tcp port 53 or udp port 53' >"$capture_log" 2>&1 &
tcpdump_pid=$!
sleep 1
if ! sudo -n kill -0 "$tcpdump_pid" >/dev/null 2>&1; then
	echo "tcpdump exited before the Cloudflare test started:" >&2
	cat "$capture_log" >&2
	wait "$tcpdump_pid" >/dev/null 2>&1 || true
	tcpdump_pid=
	exit 1
fi

go test -tags cloudflare ./internal/integration -run TestCloudflareIntegration -count=1

sleep 1
if ! sudo -n kill -0 "$tcpdump_pid" >/dev/null 2>&1; then
	echo "tcpdump exited before the Cloudflare test completed:" >&2
	cat "$capture_log" >&2
	wait "$tcpdump_pid" >/dev/null 2>&1 || true
	tcpdump_pid=
	exit 1
fi
sudo -n kill -INT "$tcpdump_pid"
wait "$tcpdump_pid" >/dev/null 2>&1 || true
tcpdump_pid=
sudo -n chmod 0644 "$capture"

if ! tcpdump -n -r "$capture" 'tcp port 443' 2>/dev/null | grep -q .; then
	echo "capture contains no TCP 443 traffic; check DPROXY_CF_CAPTURE_INTERFACE" >&2
	exit 1
fi

if tcpdump -n -r "$capture" 'tcp port 53 or udp port 53' 2>/dev/null | grep -q .; then
	echo "capture contains an ordinary DNS query" >&2
	exit 1
fi

relay_host=$(printf '%s\n' "$DPROXY_CF_URL" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
token=$(tr -d '\r\n' <"$DPROXY_CF_TOKEN_FILE")
target=${DPROXY_CF_TARGET:-example.com}
for plaintext in "$relay_host" "$target" "$token"; do
	if [ -n "$plaintext" ] && LC_ALL=C grep -aF -q "$plaintext" "$capture"; then
		echo "capture contains forbidden plaintext: $plaintext" >&2
		exit 1
	fi
done

echo "capture contains no relay hostname, target hostname, token, or ordinary DNS query"

#!/bin/sh

set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
e2e_directory=$(mktemp -d "${TMPDIR:-/tmp}/dproxy-e2e.XXXXXX")
compose_file="$repository/test/docker/docker-compose.yml"

export DPROXY_E2E_DIR="$e2e_directory"
export DPROXY_E2E_UID="$(id -u)"
export DPROXY_E2E_GID="$(id -g)"
# DPROXY_E2E_CLIENT_PINS=1 makes the fixture write client_pins into server.toml
# and the suite present the matching client identity. Exporting it here keeps
# the container and the client on the same configuration.
export DPROXY_E2E_CLIENT_PINS="${DPROXY_E2E_CLIENT_PINS:-0}"

cleanup() {
	docker compose -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$e2e_directory"
}
trap cleanup EXIT HUP INT TERM

cd "$repository"
go run -tags e2e_fixture ./internal/integration/fixture init "$e2e_directory"
docker compose -f "$compose_file" up --build --detach

attempt=0
until curl --fail --silent --show-error http://127.0.0.1:18686/healthz >/dev/null; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 30 ]; then
		docker compose -f "$compose_file" logs
		exit 1
	fi
	sleep 1
done

if [ "${DPROXY_DOCKER_BENCHMARK:-}" = 1 ]; then
	: "${DPROXY_BENCH_SETUP:=100x}"
	: "${DPROXY_BENCH_TIME:=2s}"
	: "${DPROXY_BENCH_COUNT:=5}"
	go test -tags e2e,docker_e2e ./internal/integration -run '^$' \
		-bench '^BenchmarkDockerizedRemoteTunnelSetup$' -benchmem \
		-benchtime "$DPROXY_BENCH_SETUP" -count "$DPROXY_BENCH_COUNT"
	go test -tags e2e,docker_e2e ./internal/integration -run '^$' \
		-bench '^BenchmarkDockerizedRemoteThroughput$' -benchmem \
		-benchtime "$DPROXY_BENCH_TIME" -count "$DPROXY_BENCH_COUNT"
	exit 0
fi

go test -race -tags docker_e2e -v ./internal/integration -run TestDockerizedRemote -count=1

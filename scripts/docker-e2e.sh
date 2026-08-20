#!/bin/sh

set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
e2e_directory=$(mktemp -d "${TMPDIR:-/tmp}/dproxy-e2e.XXXXXX")
compose_file="$repository/test/docker/docker-compose.yml"

export DPROXY_E2E_DIR="$e2e_directory"
export DPROXY_E2E_UID="$(id -u)"
export DPROXY_E2E_GID="$(id -g)"

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

go test -race -tags docker_e2e ./internal/integration -run TestDockerizedRemoteEndToEnd -count=1

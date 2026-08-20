#!/usr/bin/env bash
# Fail if the product module has acquired a dependency.
#
# dproxy links the standard library and nothing else, and every dependency
# added later is a deliberate decision that must be argued for in review
# rather than arriving as a transitive requirement. This check is what makes
# that visible: it fails on the first module that is not the standard library,
# whether it reaches the binary or only the tests.
#
# Development tools live in tools/, a separate module, so they cannot be what
# trips this.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

if [ -f go.sum ]; then
    echo "go.sum exists; the product module is supposed to have no dependencies:" >&2
    awk '{print "  " $1}' go.sum | sort -u >&2
    status=1
fi

requirements="$(go list -m -f '{{if not .Main}}{{.Path}}{{end}}' all)"
if [ -n "$requirements" ]; then
    echo "the product module requires modules:" >&2
    echo "$requirements" | sed 's/^/  /' >&2
    status=1
fi

linked="$(go list -deps -test -f '{{if and .Module (ne .Module.Path "github.com/wojciechpolak/dproxy")}}{{.Module.Path}}{{end}}' ./... | sort -u)"
if [ -n "$linked" ]; then
    echo "these non-standard-library modules are linked into the binary or the tests:" >&2
    echo "$linked" | sed 's/^/  /' >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "dependencies: standard library only"
fi
exit "$status"

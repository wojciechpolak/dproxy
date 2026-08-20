#!/usr/bin/env bash
# Fail if any Markdown file is not markdownfmt-formatted, or if its prose is
# not wrapped at 80 columns.
#
# Two Go tools, no other language: markdownfmt is the Go-native formatter, and
# mdwrap (tools/mdwrap) does the wrapping markdownfmt has no option for.
# Documentation formatting must not pull another toolchain into this
# repository.
#
# Usage: scripts/check-markdown.sh [path-to-markdownfmt] [path-to-mdwrap]
set -euo pipefail

cd "$(dirname "$0")/.."

markdownfmt="${1:-bin/markdownfmt}"
mdwrap="${2:-bin/mdwrap}"
for tool in "$markdownfmt" "$mdwrap"; do
    if [ ! -x "$tool" ]; then
        echo "$tool is missing; run 'make tools'" >&2
        exit 1
    fi
done

mapfile -t files < <(find . -name '*.md' -not -path './.git/*' | sort)
if [ "${#files[@]}" -eq 0 ]; then
    echo "markdown: no files"
    exit 0
fi

status=0

unformatted="$("$markdownfmt" -soft-wraps -l "${files[@]}")"
if [ -n "$unformatted" ]; then
    echo "these Markdown files are not markdownfmt-formatted (run 'make md-fmt'):" >&2
    echo "$unformatted" >&2
    status=1
fi

# A correctly wrapped file is a fixpoint, so "would mdwrap change it" is the
# whole check: no rules are needed about which long lines are acceptable.
unwrapped="$("$mdwrap" -l "${files[@]}" || true)"
if [ -n "$unwrapped" ]; then
    echo "these Markdown files are not wrapped at 80 columns (run 'make md-wrap'):" >&2
    echo "$unwrapped" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "markdown: ok"
fi
exit "$status"

# Releases

Stable releases publish binaries and archives for macOS and Linux on arm64 and
amd64, plus a multi-platform remote-server image at
`ghcr.io/wojciechpolak/dproxy`. Each release includes SHA-256 checksums and
GitHub build attestations. The container image also includes an attested SPDX
software bill of materials. The GitHub release body is the matching version's
entry in `CHANGELOG.md`.

Stable images receive `X.Y.Z`, `X.Y`, and `latest` tags. Prerelease images
receive only their full version, such as `1.0.0-rc.1`.

## Verify a downloaded release

Homebrew checks an archive's SHA-256 digest before installation. For a direct
download, fetch the binary and checksum manifest from the same release. Use
`arm64` on Apple Silicon and `amd64` on an Intel Mac:

```sh
tag=vX.Y.Z
arch=arm64
asset="dproxy-darwin-${arch}"
gh release download "$tag" \
  --repo wojciechpolak/dproxy \
  --pattern "$asset" \
  --pattern SHA256SUMS
grep "  ${asset}$" SHA256SUMS | shasum -a 256 --check
gh attestation verify "$asset" --repo wojciechpolak/dproxy
```

Verify the matching remote-server image with:

```sh
tag=vX.Y.Z
image_tag="${tag#v}"
gh attestation verify "oci://ghcr.io/wojciechpolak/dproxy:${image_tag}" \
  --repo wojciechpolak/dproxy
docker pull "ghcr.io/wojciechpolak/dproxy:${image_tag}"
```

## Reproduce the release files

Check out the release tag and use the Go version declared in `go.mod`:

```sh
tag=vX.Y.Z
git checkout "$tag"
SOURCE_DATE_EPOCH=0 make release TAG="$tag"
```

Compare the generated `SHA256SUMS` with the published manifest. Reproduction
requires the same Go toolchain. `make release-check` builds one target twice and
rejects any byte difference in its binary or archive.

## Publish a release

Update the version and changelog with one of these commands:

```sh
make bump VERSION=patch
make bump VERSION=minor
make bump VERSION=major
make bump VERSION=1.2.3
```

Before creating the tag, run `make e2e-cloudflare` from a maintainer-controlled
host against the exact release commit and record the result in the release
notes. The live deployment and packet-capture check does not run on
GitHub-hosted runners.

The release workflow needs `HOMEBREW_TAP_TOKEN`, with read and write access to
`wojciechpolak/homebrew-dproxy`.

Create and push a semantic-version tag such as `v1.0.0` only after the manual
Cloudflare check passes. The workflow requires a non-empty entry for the tagged
version in `CHANGELOG.md`, then runs the deterministic local, end-to-end, and
reproducibility checks before publishing. It publishes the changelog entry as
the GitHub release notes alongside the binaries, archives, checksums,
attestations, remote image, and tested Homebrew formula. Release assets are
attached to a draft before the workflow makes the release public.

The workflow refuses to replace existing release files with different bytes.
Prerelease tags do not update `latest`, the stable minor image tag, or the
Homebrew formula.

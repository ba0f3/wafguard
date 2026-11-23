# GoReleaser release pipeline — design

## Goal

On a pushed `v*` tag, automatically build the `wafguard` binary, publish a Docker
image to GHCR, and attach release artifacts to the GitHub release. Ordinary
pushes publish nothing.

## Current state

- Module `github.com/ba0f3/haproxy-waf-spoe`, Go 1.27.4.
- Single binary entrypoint: `./cmd/wafguard`.
- `deploy/Dockerfile` is a source-building two-stage image (Go builder →
  `alpine:3.20` runtime, ca-certificates, ports 12345/9090, CMD
  `["/wafguard", "-config", "/etc/wafguard/config.json"]`).
- No `.github/` workflows, no git tags, no version ldflags in the code.

## Approach

Add one GoReleaser config and one Actions workflow. Do not reuse
`deploy/Dockerfile` for GoReleaser: it rebuilds from source, which discards the
binary GoReleaser just produced. Instead add a runtime-only Dockerfile that
keeps the existing runtime shape and copies the prebuilt binary.

## Files

### `.goreleaser.yaml` (schema v2)

- `builds`: `./cmd/wafguard`, id `wafguard`, binary `wafguard`, `goos: [linux]`,
  `goarch: [amd64]`, `CGO_ENABLED=0`.
- `archives`: default tar.gz + `checksum`.
- `dockers`: one image from `deploy/Dockerfile.goreleaser`, tagged
  `ghcr.io/ba0f3/haproxy-waf-spoe:{{ .Version }}` and `:latest`, with OCI source
  labels. `goos`/`goarch` match the build.
- `changelog`: GoReleaser default.

### `deploy/Dockerfile.goreleaser`

```
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY wafguard /wafguard
EXPOSE 12345 9090
CMD ["/wafguard", "-config", "/etc/wafguard/config.json"]
```

### `.github/workflows/release.yml`

Trigger `push.tags: ["v*"]`. Permissions `contents: write`, `packages: write`.
Steps: checkout with `fetch-depth: 0`, `actions/setup-go@v5` using
`go-version-file: go.mod`, `make test`, `docker/login-action@v3` to `ghcr.io`
with `github.actor` and `secrets.GITHUB_TOKEN`, then
`goreleaser/goreleaser-action@v6` with `version: '~> v2'` and
`args: release --clean`, passing `GITHUB_TOKEN`.

## Decisions made here (not user choices)

- No ldflags or `-version` flag: not requested, and injecting into absent
  symbols would be dead config.
- Single `linux/amd64` image, not multi-arch manifests.
- No `make release` / `make snapshot` convenience targets.
- No credentials beyond the built-in `GITHUB_TOKEN`.

## Verification

- `goreleaser check` passes on the config.
- `goreleaser release --snapshot --clean --skip=publish` produces a binary and
  image locally (publish steps skipped), confirming the Docker context is valid.
- `make lint`, `make vet`, `make test` remain green.

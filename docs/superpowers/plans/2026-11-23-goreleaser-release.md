# GoReleaser Release Pipeline Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Publish `wafguard` binaries and a GHCR Docker image automatically when a `v*` tag is pushed.
**Architecture:** A v2 GoReleaser config builds the single Go binary and hands it to a runtime-only Dockerfile for image publishing. A GitHub Actions workflow gates on tests, logs in to GHCR with the built-in token, and invokes GoReleaser. The existing source-building `deploy/Dockerfile` is left untouched.
**Tech Stack:** GoReleaser 2.20.2 (local), schema `version: 2`, GitHub Actions (`actions/checkout@v4`, `actions/setup-go@v5`, `docker/login-action@v3`, `goreleaser/goreleaser-action@v6`), GHCR.
**Spec:** `docs/superpowers/specs/2026-11-23-goreleaser-release.md`

## Global Constraints
- Go version is `1.27.4` (`go.mod`); workflow must use `go-version-file: go.mod`.
- GHCR image name is exactly `ghcr.io/ba0f3/haproxy-waf-spoe`.
- Release trigger is exactly `push` on tags matching `v*`. Ordinary pushes publish nothing.
- Binary entrypoint is `./cmd/wafguard`; output binary name `wafguard`; `CGO_ENABLED=0`.
- Runtime image base `alpine:3.20` with `ca-certificates`, ports `12345`/`9090`, and CMD `["/wafguard", "-config", "/etc/wafguard/config.json"]` (verbatim from `deploy/Dockerfile`).
- No credentials beyond `secrets.GITHUB_TOKEN`; workflow permissions `contents: write` and `packages: write`.
- No version ldflags, no multi-arch manifests, no `make release` target.

## Review Focus
- **No `v*` tag exists yet** — nothing will publish until one is pushed; verification uses a local snapshot, not a real release.
- **GHCR push denied without `packages: write`** — workflow declares both permissions explicitly; local snapshot skips publish.
- **Docker context missing the binary** — the release Dockerfile must `COPY wafguard` from the context root; snapshot build proves the context is valid.
- **Schema drift** — local GoReleaser is 2.20.2; `goreleaser check` must pass with `version: 2`.
- **Existing Dockerfile must stay usable** — no edits to `deploy/Dockerfile`; the new release Dockerfile is separate.

---

### Task 1: GoReleaser config and release Dockerfile
**Files:**
- Create: `.goreleaser.yaml`
- Create: `deploy/Dockerfile.goreleaser`

**Interfaces:**
- Consumes: `./cmd/wafguard` (main package), `go.mod` version 1.27.4, `deploy/Dockerfile` runtime shape.
- Produces: image tags `ghcr.io/ba0f3/haproxy-waf-spoe:{{ .Version }}` and `:latest`; archives + `checksums.txt` as release artifacts.

- [ ] **Step 1: Write `deploy/Dockerfile.goreleaser`**
```
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY wafguard /wafguard
EXPOSE 12345 9090
CMD ["/wafguard", "-config", "/etc/wafguard/config.json"]
```

- [ ] **Step 2: Write `.goreleaser.yaml`**
Top-level `version: 2`. `builds`: id `wafguard`, `main: ./cmd/wafguard`, `binary: wafguard`, `goos: [linux]`, `goarch: [amd64]`, `env: [CGO_ENABLED=0]`. `archives`: defaults plus `checksum`. `dockers`: single entry, `dockerfile: deploy/Dockerfile.goreleaser`, `image_templates` with `:{{ .Version }}` and `:latest`, `goos: linux`, `goarch: amd64`, and `build_flag_templates` carrying `--label=org.opencontainers.image.source=https://github.com/ba0f3/haproxy-waf-spoe`. `changelog`: defaults.

- [ ] **Step 3: Validate the config**
Run: `goreleaser check`
Expected: config OK, no schema errors.

- [ ] **Step 4: Prove the build and Docker context work locally**
Run: `goreleaser release --snapshot --clean --skip=publish`
Expected: a `dist/` tree containing the `wafguard` binary, archives, `checksums.txt`, and a Docker build that completes without "COPY failed: file not found in build context" (publish steps skipped).

- [ ] **Step 5: Confirm the existing Dockerfile is unchanged**
Run: `git diff -- deploy/Dockerfile`
Expected: empty output.

### Task 2: GitHub Actions release workflow
**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `.goreleaser.yaml`, `deploy/Dockerfile.goreleaser`, `make test` target from `Makefile`, `go.mod`.
- Produces: published GitHub release and GHCR images on `v*` tag push.

- [ ] **Step 1: Write the workflow**
`name: Release`; `on: push: tags: ["v*"]`; `permissions: contents: write`, `packages: write`. Single `goreleaser` job on `ubuntu-latest` with steps in order: `actions/checkout@v4` with `fetch-depth: 0`; `actions/setup-go@v5` with `go-version-file: go.mod`; `make test`; `docker/login-action@v3` with `registry: ghcr.io`, `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`; `goreleaser/goreleaser-action@v6` with `version: '~> v2'`, `args: release --clean`, and `env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}`.

- [ ] **Step 2: Validate the workflow YAML parses**
Run: `python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/release.yml')); print(sorted(d['jobs']['goreleaser']['steps'][i].get('uses','run') for i in range(len(d['jobs']['goreleaser']['steps']))))"`
Expected: a list containing checkout, setup-go, `make test`, docker login, and goreleaser-action — no YAML parse error.

- [ ] **Step 3: Confirm no ordinary-push trigger exists**
Run: `grep -nE '^on:|tags:|branches:' .github/workflows/release.yml`
Expected: tags `v*` only, no `branches` key.

### Task 3: Final verification
**Files:** none

- [ ] **Step 1: Run the full local quality gate**
Run: `make lint && make vet && make test`
Expected: all three exit 0.

- [ ] **Step 2: Review the complete change set**
Run: `git status --short && git diff --stat`
Expected: only the three new release files plus the already-approved Go 1.27 / lint-vet changes from earlier tasks; no tracked file unexpectedly modified.

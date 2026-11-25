# wafctl v2 (Cobra) — design

## Goal

Replace the hand-rolled `wafctl` with a Cobra CLI that can manage and inspect
every wafguard setting through the admin HTTP API: generic config get/set/add/del,
mode, whitelist, ban listing/unban, inspect, status and metrics.

## Current state

- `cmd/wafctl` is a small flag parser with status/policy/mode/whitelist/unban/inspect.
- Admin API has PUT/GET policy, GET status, GET/POST/DELETE whitelist, POST unban,
  POST auth-outcomes, GET decisions/{ip}. No ban listing.
- `policy.Config` has 19 fields (int, bool, []string).

## Design

### Dependency

Add `github.com/spf13/cobra`. No other new runtime dependency.

### Command tree

```
wafctl [--endpoint URL] [--token STR] [--app NAME] [--json]
  status
  config list
  config get <key>
  config set <key> <value>          # int / bool / scalar
  config add <key> <value>...       # []string fields
  config del <key> <value>...       # []string fields
  mode get | mode set <observe|enforce>
  whitelist list | add <ip/cidr>... | remove <ip/cidr>...
  ban list
  unban <ip> [reason]
  inspect <ip>
  metrics
```

- Persistent flags replace the old top-level flags; env/`.env` fallbacks stay
  (`WAFGUARD_ENDPOINT`, `WAFGUARD_TOKEN`, `WAFGUARD_APP`).
- Generic config commands read `GET /policy`, modify one field by JSON tag,
  then CAS-write via `PUT /policy` with `expected_revision`. Key names are the
  JSON tags from `policy.Config`; a registry rejects unknown keys.
- `whitelist` delegates to `config add/del whitelist_ips`.
- `ban list` needs a new endpoint `GET /v1/apps/{app}/bans`, backed by
  `Store.BannedIPs()` scanning `wg:ban:<app>:*` with `TTL` for expiry.
- `metrics` reads `/metrics` from the metrics endpoint (`--metrics-endpoint`)
  and prints `wafguard_*` lines.

### Safety

- `config set/del` writes are CAS; a stale revision is reported clearly.
- Validation stays server-side in `policy.Validate` via `SetPolicy`.
- No direct Redis access from the CLI.

## Files

- `go.mod` / `go.sum` (cobra), `cmd/wafctl/*.go` (rewrite)
- `internal/state/redis.go` (`BannedIPs`), `internal/admin/handler.go` (GET bans)
- tests for config commands, ban list, CLI tree
- README

## Verification

- `make lint`, `make vet`, `make test`, `goreleaser check`, `make build`.

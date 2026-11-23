# Redis and Sentinel authentication — design

## Goal

Allow wafguard to authenticate to a password/ACL-protected Redis, and to a
password/ACL-protected Sentinel, using configuration already mounted as JSON.

## Current state

- `redisOptions` has only `addr` and an optional `sentinel{master_name, addrs}`.
- `newRedisClient()` builds `redis.Options` and `redis.FailoverOptions` with the
  existing timeouts but no credentials.
- go-redis v9.17.2 already supports `Username`/`Password` (master) and
  `SentinelUsername`/`SentinelPassword` (sentinel); no new dependency needed.

## Approach

Add nested credential fields and pass them to the existing go-redis option
structs. Split option construction into small helpers so the sentinel fields
can be asserted in tests (`Client.Options()` does not expose them).

### Config schema

```
"redis": {
  "addr": "redis:6379",
  "db": 0,
  "username": "wg",
  "password": "...",
  "sentinel": {
    "master_name": "mymaster",
    "addrs": ["sentinel:26379"],
    "username": "sentinel-user",
    "password": "..."
  }
}
```

- `redis.db` → `DB` on both option structs; omitted means database `0`.
- `redis.username` / `redis.password` → master `Username` / `Password`, used for
  both standalone and failover clients.
- `redis.sentinel.username` / `password` → `SentinelUsername` /
  `SentinelPassword` on `FailoverOptions` only.
- All fields optional; empty values keep today's unauthenticated behaviour.

## Decisions

- Credentials are plaintext in the mounted JSON (user choice). No `${ENV}`
  expansion — protect the config file outside this repo.
- No changes to `state.New`, Lua scripts, timeouts, or validation rules.
- No new dependency.

## Files

- `cmd/wafguard/main.go` — fields, helpers, client wiring.
- `cmd/wafguard/main_test.go` — standalone and sentinel auth option tests.
- `deploy/wafguard.sentinel.json` — placeholder auth fields.
- `README.md` — document the four new fields in the config table.

## Verification

- `goreleaser check`, `make lint`, `make vet`, `make test`.
- New tests assert credentials land on the right option struct for both modes.

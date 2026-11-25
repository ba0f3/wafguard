# Whitelist and management CLI — design

## Goal

Let operators exempt trusted IPs/CIDRs from all behavioral policy (no ban, no
counter) and manage mode/policy/unban/whitelist from one Go CLI instead of curl
plus redis-cli.

## Whitelist

- New `policy.Config.WhitelistIPs []string` (`whitelist_ips`), values are IP or
  CIDR strings. Empty = disabled. Stored with the rest of the policy config in
  Redis (`wg:policy:<app>:config`), so it is central and versioned.
- `policy.IPInList(ip, entries)` parses each entry as `netip.ParsePrefix` or
  `netip.ParseAddr` and returns true on match.
- `state.Check()` still runs `check.lua` (so a fresh admission token exists for
  the later `waf-verdict`), then loads the effective app config with the
  revision returned by Lua. A whitelisted IP gets `Action = allow` and
  `Whitelisted = true`, overriding any ban from Lua.
- `state.Observe()` returns early for whitelisted IPs — no counter, no zset, no
  ban. Coraza still runs independently at HAProxy, so WAF inspection is intact.

## Admin API additions

- `GET  /v1/apps/{app}/policy` → `{revision, mode, config}` (read current state)
- `GET  /v1/apps/{app}/status` → `{revision, mode, whitelist_count}`
- `GET  /v1/apps/{app}/whitelist` → `{"ips":[...]}`
- `POST /v1/apps/{app}/whitelist` body `{"ips":[...]}` → add, CAS via SetPolicy
- `DELETE /v1/apps/{app}/whitelist` body `{"ips":[...]}` → remove, CAS via SetPolicy

Whitelist mutations reuse `SetPolicy` so revision, mode, fence and config stay
atomic and consistent. Write role required.

## CLI (`cmd/wafctl`)

Go binary using only stdlib `net/http`, talking to the admin HTTP API:

```
wafctl [-endpoint URL] [-token STR] [-app NAME] <command> [args]

  status
  policy get
  mode get | mode set <observe|enforce>
  whitelist list | whitelist add <ip|cidr>... | whitelist remove <ip|cidr>...
  unban <ip> [reason]
  inspect <ip>
```

Token from `-token`, `WAFGUARD_TOKEN` env, or a `.env` file. Output is plain
human-readable text; JSON available with `-json`.

## Decisions

- No new Redis keys for whitelist; no new HAProxy config.
- CLI uses admin API only (user choice); no direct Redis access.
- Whitelist is per app, like all other policy config.

## Verification

- `make lint`, `make vet`, `make test`, `goreleaser check`.
- Tests for IP/CIDR matching, whitelisted Check/Observe, whitelist admin endpoints,
  and CLI subcommands against an httptest server.

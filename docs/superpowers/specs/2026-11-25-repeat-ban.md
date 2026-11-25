# Repeat-offender ban escalation — design

## Goal

Keep a bounded ban history per IP. A second ban inside a configurable window
escalates the ban TTL from the normal 15 minutes to 30 days, and the ban reason
becomes visible through `wafctl ban list`.

## Current state

- Ban key `wg:ban:<app>:<ip>` holds only an expiry timestamp (`tonumber`).
- `observe.lua` sets it with `waf_deny_ban_sec` (default 900s); `check.lua`
  deletes it when expired. No history, no reason stored.
- `BannedIPs()` reports only IP + expiry.

## Design

### Config (per app, in policy.Config)

- `repeat_ban_threshold` (default 2)
- `repeat_ban_window_sec` (default 604800 = 7 days)
- `repeat_ban_ttl_sec` (default 2592000 = 30 days)

### Redis

- New zset `wg:ban-history:<app>:<ip>` (`KEYS[13]`): member = event id, score =
  ban time, trimmed to window and PEXPIREd at window. Count = ZCARD.
- New hash `wg:ban-info:<app>:<ip>` (`KEYS[14]`): `reason`, `count`, `at_ms`,
  PEXPIREd with the chosen ban TTL.
- On ban: `ttl = (history count >= threshold) ? repeat_ban_ttl_sec : waf_deny_ban_sec`.
  The ban key stays numeric, so `check.lua` needs no change.
- Unban keeps history intact, so a later offense still escalates.

### Logging and CLI

`ban issued ... reason=<reason> count=<n>/<threshold> history=<h> ttl_sec=<t> repeat=<bool>`.

`BanInfo` gains `Reason` and `BanCount`; `GET /bans` and `wafctl ban list`
expose them.

## Decisions

- Escalation is 30 days, not infinite (user choice; still requires explicit unban
  to clear early).
- First ban is unchanged at 900s.
- No new admin endpoints; existing `/bans` is extended.

## Files

- `internal/policy/policy.go`, `internal/state/redis.go`,
  `internal/state/scripts/observe.lua`, `internal/admin/handler.go`,
  `cmd/wafctl/main.go`, tests, README.

## Verification

- `make lint`, `make vet`, `make test`, `goreleaser check`.
- Test that the 2nd ban inside the window gets the 30-day TTL and that
  `ban list` includes the reason.

# Backend status signals and counter logging — design

## Goal

Make every policy counter increment observable, and let backend response codes
contribute to brute-force / scanner detection with thresholds deliberately
higher than the Coraza deny threshold. Backend 5xx is logged but never bans.

## Current state

- `observe.lua` maintains two counters: a WAF-deny zset (`KEYS[2]`) and an
  auth-failure brute zset (`KEYS[8]`). It returns a single outcome word; the Go
  side only logs bans / would-be bans, so counter increments are invisible.
- `origin_status` (and `final_client_status`) arrive in `ARGV[16]`/`ARGV[17]`
  and are only written to the per-IP meta hash.
- `scanner_responses` / `scanner_window_sec` and `outage_*` config fields exist
  but are unused in any decision path.

## Design

### Lua return shape

`observe.lua` returns:

```
{status, banReason, {reason, count, threshold}, ...}
```

- `status`: `ok`, `banned`, `shadow`, `deduped`, `fenced:*`, `suppressed`.
- `banReason`: the reason that crossed the threshold (`waf_deny`,
  `brute_auth`, `brute_401`, `scanner_404`), empty otherwise.
- One nested array per signal observed in this event. Signals are collected
  even when a ban happens, so all increments remain visible.

Early returns keep the same first element and use an empty `banReason`.

### New signals

| Status | Counter | Threshold source | Bans? |
|---|---|---|---|
| `401` | brute zset `KEYS[8]`, member `rid` (same member as auth-failure counting, so a request with both is counted once) | `brute_failures` / `brute_window_sec` (default 10 / 60s) | yes, enforce |
| `404` | new scanner zset `KEYS[12]`, member `rid` | `scanner_responses` / `scanner_window_sec` (default 30 / 60s) | yes, enforce |
| `500`–`504` | none | — | **no**, log only with `status=<code>` |

All thresholds are strictly higher than the default WAF deny threshold
(`3 / 30s`), matching the requirement to avoid banning on Coraza-level noise.

### Go side

- `Observe()` passes `s.prefix("scanner", app, ip)` as `KEYS[12]` and
  `cfg.ScannerWindowSec`, `cfg.ScannerResponses` as `ARGV[19]`/`ARGV[20]`.
- Parse the new return shape and log each signal:

```
counter +1 app=... request_id=... client_ip=... reason=waf_deny count=2 threshold=3
counter +1 app=... request_id=... client_ip=... reason=brute_401 count=6 threshold=10
counter +1 app=... request_id=... client_ip=... reason=scanner_404 count=18 threshold=30
backend_5xx app=... request_id=... client_ip=... status=500
ban issued app=... request_id=... client_ip=... reason=brute_401 count=10 threshold=10
ban would fire ... reason=scanner_404 count=30 threshold=30
```

## Decisions

- No new config fields: reuse `brute_*`, `scanner_*` and `outage_*`-adjacent
  defaults already present in `policy.Config`.
- `final_client_status` is not used as a signal (HAProxy configs do not send it).
- 5xx never bans: it is a backend fault, not client behaviour.
- No changes to `check.lua`, admission tokens, or the admin API.

## Files

- `internal/state/scripts/observe.lua` — signal collection, new counters, new
  return shape.
- `internal/state/redis.go` — new key, ARGV, return parsing, log lines.
- Tests in `internal/state/` for counter logs, 5xx log, and ban reason.

## Verification

- `make lint`, `make vet`, `make test`.
- Existing ban/shadow tests must still pass with the new return shape.

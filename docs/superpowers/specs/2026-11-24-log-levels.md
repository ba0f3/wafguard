# Log levels — design

## Goal

Keep normal container logs quiet: info shows only operational events, while
per-request detail is available on demand by setting `log_level: "debug"`.

## Current state

All sites use `log.Printf` unconditionally: startup/listener lines in `main.go`,
one `spoe` line per SPOE message in `internal/spoa/handler.go`, and counter /
ban lines in `internal/state/redis.go`. Tests capture output with
`log.SetOutput`.

## Level assignment

| Line | Level |
|---|---|
| `wafguard starting`, `redis ok` / `redis ping failed`, `... listening`, `admin listen <err>` | info |
| `counter +1 ... reason=<reason> count=<n> threshold=<t>` ("tracked") | info |
| `ban issued ... reason=<reason> count=<n> threshold=<t>` | info |
| `ban would fire ...` | info |
| `backend_5xx ... status=<code>` | info |
| `spoe ... result != ok` (degraded, invalid, overload, observe_error, …) | info |
| `spoe ... result=ok` (ban check allow, waf-verdict allow, etc.) | debug |

Info is the default. `log_level` accepts `info` (default) and `debug`; unknown
values fall back to info.

## Implementation

- New `internal/logging` package: atomic level + `Infof` / `Debugf` wrappers
  around stdlib `log`, keeping existing output format and test capture.
- `fileConfig.LogLevel string json:"log_level,omitempty"`; `run()` sets the
  level from it at startup.
- Replace the per-request `spoe` line: always emit `Debugf`; additionally emit
  `Infof` when `result != "ok"` so failures stay visible at info.
- Add `count`/`threshold` of the crossing signal to `ban issued`, so info
  reads `banned (x times)` as requested.
- No new dependency, no change to metrics or policy logic.

## Files

- `internal/logging/logging.go` (+ test)
- `cmd/wafguard/main.go`, `internal/spoa/handler.go`, `internal/state/redis.go`
- tests that assert the `spoe` debug line
- `README.md` config table

## Verification

- `make lint`, `make vet`, `make test`.
- Test that `Debugf` is silent at info and visible at debug.
- Test that a non-ok SPOE result is logged at info.

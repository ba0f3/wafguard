# P0 task reconciliation (plan 2026-11-23)

**Branch:** `ba0f3/waf-spoe-implementation`

## Closed this session (orchestration msg)

| Item | Evidence |
|------|----------|
| Configured enforcement guard | `behavior_mode` → `snap_source`; policy `enforced` only |
| redirect / transport error | `TestStockLifecycle`, `TestStockCorazaTransportError` |
| observe-response | `TestObserveResponsePhase`, scanner probe IT |
| Auth join (both orders, dup, real Redis) | `record_auth.lua`, `TestAuthReceipt*`, `TestAuthJoinRealRedis` |
| Native stock JSON enrich | `TestEnrichmentNativeStockJSON`, zerolog parser |
| Failover → clean base stack | `Makefile` `it-failover` down + recreate redis |
| Synthetic vs native enrich labels | `it-enrich-synthetic` vs `it-enrich-native` |

## Still open

- Full stock assertion table (drop, body, affinity, coraza-res response deny)
- Brute-force ban from auth outcomes (join exists; no brute zset yet)
- HTTP admin `auth-outcomes` integration (no auth listener in default compose)

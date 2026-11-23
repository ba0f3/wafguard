# P0 task reconciliation (msg three remaining gates)

**Branch:** `ba0f3/waf-spoe-implementation`

| Item | Status | Evidence |
|------|--------|----------|
| Brute 9 vs 10 + dup/out-of-order Redis | **PASS** | `make it-brute`, `TestBruteForceNineVersusTenRealRedis` |
| coraza-res sync 3.2 / 3.4 | **PASS** | `make it-coraza-res`, `TestStockCorazaResponseSyncDeny` |
| Stock drop | **PASS** | `TestStockDropRequest` in `it-stock` |
| Failover → stock → rollout | **PASS** | `make it-gate-sequence` (after `res_insp` guard) |

## Unresolved (honest)

- Plan table body/affinity, recorder disconnect cases
- Brute throttle vs ban policy (lab uses shared ban TTL)
- HTTP admin auth-outcomes IT (no auth listener in default compose)

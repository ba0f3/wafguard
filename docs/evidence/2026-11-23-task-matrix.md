# P0 task reconciliation (orchestration)

**Branch:** `ba0f3/waf-spoe-implementation`

| Item | Status | Evidence |
|------|--------|----------|
| Brute 9 vs 10 + dup/out-of-order Redis | **PASS** | `make it-brute` |
| coraza-res sync 3.2 / 3.4 | **PASS** | `make it-coraza-res` |
| Stock drop | **PASS** | `it-stock` |
| Failover → stock → rollout | **PASS** | `make it-gate-sequence` |
| Body/Expect/timeout/affinity matrix | **PASS** | `make it-recorder-body`, `docs/evidence/2026-11-23-body-affinity.md` |
| Phase-4 response body benign + negative | **PASS** | `TestStockResponseBodyPhase4*` (evil via phase-3 header control) |

## Unresolved (honest)

- Recorder SPOA disconnect ITs (precheck / verdict)
- Phase-4-only body deny without header on coraza-spoa 0.9.1
- HTTP admin auth-outcomes IT (no auth listener in default compose)

# P0 task reconciliation (orchestration)

**Branch:** `ba0f3/waf-spoe-implementation`

| Item | Status | Evidence |
|------|--------|----------|
| Brute 9 vs 10 + dup/out-of-order Redis | **PASS** | `make it-brute` |
| coraza-res sync 3.2 / 3.4 | **PASS** | `make it-coraza-res` |
| Stock drop | **PASS** | `it-stock` |
| Failover → stock → rollout | **PASS** | `make it-gate-sequence` |
| Body/Expect/timeout/affinity matrix | **PASS** | `make it-recorder-body` |
| Recorder disconnect | **PASS** | `TestStockRecorderDisconnect*` |
| Dual Coraza (failover affinity) | **PASS** | `TestStockDualCorazaRoundRobinCorrelation` (c1+c2 UP, c2 backup) |
| Phase-4 isolation 3.2 / 3.4 | **PASS (observed 200)** | `make it-phase4-only-all` |
| Phase-4 response header enforce | **PASS** | `TestStockResponseBodyPhase4*` (evil via phase-3) |
| Operator deploy validate | **PASS** | `docs/examples/deploy-operator-validate.sh` |
| HTTP auth-outcomes | **PASS** | `make it-auth-http` |
| Runnable shadow rollback | **PASS** | `docs/examples/shadow-rollback.sh` |

## Unresolved (honest)

- Phase-4-only body deny without header on coraza-spoa 0.9.1
- Active/active dual Coraza response inspect (backup-server lab shortcut)

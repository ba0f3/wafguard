# Progress: haproxy-waf-spoe implementation

Branch: `ba0f3/waf-spoe-implementation`

| Task | Status | Evidence |
|------|--------|----------|
| 1 HAProxy/stock | **partial** | `TestStockLifecycle` PASS (403, zero origin hits); stream/body skipped |
| 2 Event/SPOP | done | unit tests |
| 3 Redis | done | miniredis + `TestSharedBanRedis` |
| 4 Policy | done | unit tests |
| 5 Admin | partial | `TestAdminRoles`; fence/dry-run gaps |
| 6 wafguard | done | binary + race |
| 7 Rollout | partial | stubs; compose single-node |
| 8 Enrichment | partial | `internal/enrich` parser tests only |

Evidence: `docs/evidence/2026-11-23-compose.md`

**Fix:** Coraza compose config mount → `/config.yaml` (403 terminal deny).

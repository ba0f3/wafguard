# P0 task reconciliation (plan 2026-11-23)

**Branch:** `ba0f3/waf-spoe-implementation`  
**Coraza:** `0.9.1` / `c9b34f409e04cfb60219602bd1ad711afd15eaa3`  
**HAProxy images:** `3.2.0`, `3.4.0` (`integration/images.env`)

## Gate run (2026-11-23, lab)

| Command | Result |
|---------|--------|
| `go test ./... -count=1` | **PASS** |
| `go test -race ./... -count=1` | **PASS** |
| `make it-stock HAPROXY_SERIES=3.2` | **PASS** (incl. **TestStockStreamIsolation** h2c on `:18443`) |
| `make it-redis` | **PASS** |
| `WAF_ROLLOUT=1 make it-rollout` | **PASS** |
| `make it-failover` | **PASS** **TestSentinelFailoverWafDecision** (stop `redis`, replica promotion, HAProxy allow/deny) |
| `make it-sentinel` | **PASS** discovery |
| `make it-enrichment` / `it-enrichment-integration` | **PASS** |

## Tasks 1–8 vs assertions

| Task | Status | Evidence |
|------|--------|----------|
| **1** Stock | **partial→stronger** | `TestStockLifecycle`, `TestStockStreamIsolation` (HTTP/2), recorder tests |
| **2** Event / SPOP | **partial** | `TestWireV1Decode`, `TestMissingAdmission`, `TestSlowResponseAdmission` |
| **3** Redis | **partial→stronger** | shared ban, `TestLostCommitObserveFenced`, failover via wafguard + IT |
| **4** Policy | **partial→stronger** | `TestClassify*`, `TestClassifyProbeAnd4xx` |
| **5** Admin | **partial→stronger** | roles, `PUT …/policy?dry_run=1`, **409** stale revision, fence/unban tests |
| **6** Runtime | **partial** | `TestSentinelConfigValidation`, `newRedisClient` FailoverClient |
| **7** Rollout / Sentinel | **partial→stronger** | shared ban rollout IT; **wafguard Sentinel client + primary stop gate** |
| **8** Enrichment | **partial** | join + `TestEnrichmentStock` |

## Still open vs plan

- Full `TestStockLifecycle` table (every plan row)
- Live Coraza log socket in compose
- Full auth brute-force / scanner contrib integration (unit evidence only)
- Concurrent HTTP unban race at scale

## Artifacts

- `cmd/wafguard/main.go` — direct `redis.addr` or `redis.sentinel`
- `deploy/wafguard.sentinel.json`, `integration/compose.failover.yaml`
- `integration/sentinel_test.go` — discovery + failover
- `internal/admin/handler.go` — policy dry-run / 409
- `internal/state/redis.go` — `ValidatePolicyUpdate`, `PolicyRevision`

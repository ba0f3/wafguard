# Lifecycle completion (msg_9605e4cbcab9, msg_c891d0860d84, msg_b23688c47a86)

**Commits:** `dad42cc` (auth/deploy split) → `7e51542` (operator overlay) → final follow-up on `ba0f3/waf-spoe-implementation`

## Per-series results (lab)

| Gate | HAProxy 3.2 | HAProxy 3.4 |
|------|-------------|-------------|
| `make it-phase4-only` | PASS (marker **200**, documented limitation) | PASS (same observation) |
| `make it-recorder-body` | PASS | PASS (`it-recorder-body-all`) |
| Response header enforce | PASS (`make it-coraza-res`) | PASS |

Phase-4-only isolation stays **200** on both series — separate from **403** response-header enforcement (`TestStockCorazaResponseSyncDeny` / phase-3 `X-Evil-Marker`).

## Deploy / rollback artifacts

| Role | Path |
|------|------|
| Integration lab script | `docs/examples/shadow-rollback.sh` |
| Operator compose overlay | `deploy/compose.operator-example.yaml` + `deploy/operator/*` |
| Operator validate (observe→enforce→rollback via admin write API) | `make validate-operator-deploy` |
| Runbook | `docs/runbooks/rollout.md` (exact overlay invocation, HAProxy origin backend, PUT policy mode) |
| Bounded readiness | `scripts/wait-readyz.sh`, `scripts/wait-rollout-ready.sh` |
| Auth HTTP listener | `admin_http_auth`, `admin_http_auth_token`, `admin_http_write` on loopback |
| Coraza (replaceable) | `deploy/operator/coraza-spoa.yaml` |

**Validate result:** `all_ok` — observe `/ok` 200 with no ban, auth 204/403 (token), enforce ban + precheck 403, unban + rollback 200, `wg:mode` observe/enforce asserted.

**Root-cause fix:** `SetPolicy` set a fence generation that new admissions could never carry (check.lua returned meta generation), so waf-verdict events after any mode PUT were fenced and never banned. `check.lua` now returns the fence generation and `TestNewAdmissionAfterPolicyChangeCounts` regressions it.

## Gate sequence (clean isolated Compose project `wafgate-seq`)

| Step | Result |
|------|--------|
| `make it-gate-sequence` | PASS (failover → stock 3.2/3.4 → rollout → unban race) |
| `make validate-operator-deploy` | PASS (isolated `wafgate-operator-val`) |
| `make it-auth-http` | PASS |
| `make it-coraza-res` | PASS (3.2 + 3.4) |
| `make it-recorder-body-all` | PASS (3.2 + 3.4) |
| `make it-phase4-only-all` | PASS (3.2 + 3.4; body 200 documented) |
| `make it-brute` | PASS |
| `go test -race ./...` | PASS |

## HTTP auth-outcomes IT

`make it-auth-http` → `TestStockHTTPAuthOutcomes` (POST **204**, Redis `wg:auth:sample_app:*` outcome **failure**, source **login-app**).

## Dual Coraza contract (honest)

- **Tested:** two containers UP; `c1` primary with `c2` **backup**; hash+stick on `txn.wafguard.request_id`; response deny **403** with cache on primary.
- **Not tested:** active/active response inspect on both instances without backup shortcut.

## Unresolved

- Phase-4-only body deny on coraza-spoa 0.9.1 (both series)
- Active/active dual Coraza response cache

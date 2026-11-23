# Lifecycle completion (msg_9605e4cbcab9, msg_c891d0860d84)

**Commits:** `dad42cc` (auth/deploy split) → operator overlay follow-up on branch `ba0f3/waf-spoe-implementation`

## Per-series results (lab)

| Gate | HAProxy 3.2 | HAProxy 3.4 |
|------|-------------|-------------|
| `make it-phase4-only` | PASS (marker **200**, documented limitation) | PASS (same observation) |
| `make it-recorder-body` | (see session log) | `make it-recorder-body-all` |
| Response header enforce | `make it-coraza-res` (3.2+3.4 internal) | included |

Phase-4-only isolation remains **200** on both series — separate from **403** response-header enforcement (`TestStockCorazaResponseSyncDeny` / phase-3 `X-Evil-Marker`).

## Deploy / rollback artifacts

| Role | Path |
|------|------|
| Integration lab script | `docs/examples/shadow-rollback.sh` |
| Operator compose overlay | `deploy/compose.operator-example.yaml` + `deploy/operator/*` (env paths) |
| Operator validate (observe→enforce→rollback) | `make validate-operator-deploy` / `docs/examples/deploy-operator-validate.sh` |
| Runbook (lab vs operator sections) | `docs/runbooks/rollout.md` |
| Observe default config | `deploy/wafguard.example.json` |
| Auth HTTP listener | `admin_http_auth` **:19201**, `admin_http_auth_source` |
| Coraza (replaceable) | `integration/fixtures/coraza-spoa.yaml` |
| HAProxy stock | `deploy/haproxy/haproxy.cfg` |

## HTTP auth-outcomes IT

`make it-auth-http` → `TestStockHTTPAuthOutcomes` (POST **204**, Redis `wg:auth:sample_app:*` outcome **failure**, source **login-app**).

## Dual Coraza contract (honest)

- **Tested:** two containers **UP**; SPOA `c1` primary with `c2` **backup**; hash+stick on `txn.wafguard.request_id`; response deny **403** with cache on primary.
- **Not tested:** active/active response inspect on both instances without backup shortcut (`docs/evidence/2026-11-23-body-affinity.md`).

## Unresolved

- Phase-4-only body deny on coraza-spoa 0.9.1
- Active/active dual Coraza response cache

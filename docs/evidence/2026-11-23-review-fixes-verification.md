# wafguard review fixes verification

Base: `905616f`. Fix commit: `a41fbfd` (branch `ba0f3/wafguard-review-fixes`).
No push, merge or live deployment. All traffic was benign synthetic markers on
isolated loopback/Compose projects; other running Compose projects
(`ccload`, `plane-dashboard-qa`, `wafgate-final`) were left untouched.

## Finding → files/tests

| # | Fix | Regression evidence |
|---|-----|---------------------|
| 1 | `deploy/compose.operator.yaml` (Redis + 2 wafguard + 2 Coraza, internal `spoe` net, no published SPOE/Redis ports), `deploy/compose.operator-example.yaml`, `docs/examples/deploy-operator-validate.sh`, `docs/runbooks/rollout.md`, `Makefile` | operator validate topology assertions; `all_ok` on HAProxy 3.2 and 3.4 |
| 2 | `cmd/wafguard/main.go` (token required at startup for both HTTP listeners, constant-time compare, 0600 Unix sockets), `internal/admin/handler.go`, `deploy/*.json` | `TestAdminHTTPWriteRequiresTokenAtStartup`, `TestWithAuthToken`, operator script unauthenticated PUT → 403 / authenticated → 200 |
| 3 | `internal/state/redis.go` (all six scripts use `*redis.Script.Run`) | `TestScriptCacheFlushRecoveryAllFour` after `SCRIPT FLUSH SYNC`; Sentinel failover test |
| 4 | `internal/state/scripts/observe.lua` (`PX`), `internal/state/redis.go` | `TestDedupePTTLMilliseconds` asserts real PTTL and expiry |
| 5 | `internal/event/event.go`, `internal/spoa/decode.go` | `TestCheckBanIndependentOfPath` (long raw path + query, older SPOP-style caller) |
| 6 | `deploy/operator/haproxy/haproxy.cfg`, `deploy/operator/haproxy/req-inspect-paths.lst` | operator script bounded slow benign body POST → 200 on 3.2 and 3.4 |
| 7 | `deploy/operator/haproxy/haproxy.cfg` (reset Coraza vars, fail closed on error/missing verdict) | operator script healthy protected response → 200; Coraza stopped → 500 (`waf-block: response-error`) on 3.2/3.4 |
| 8 | `cmd/wafguard/main.go` (dial/read/write/pool/retry bounds + `ContextTimeoutEnabled`), `internal/state/redis.go` | `TestRedisStalledEndpointIsBounded`; `TestSentinelFailoverWafDecision` PASS |
| 9 | `check.lua`, `observe.lua`, `record_auth.lua` (PEXPIRE on meta/contrib/brute/admission) | `TestIdleKeysBoundedAndStaleAdmissionFenced` |
| 10 | `internal/state/redis.go` (`policy.lua` stores config in Redis; revision-keyed replica cache), `internal/state/scripts/policy.lua` | `TestPolicyConvergenceAndAtomicCAS` (replica B enforces A's config) |
| 11 | `internal/state/scripts/policy.lua` (CAS) | same test: 8 concurrent same-revision writers → 1 success / 7 conflicts; stale admission fenced |
| 12 | `internal/state/scripts/unban.lua`, `internal/state/redis.go` | `TestUnbanIdempotentAndNewerBanProtected`; operator idempotent unban |
| 13 | `internal/spoa/decode.go` (`kvValueString` typed ints/bools), `internal/spoa/handler.go` (no synthesized admission), all `wafguard.cfg` (policy metadata on observe-response) | `TestTypedSPOEFields`, `TestDelayedObservationRequiresRealAdmission`; full HAProxy integration on 3.2/3.4 |
| 14 | `deploy/operator/haproxy/haproxy.cfg` + `observe-response-paths.lst`, `internal/state/redis.go`/`observe.lua` (status consumer, no WAF re-count) | `TestResponseObservationNoDoubleCount`; operator validate with real opt-in config |
| 15 | `internal/policy/policy.go` (`WithDefaults`, strict `Validate`) | `TestWithDefaultsPartialOperatorConfig`, `TestPartialOperatorPolicyNoFirstFailureBan` |
| 16 | `record_auth.lua`, `observe.lua`, `check.lua`, `internal/state/redis.go`, `internal/admin/handler.go`, HAProxy `X-Wafguard-Request-Id` | `TestAuthCorrelationAdmissionBound`, `TestAdminRoles`, `TestStockHTTPAuthOutcomes`, operator auth ingress checks |
| 17 | `internal/enrich/tail.go`, `internal/enrich/tail_test.go` | `TestTailCompleteLinesOnly`, `TestTailRetryRetainsOffset`, `TestTailRotationAndTruncation`, `TestTailSkipsOversizedLine` |

## Commands and outcomes (all PASS unless noted)

```sh
go build ./...
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
REDIS_ADDR=127.0.0.1:36379 go test -tags=integration ./internal/state -count=1
go test ./internal/spoa -run '^$' -fuzz '^FuzzDecodeSPOE$' -fuzztime=5s -parallel=2
go test ./internal/spoa -run '^$' -fuzz '^FuzzSPOEOperationLabel$' -fuzztime=5s -parallel=2
go test ./internal/admin -run '^$' -fuzz '^FuzzAdminPolicyRequest$' -fuzztime=5s -parallel=2
go test ./internal/enrich -run '^$' -fuzz '^FuzzParseCorazaLog$' -fuzztime=5s -parallel=2
docker compose -f deploy/compose.operator.yaml config
OPERATOR_HAPROXY_IMAGE=haproxy:3.2.0 bash docs/examples/deploy-operator-validate.sh   # all_ok
OPERATOR_HAPROXY_IMAGE=haproxy:3.4.0 bash docs/examples/deploy-operator-validate.sh   # all_ok
```

Lab integration on isolated host ports (`integration/compose.ci-ports*.yaml`,
project `wafguard-review-ci`): HAProxy 3.2 and 3.4 `go test -tags=integration
./integration -count=1` with `WAF_INTEGRATION=1 WAF_AUTH_HTTP=1
WAF_OBSERVE_MODE=1` PASS; response-inspect suite (`WAF_CORAZA_RES=1`) PASS on
both; two-replica rollout (`TestRollout*`, `TestHTTPUnban*`) PASS; Sentinel
(`TestSentinelMasterDiscoverable`, `TestSentinelFailoverWafDecision`) PASS.
Skips were only tests requiring overlays not active in a given run (e.g.
phase4-only, recorder-body, detect-only) — no mandatory check was skipped.

## Remaining gaps

- Missing-transaction fail-closed is enforced by the HAProxy condition
  `!{ var(txn.coraza.status) -m found }`; only the Coraza transport-error path
  was exercised live (stopping both Coraza containers). Simulating a live
  Coraza process that returns no transaction requires an upstream mock.
- `!reset`/`!override` port overrides in `integration/compose.ci-ports*.yaml`
  are verification-only artifacts for shared-host port isolation; they do not
  change the shipped lab defaults.

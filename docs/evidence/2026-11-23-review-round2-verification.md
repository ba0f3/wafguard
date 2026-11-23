# Coordinator round-2 review fixes verification

Base: `7ab84b9`. Worktree branch: `ba0f3/wafguard-review-fixes`.
Benign synthetic markers only; no push, merge or live deployment. Other
Compose projects (`ccload`, `plane-dashboard-qa`, `wafgate-final`) untouched.
Coordinator project `wafguard-coordinator-verify` ports (38080/39090/39200/
39201) were avoided: lab verification used `wafguard-review2-ci` on 48080/
49090/49200/49201; operator validation used `wafgate-operator-val` on 28080/
29090/29200/29201.

## Gap → fix → regression

| Gap | Fix | Evidence |
|-----|-----|----------|
| 1 Network isolation | `deploy/compose.operator.yaml` splits `origin`, internal `spoe`, internal `redis_net`, `admin`; static IPs and listener binds in `deploy/operator/wafguard-isolated-*.json`; HAProxy backends use SPOE addresses | validate script asserts rendered published ports, `docker inspect` network membership per container, `nc` reachability from origin (negative) and wafguard (Redis/admin positive), config bind addresses |
| 2 Delayed request body rule | `deploy/operator/coraza-spoa.yaml` phase-2 `REQUEST_BODY` marker rule; `integration/testorigin/main.go` `/body-inspect` fixture; fixture-only `req-inspect-paths.lst` entry | delayed marker POST → 403, delayed benign POST → 200 on 3.2 and 3.4; no shared /tmp path (unique `mktemp -d`, trap cleanup) |
| 3 Missing transaction | `deploy/operator/haproxy/haproxy.cfg` resets verdicts, relies on upstream `txn.coraza.error >= 1000` and no longer uses `-m found` on status; c2 Coraza is a hot standby for phase-4 affinity; isolated overlay replaces the request id before `coraza-response-sync` | clean allow 200 with body, overlay 500 + `waf-block: response-error` with no upstream body, restored 200 — on both releases. Upstream v0.9.1 `internal/agent.go` sets `error = 1000 + Reason` for uncorrelated responses and sets no error var on success ACK. |
| 4 Meta TTL / opt-in | `observe.lua` applies `PEXPIRE` after status `HSET`; shipped observation/request-wait lists are empty, fixtures opt in via temp dir | `TestResponseMetaPTTLRealRedis` (real Redis PTTL for a fresh IP before and after a policy update); validate script observes `/status-observe` and asserts `origin_status`/`response_seen` |
| 5 Unban | `unban.lua` clears ban, contrib **and** brute atomically; requires non-empty op id; returns stored expiry; changed payload conflicts; suppression checked in `observe.lua` and `record_auth.lua` | `TestUnbanIdempotentAndNewerBanProtected` (full struct equality), `TestUnbanClearsBruteAndSuppressionStopsReban`, admin 400 without op id |
| 6 Atomic boundary | `observe.lua` and `record_auth.lua` verify token app/ip/rev and current policy revision; `appCfgAt` errors on a failed newer-config load instead of using a stale cache | `TestRecordAuthRejectsTokenAndRevisionMismatch`, `TestObserveRejectsTokenAndRevisionMismatch`, `TestNewerPolicyLoadFailureFailsClosed`, `TestAuthScopeNoFalseBruteCount`, `TestRecordAuthSurfacesLuaOutcome` |
| 7 Observe rollback | `check.lua` reads mode first and never enforces an active ban outside enforce | `TestObserveRollbackDoesNotEnforceActiveBan`; validate script PUTs observe with the ban key intact and asserts 200 |
| Coordinator auth 3.4 | `RecordAuth` parses Lua outcome and errors on `fenced`/`unjoined`/`source_mismatch`; validate script asserts persistence and retries with a fresh admission | 4 consecutive clean operator runs (3.2, 3.4, 3.2, 3.4) all `all_ok` |

## Commands and outcomes (all PASS)

```sh
go build ./...
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
REDIS_ADDR=127.0.0.1:46379 go test -tags=integration ./internal/state -count=1
go test ./internal/spoa -run '^$' -fuzz '^FuzzDecodeSPOE$' -fuzztime=5s -parallel=2
go test ./internal/spoa -run '^$' -fuzz '^FuzzSPOEOperationLabel$' -fuzztime=5s -parallel=2
go test ./internal/admin -run '^$' -fuzz '^FuzzAdminPolicyRequest$' -fuzztime=5s -parallel=2
go test ./internal/enrich -run '^$' -fuzz '^FuzzParseCorazaLog$' -fuzztime=5s -parallel=2
docker compose -f deploy/compose.operator.yaml config
OPERATOR_HAPROXY_IMAGE=haproxy:3.2.0 bash docs/examples/deploy-operator-validate.sh   # all_ok (x2)
OPERATOR_HAPROXY_IMAGE=haproxy:3.4.0 bash docs/examples/deploy-operator-validate.sh   # all_ok (x2)
WAF_INTEGRATION=1 WAF_AUTH_HTTP=1 WAF_OBSERVE_MODE=1 go test -tags=integration ./integration -count=1   # 3.2 and 3.4
WAF_INTEGRATION=1 WAF_SENTINEL=1 WAF_FAILOVER=1 go test -tags=integration ./integration -run '^TestSentinel' -count=1
WAF_INTEGRATION=1 WAF_ROLLOUT=1 WAF_UNBAN_RACE=1 go test -tags=integration ./integration -run 'TestRollout|TestHTTPUnban' -count=1
WAF_INTEGRATION=1 WAF_CORAZA_RES=1 go test -tags=integration ./integration -run '^TestStockCorazaResponse|^TestStockResponseBody' -count=1   # 3.2 and 3.4
```

Only skips were tests whose overlay was not active in a given run (phase4-only,
recorder-body, detect-only). No mandatory check was skipped or failed.

## Remaining gaps

- Coraza's second replica is intentionally a hot standby; active-active
  phase-4 inspection would require external transaction affinity that stock
  coraza-spoa does not provide.
- The missing-transaction test exercises upstream `ReasonNotFound` (error
  1002) via an isolated HAProxy overlay; other error codes share the same
  `error > 0` fail-closed rule but were not individually triggered.

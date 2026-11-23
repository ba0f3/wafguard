# Coordinator round-3 verification

Base: `db8ca45`, worktree `ba0f3/wafguard-review-fixes`. Benign synthetic
fixtures only; no push, merge or live deployment. Other Compose projects were
untouched.

## Reproduced failures (coordinator command)

```
/home/linuxbrew/.linuxbrew/bin/go test -overlay /tmp/wg-root-round2-overlay.json ./internal/state -run '^TestCoordinator' -count=1
```

Before the fix both failed: auth source accepted for a second admitted app;
changed unban reason accepted for an existing operation id. After the fix the
same command passes.

## Fixes

- Auth scope: `state.Config.AuthApplication`, deterministic fail-closed default
  (sample_app, else single app, else lexicographically first), `RecordAuth`
  rejects other apps; `cmd/wafguard/main.go` passes
  `admin_http_auth_application` and binds `admin.Access.Application` to the
  same app, so the HTTP endpoint returns 403 for a cross-app path even when
  both apps have real admissions.
- Unban fingerprint: `unban.lua` stores and compares `reason` alongside app,
  ip and suppression; `state.ErrOperationConflict` is returned on a changed
  payload and mapped to HTTP 409 by the admin handler. Exact retries return
  identical generation and expiry.
- Operator secrets: `deploy/compose.operator.yaml` now *requires*
  `OPERATOR_WAFGUARD_CONFIG` and `OPERATOR_WAFGUARD_CONFIG2`; checked-in
  `wafguard-isolated-*.json` contain no tokens. The validation script injects
  test-only tokens into private temp copies and asserts that `docker compose
  config` fails without the operator-owned configs.
- Lab ports: every host-published port in `integration/compose*.yaml` is bound
  to `127.0.0.1`, including Redis, SPOP, Coraza, Sentinel, recorder and rollout
  overrides.

Durable regressions: `TestAuthSourceBoundToOneAdmittedApp`,
`TestUnbanFingerprintIncludesReason` (internal/state),
`TestAuthHTTPBoundToSingleApp`, `TestUnbanChangedReasonHTTP409` (internal/admin).

## Commands and outcomes (all PASS)

```sh
/home/linuxbrew/.linuxbrew/bin/go test -overlay /tmp/wg-root-round2-overlay.json ./internal/state -run '^TestCoordinator' -count=1
go build ./...
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
REDIS_ADDR=127.0.0.1:46379 go test -tags=integration ./internal/state -count=1
go test ./internal/spoa -run '^$' -fuzz '^FuzzDecodeSPOE$' -fuzztime=5s -parallel=2
go test ./internal/spoa -run '^$' -fuzz '^FuzzSPOEOperationLabel$' -fuzztime=5s -parallel=2
go test ./internal/admin -run '^$' -fuzz '^FuzzAdminPolicyRequest$' -fuzztime=5s -parallel=2
go test ./internal/enrich -run '^$' -fuzz '^FuzzParseCorazaLog$' -fuzztime=5s -parallel=2
OPERATOR_HAPROXY_IMAGE=haproxy:3.2.0 bash docs/examples/deploy-operator-validate.sh  # all_ok
OPERATOR_HAPROXY_IMAGE=haproxy:3.4.0 bash docs/examples/deploy-operator-validate.sh  # all_ok
WAF_INTEGRATION=1 WAF_AUTH_HTTP=1 WAF_OBSERVE_MODE=1 go test -tags=integration ./integration -count=1  # 3.2 and 3.4 on 127.0.0.1:48080
WAF_INTEGRATION=1 WAF_SENTINEL=1 WAF_FAILOVER=1 go test -tags=integration ./integration -run '^TestSentinel' -count=1
WAF_INTEGRATION=1 WAF_ROLLOUT=1 WAF_UNBAN_RACE=1 go test -tags=integration ./integration -run 'TestRollout|TestHTTPUnban' -count=1
```

Isolated lab project `wafguard-review2-ci` used 48080/49090/49200/49201, not
the coordinator ports. Skips were only overlay-gated tests not activated in a
given run; no mandatory check was skipped or failed.

## Remaining gaps

- `admin_http_auth_application` is optional for single-app deployments and
  defaults deterministically; multi-app operators should set it explicitly to
  avoid relying on the `sample_app`/lexicographic default.

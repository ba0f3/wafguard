# Centralised path inspection lists — design

## Goal

Remove the three per-HAProxy `.lst` files. Path lists live in the app config
in Redis; wafguard decides which inspection flags apply and returns them in the
existing `check-ban` SPOE ACK. HAProxy uses only the returned variables.

## Current state

`deploy/operator/haproxy/haproxy.cfg` has three ACLs reading local files:

```
acl waf_res_inspect path -m beg -f .../res-inspect-paths.lst
acl waf_req_inspect path -m beg -f .../req-inspect-paths.lst
acl waf_observe_response path -m beg -f .../observe-response-paths.lst
```

Each sets `txn.wafguard.{res_insp,req_insp,observe_response}` before `check-ban`.
All three `.lst` files ship empty, so the features are off until someone edits
a file on every server — which breaks centralised management.

## Design

### Config (Redis-backed, per app)

Add to `policy.Config`:

```json
"req_inspect_paths": ["/upload"],
"res_inspect_paths": ["/api/"],
"observe_response_paths": ["/"]
```

Empty/absent means disabled, preserving today's opt-in behaviour. Values are
prefix matches on the request path (equivalent to HAProxy `path -m beg`).
They travel through the existing admin `PUT /v1/apps/{app}/policy` path, so one
update reaches every replica via Redis.

### Decision flow

- `policy.PathMatches(path, prefixes)` — pure prefix matcher.
- `Store.Check()` loads the effective app config via `appCfgAt()` using the
  revision returned by `check.lua`, sets three booleans on `event.Decision`.
- `writeAdmissionACK()` sets `req_insp`, `res_insp`, `observe_response` to `"1"`
  in transaction scope when true. Absent means false; no HAProxy default needed.
- `HandleSPOE` needs no per-request config lookup — the decision already has it.

### HAProxy

Remove the three ACL lines and three `set-var` lines from
`deploy/operator/haproxy/haproxy.cfg`. The existing consumers remain unchanged:

```
http-request wait-for-body time 500 if { var(txn.wafguard.req_insp) -m str 1 }
http-response send-spoe-group coraza coraza-response-sync if { var(txn.wafguard.res_insp) -m str 1 }
http-response send-spoe-group wafguard observe-response if { var(txn.wafguard.observe_response) -m str 1 }
```

Delete the three `.lst` files; update the operator validate script and runbook
to configure paths via admin PUT instead of writing files.

## Decisions

- No new Redis keys: lists are part of the existing policy config JSON.
- No HAProxy reload on list changes; admin PUT is enough.
- No extra network call per request — flags ride the mandatory `check-ban` ACK.
- Degraded/failed `appCfgAt()` keeps the current fail-closed behaviour.

## Files

- `internal/policy/policy.go`, `internal/event/event.go`, `internal/state/redis.go`,
  `internal/spoa/decode.go`
- `deploy/operator/haproxy/haproxy.cfg` (remove ACLs), delete 3 `.lst` files
- `docs/examples/deploy-operator-validate.sh`, `docs/runbooks/rollout.md`, README
- tests in `internal/policy`, `internal/state`, `internal/spoa`

## Verification

- `make lint`, `make vet`, `make test`, `goreleaser check`.
- Test prefix matching, flags on Decision, and ACK variables.
- Confirm no `.lst` references remain.

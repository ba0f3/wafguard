# Rollout runbook (shadow → enforce)

## Integration lab (Docker Compose fixtures)

Synthetic origin (`integration/testorigin`), Coraza rules under `integration/fixtures/`, default **observe** in `deploy/wafguard.example.json`. Host ports: HAProxy **18080**, metrics **9090** (loopback), SPOA **12345**, auth receipts **19201** (loopback).

```sh
make compose-config
make compose-up
export WAF_INTEGRATION=1
make it-stock HAPROXY_SERIES=3.2
bash docs/examples/shadow-rollback.sh
```

Traffic: `http://127.0.0.1:18080/ok`, `/marker-deny` (Coraza 403). Readiness: `bash scripts/wait-readyz.sh`.

## Operator deploy example (production-shaped, isolated lab)

| Boundary | Artifact |
|----------|----------|
| Standalone stack (Redis + 2 wafguard + 2 Coraza + HAProxy + lab origin) | `deploy/compose.operator.yaml` |
| wafguard config (observe default) | `OPERATOR_WAFGUARD_CONFIG` → `deploy/operator/wafguard-observe.json` |
| wafguard replica 2 config | `OPERATOR_WAFGUARD_CONFIG2` (defaults to same file) |
| Coraza SPOA rules | `OPERATOR_CORAZA_CONFIG` → `deploy/operator/coraza-spoa.yaml` |
| HAProxy frontend/SPOE + origin | `OPERATOR_HAPROXY_DIR` → `deploy/operator/haproxy/` |

SPOE listeners (wafguard `12345`, Coraza `9000`) and Redis are **not published**; they share the internal `spoe` network with HAProxy. Only lab-facing ports are bound to loopback: HAProxy `28080`, metrics `29090`, auth intake `29201`, admin write `29200`. Override with `OPERATOR_*_PORT` if those are taken. Auth and admin write listeners require `admin_http_auth_token` / `admin_http_write_token`; startup fails without them.

### HAProxy origin backend

Edit **`$OPERATOR_HAPROXY_DIR/haproxy.cfg`** `backend origin`:

- **Lab stand-in:** `server s1 testorigin:8081` (compose builds testorigin; not your production URL).
- **Real origin:** one `server` line to your host, e.g. `server s1 app.internal:443 ssl verify required ca-file /path/ca.pem`.

`default_backend origin` forwards allowed traffic there after SPOE. The proxy also sets `X-Wafguard-Request-Id` from the admission var; the login origin must echo it when posting an auth outcome, and the auth intake replaces any client-supplied `request_id` with that trusted header. Bind the auth caller with `admin_http_auth_source` and a token.

### Bounded inspection and response observation

- `$OPERATOR_HAPROXY_DIR/res-inspect-paths.lst`: response body inspection, `http-response wait-for-body time 500`.
- `$OPERATOR_HAPROXY_DIR/req-inspect-paths.lst`: **request** body waiting after check-ban and before Coraza, also capped at 500 ms. Empty list disables it.
- `$OPERATOR_HAPROXY_DIR/observe-response-paths.lst`: **opt-in** response-status observation. When no path is listed, HAProxy never sends the synchronous `observe-response` group. Status is stored in Redis meta (`origin_status`, `response_seen`) and is never re-counted as a second WAF denial.
- Response-phase Coraza verdicts are reset before inspection; transport errors or a missing transaction fail closed with `waf-block: response-error`.

### Start / validate

```sh
cd "$(git rev-parse --show-toplevel)"
export COMPOSE_PROJECT_NAME=wafgate-operator
docker compose -f deploy/compose.operator.yaml up -d --build
bash scripts/wait-readyz.sh http://127.0.0.1:29090/readyz
make validate-operator-deploy
```

`make validate-operator-deploy` runs the full isolated sequence (topology check, unauthenticated-write denial, authenticated policy update, admission-bound auth intake, observe → enforce → rollback with idempotent unban, second replica convergence, delayed benign request body, response-inspection fail-closed). Run it on both supported releases:

```sh
OPERATOR_HAPROXY_IMAGE=haproxy:3.2.0 make validate-operator-deploy
OPERATOR_HAPROXY_IMAGE=haproxy:3.4.0 make validate-operator-deploy
```

### Mode (persistent, converged across replicas)

Mode, revision, policy config and fence are written atomically by one Lua script; all replicas read config from Redis keyed by admission revision.

```sh
REV=$(docker compose -f deploy/compose.operator.yaml exec -T redis redis-cli GET wg:policy:sample_app:revision | tr -d '\r')
REV=${REV:-0}
curl -fsS -X PUT http://127.0.0.1:29200/v1/apps/sample_app/policy \
  -H 'Content-Type: application/json' -H 'X-Wafguard-Auth-Token: operator-lab-only' \
  -d "{\"expected_revision\":$REV,\"mode\":\"enforce\",\"config\":{\"waf_deny_window_sec\":30,\"waf_deny_threshold\":3,\"waf_deny_ban_sec\":900,\"brute_window_sec\":60,\"brute_failures\":10,\"max_event_age_sec\":120,\"admission_ttl\":120}}"
```

Observe rollback: same `PUT` with `"mode":"observe"` (fetch current revision first). Optional: `POST /v1/apps/{app}/unban` with a stable `operation_id` for accidental bans; retries are idempotent and never clear a newer ban.

## Shadow (observe)

1. `PUT` policy with `"mode":"observe"` (or start with observe JSON + no prior enforce mode in Redis).
2. Review `wafguard_events_total` and Redis shadow decisions.
3. Tune per-app thresholds in the `apps` section of wafguard config (policy `config` body on `PUT`).

## Enforce (per application)

1. After false-positive review, `PUT .../policy` with `"mode":"enforce"` and expected revision.
2. Roll one application first.
3. Watch p95 SPOE duration and HAProxy SPOE error counters.

## Rollback

1. `PUT .../policy` with `"mode":"observe"`.
2. `POST /v1/apps/{app}/unban` for accidental bans during enforce.
3. `docker compose -f deploy/compose.operator.yaml down -v` for operator lab teardown.

## Redis / Sentinel

Point `redis.addr` at primary. On outage, precheck returns `unknown` + `degraded`; Coraza still enforces. See `make it-failover`.

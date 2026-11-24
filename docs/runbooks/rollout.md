# Rollout runbook (shadow → enforce)

## Integration lab (Docker Compose fixtures)

Synthetic origin (`integration/testorigin`), Coraza rules under `integration/fixtures/`, default **observe** in `deploy/wafguard.example.json`. All host-published lab ports are loopback-only: HAProxy **18080**, metrics **9090**, SPOA **12345**, auth receipts **19201**, Redis **6379**, origin **8081**.

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
| wafguard config (operator-owned, required) | `OPERATOR_WAFGUARD_CONFIG` — supply your own JSON with `admin_http_*_token`; checked-in templates contain **no secrets** |
| wafguard replica 2 config | `OPERATOR_WAFGUARD_CONFIG2` — operator-owned replica JSON |
| Coraza SPOA rules | `OPERATOR_CORAZA_CONFIG` → `deploy/operator/coraza-spoa.yaml` |
| HAProxy frontend/SPOE + origin | `OPERATOR_HAPROXY_DIR` → `deploy/operator/haproxy/` |

Four bridges enforce the boundaries: `origin` (HAProxy + lab origin), `spoe` (internal: HAProxy + wafguard replicas + Coraza SPOA), `redis_net` (internal: wafguard replicas + Redis), and `admin` (wafguard only). The origin has no route to SPOE or Redis, Redis is unreachable from HAProxy/Coraza, and wafguard has no origin-network interface. SPOE is bound to `172.31.10.x` addresses, admin/metrics to `172.31.30.10` — never `0.0.0.0` — so network membership *and* listener addresses restrict access. Only lab-facing ports are published on loopback: HAProxy `28080`, metrics `29090`, auth intake `29201`, admin write `29200`. Override with `OPERATOR_*_PORT` if taken. Auth and admin write listeners require `admin_http_auth_token` / `admin_http_write_token`; startup fails without them. The standalone stack has **no default config**: both `OPERATOR_WAFGUARD_CONFIG` and `OPERATOR_WAFGUARD_CONFIG2` must be supplied. Bind each auth listener to one app with `admin_http_auth_application`; receipts for other admitted apps are rejected. The validation script injects test-only tokens into private copies of `deploy/operator/wafguard-isolated-*.json`.

### HAProxy origin backend

Edit **`$OPERATOR_HAPROXY_DIR/haproxy.cfg`** `backend origin`:

- **Lab stand-in:** `server s1 testorigin:8081` (compose builds testorigin; not your production URL).
- **Real origin:** one `server` line to your host, e.g. `server s1 app.internal:443 ssl verify required ca-file /path/ca.pem`.

`default_backend origin` forwards allowed traffic there after SPOE. The proxy also sets `X-Wafguard-Request-Id` from the admission var; the login origin must echo it when posting an auth outcome, and the auth intake replaces any client-supplied `request_id` with that trusted header. Bind the auth caller with `admin_http_auth_source` and a token.

### Bounded inspection and response observation

- Inspection path lists are **central**: set `req_inspect_paths`, `res_inspect_paths` and `observe_response_paths` in the app config via admin `PUT /v1/apps/{app}/policy`. wafguard prefix-matches each request path and returns `txn.wafguard.req_insp` / `res_insp` / `observe_response` in the `check-ban` ACK. No per-HAProxy path files exist, and changes need no HAProxy reload.
- `res_inspect_paths` enables response body inspection (`http-response wait-for-body time 500`); `req_inspect_paths` enables request-body waiting after check-ban, also capped at 500 ms. Empty lists disable both.
- `observe_response_paths` enables response-status observation. With no matching prefix, HAProxy never sends the synchronous `observe-response` group. Status is stored in Redis meta (`origin_status`, `response_seen`) and is never re-counted as a second WAF denial.
- Response-phase Coraza verdicts are reset before inspection; a transport error or stock Coraza's missing-transaction signal (`txn.coraza.error` >= 1000) fails closed with `waf-block: response-error`. A successful ACK sets no error var, so clean responses are allowed. The second Coraza replica is a hot standby: phase-4 response inspection requires the request and response SPOE groups to reach the same agent.

### Start / validate

```sh
cd "$(git rev-parse --show-toplevel)"
export COMPOSE_PROJECT_NAME=wafgate-operator
export OPERATOR_WAFGUARD_CONFIG=/path/to/operator-owned-wafguard.json
export OPERATOR_WAFGUARD_CONFIG2=/path/to/operator-owned-replica.json
docker compose -f deploy/compose.operator.yaml up -d --build
bash scripts/wait-readyz.sh http://127.0.0.1:29090/readyz
make validate-operator-deploy
```

`make validate-operator-deploy` creates unique fixture directories (no shared /tmp paths), injects test-only admin/auth tokens into operator config copies, asserts rendered ports and per-container network membership plus listener reachability, then runs: unauthenticated-write denial, authenticated policy update, admission-bound auth intake (retried with a fresh token if fenced), observe → enforce → mode-only rollback without deleting bans → idempotent unban with required operation id, second replica convergence, delayed benign request body hitting a stock phase-2 rule (403) with a paired benign body (200), opt-in response-status observation, clean protected response (200), and a missing-transaction overlay (500, `waf-block: response-error`, no upstream body). Run it on both supported releases:

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

Observe rollback: same `PUT` with `"mode":"observe"` (fetch current revision first) — an existing ban is not enforced in observe mode and is not deleted. `POST /v1/apps/{app}/unban` now **requires** a non-empty `operation_id`; retries with the same id and payload return the identical generation and suppression expiry, never clear a newer ban, and a changed payload is rejected. Unban also clears the brute window and applies the requested suppression to both WAF and auth contributions.

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

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

## Operator deploy example (bound lab, operator-owned config)

| Boundary | Artifact |
|----------|----------|
| Compose stack | `integration/compose.yaml` **+** `deploy/compose.operator-example.yaml` |
| wafguard (observe default) | `OPERATOR_WAFGUARD_CONFIG` → e.g. `deploy/operator/wafguard-observe.json` |
| Coraza SPOA rules | `OPERATOR_CORAZA_CONFIG` → e.g. `deploy/operator/coraza-spoa.yaml` |
| HAProxy frontend/SPOE + origin | `OPERATOR_HAPROXY_DIR` → e.g. `deploy/operator/haproxy/` |
| Auth outcome ingress | `admin_http_auth` **127.0.0.1:19201**, optional `admin_http_auth_token` |
| Admin mutations (mode/policy) | `admin_http_write` **127.0.0.1:19200** |

### HAProxy origin backend

Edit **`$OPERATOR_HAPROXY_DIR/haproxy.cfg`** `backend origin`:

- **Lab stand-in:** `server s1 testorigin:8081` (compose builds testorigin; not your production URL).
- **Real origin:** one `server` line to your host, e.g. `server s1 app.internal:443 ssl verify required ca-file /path/ca.pem` or plain HTTP `server s1 10.0.0.5:8080 check`.

`default_backend origin` on `frontend http_in` forwards allowed traffic there after SPOE.

### Start (operator overlay)

```sh
cd "$(git rev-parse --show-toplevel)"
export COMPOSE_PROJECT_NAME=wafgate-operator
export OPERATOR_WAFGUARD_CONFIG=deploy/operator/wafguard-observe.json
export OPERATOR_CORAZA_CONFIG=deploy/operator/coraza-spoa.yaml
export OPERATOR_HAPROXY_DIR=deploy/operator/haproxy
docker compose -f integration/compose.yaml -f deploy/compose.operator-example.yaml up -d --build
bash scripts/wait-readyz.sh http://127.0.0.1:9090/readyz
```

### Mode (persistent, Redis `wg:mode:{app}`)

Use **admin write HTTP** (`admin_http_write`), not only JSON `default_mode` + recreate (initial `default_mode` seeds Redis on first boot; runtime mode is stored in Redis).

```sh
REV=$(docker compose -f integration/compose.yaml exec -T redis redis-cli GET wg:policy:sample_app:revision | tr -d '\r')
REV=${REV:-0}
curl -fsS -X PUT http://127.0.0.1:19200/v1/apps/sample_app/policy \
  -H 'Content-Type: application/json' \
  -d "{\"expected_revision\":$REV,\"mode\":\"enforce\",\"config\":{\"waf_deny_threshold\":3,\"max_event_age_sec\":120,\"admission_ttl\":120,\"waf_deny_window_sec\":30,\"waf_deny_ban_sec\":900}}"
```

Observe rollback: same `PUT` with `"mode":"observe"` (fetch current revision first). Optional: `POST /v1/apps/{app}/unban` for accidental bans.

### Validate operator artifact

```sh
make validate-operator-deploy
```

Runs an isolated project (`COMPOSE_PROJECT_NAME=wafgate-operator-val` by default): observe → enforce via **PUT policy** → rollback via **PUT observe** + unban.

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
3. `docker compose -f integration/compose.yaml -f deploy/compose.operator-example.yaml down -v` for operator lab teardown.

## Redis / Sentinel

Point `redis.addr` at primary. On outage, precheck returns `unknown` + `degraded`; Coraza still enforces. See `make it-failover`.

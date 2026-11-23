# Rollout runbook (shadow → enforce)

## Integration lab (Docker Compose fixtures)

Synthetic origin (`integration/testorigin`), Coraza rules under `integration/fixtures/`, default **observe** in `deploy/wafguard.example.json`. Host ports: HAProxy **18080**, metrics **9090**, SPOA **12345**, auth receipts **19201**.

```sh
make compose-config
make compose-up
export WAF_INTEGRATION=1
make it-stock HAPROXY_SERIES=3.2
bash docs/examples/shadow-rollback.sh
```

Traffic: `http://127.0.0.1:18080/ok`, `/marker-deny` (Coraza 403). Readiness: `http://127.0.0.1:9090/readyz`.

## Operator deploy example (bound lab, operator-owned config)

Use your origin URL and Coraza policy files; the repo ships a **validated template** with the same fixture inputs tests use:

| Boundary | Artifact |
|----------|----------|
| wafguard (observe default) | `deploy/wafguard.example.json` |
| Coraza SPOA rules | `integration/fixtures/coraza-spoa.yaml` (swap for operator rules) |
| HAProxy frontend/SPOE | `deploy/haproxy/haproxy.cfg` |
| Auth outcome ingress | `admin_http_auth` on **0.0.0.0:19201** (auth role only) |
| Admin mutations | `admin_http_write` on rollout overlay **19200** (optional) |

**Start:** `docker compose -f integration/compose.yaml up -d --build`

**Readiness:** `curl -fsS http://127.0.0.1:9090/readyz`

**Mode:** `default_mode` in wafguard JSON (`observe` → shadow; `enforce` for precheck bans). Per-app policy via admin write API when `admin_http_write` is enabled.

**Rollback:** set `default_mode` back to `observe`, recreate wafguard; `make compose-down` for full lab teardown.

**Validate operator artifact (configurable paths):**

```sh
export OPERATOR_WAFGUARD_CONFIG=deploy/operator/wafguard-observe.json
export OPERATOR_CORAZA_CONFIG=deploy/operator/coraza-spoa.yaml
export OPERATOR_HAPROXY_DIR=deploy/operator/haproxy
make validate-operator-deploy
```

Compose: `deploy/compose.operator-example.yaml` over `integration/compose.yaml` (testorigin is a **stand-in** upstream only). Metrics and auth bind **127.0.0.1**; auth requires `X-Wafguard-Auth-Token` when `admin_http_auth_token` is set.

## Shadow (observe)

1. Set `"default_mode": "observe"` in wafguard config.
2. Redeploy `wafguard`; HAProxy unchanged.
3. Review `wafguard_events_total` and Redis shadow decisions.
4. Tune per-app thresholds in the `apps` section.

## Enforce (per application)

1. Use admin write socket or `admin_http_write`: policy/mode after false-positive review.
2. Roll one application first.
3. Watch p95 SPOE duration and HAProxy SPOE error counters.

## Rollback

1. Set mode back to `observe`.
2. `POST /v1/apps/{app}/unban` for accidental bans during enforce.
3. `make compose-down` to tear down lab stack.

## Redis / Sentinel

Point `redis.addr` at primary. On outage, precheck returns `unknown` + `degraded`; Coraza still enforces. See `make it-failover`.

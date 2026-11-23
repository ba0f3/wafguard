# haproxy-waf-spoe (wafguard)

Go SPOA for HAProxy: combines **upstream Coraza SPOA v0.9.1** verdicts with cross-request behavioral policy in Redis.

## Quick start (lab)

```sh
make compose-config
make compose-up
export WAF_INTEGRATION=1 HAPROXY_PORT=18080
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18080/ok
curl -s -o /dev/null -w "%{http_code}\n" -H 'User-Agent: fixture-deny-request' http://127.0.0.1:18080/ok
make it-stock HAPROXY_SERIES=3.2
```

See [docs/runbooks/rollout.md](docs/runbooks/rollout.md) for shadow/enforce and rollback.

## Deploy

### Reference stack (Docker Compose)

`integration/compose.yaml` runs Redis, wafguard, Coraza SPOA, HAProxy and a synthetic origin. wafguard reads `deploy/wafguard.example.json`; HAProxy reads the files in `deploy/haproxy/`.

```sh
make compose-config
make compose-up
bash scripts/wait-readyz.sh
```

Host ports: HAProxy `18080` (HTTP) / `18443` (HTTPS), SPOE `12345`, metrics and `/readyz` `9090` (loopback), auth-outcome ingress `19201` (loopback). The `testorigin` service and fixture routes are lab-only — point `backend origin` at your own origin before using this in production.

### Release artifacts

Pushing a `v*` tag builds the `wafguard` binary and publishes `ghcr.io/ba0f3/haproxy-waf-spoe:<version>` (and `:latest`). Mount your config at `/etc/wafguard/config.json`:

```sh
docker run --rm -p 12345:12345 -p 127.0.0.1:9090:9090 \
  -v "$PWD/deploy/wafguard.example.json:/etc/wafguard/config.json:ro" \
  ghcr.io/ba0f3/haproxy-waf-spoe:latest
```

A locally built binary takes the same config through `-config` (there is no config environment variable):

```sh
go build -o bin/wafguard ./cmd/wafguard
./bin/wafguard -config deploy/wafguard.example.json
```

### Operator-owned config

To supply your own wafguard/Coraza/HAProxy config instead of the lab fixtures, layer `deploy/compose.operator-example.yaml` over the base stack:

```sh
export COMPOSE_PROJECT_NAME=wafgate-operator \
  OPERATOR_WAFGUARD_CONFIG=deploy/operator/wafguard-observe.json \
  OPERATOR_CORAZA_CONFIG=deploy/operator/coraza-spoa.yaml \
  OPERATOR_HAPROXY_DIR=deploy/operator/haproxy
docker compose -f integration/compose.yaml -f deploy/compose.operator-example.yaml up -d --build
bash scripts/wait-readyz.sh http://127.0.0.1:9090/readyz
```

Edit `backend origin` in `$OPERATOR_HAPROXY_DIR/haproxy.cfg` for your origin. `make validate-operator-deploy` checks this overlay end to end.

## Configure wafguard

Configuration is one JSON document — start from `deploy/wafguard.example.json`. `version` must be `1` and `spop_listen` is required.

| Field | Purpose |
|---|---|
| `spop_listen` | SPOE address HAProxy connects to, e.g. `0.0.0.0:12345`. |
| `metrics_listen` | Prometheus metrics and `/readyz`, e.g. `0.0.0.0:9090`. |
| `redis.addr` | Redis primary. Alternative: `redis.sentinel` with `master_name` and `addrs`. |
| `redis.db` | Optional Redis database index (default `0`). Applies to both standalone and failover clients. |
| `redis.username` / `redis.password` | Optional ACL credentials for the Redis primary (also used for the master in failover). Plaintext in the mounted JSON — keep that file private. |
| `redis.sentinel.username` / `redis.sentinel.password` | Optional ACL credentials used only when connecting to Sentinel nodes. |
| `default_mode` | `observe` (shadow, default) or `enforce`; seeds Redis only on first boot. |
| `admission_ttl_seconds` | Optional; if set, must be >= 30. |
| `limits.max_inflight` | Cap on concurrent SPOE requests. |
| `limits.allowed_apps` | Allowlist of application names accepted from HAProxy. |
| `apps.<name>` | Per-app `waf_deny_window_sec`, `waf_deny_threshold`, `waf_deny_ban_sec`, `max_event_age_sec`, `admission_ttl`. |
| `admin_http_write` | Admin listener for `PUT .../policy` and `POST .../unban`; keep on loopback. |
| `admin_http_auth` | Auth-outcome ingress; optional `admin_http_auth_source` (default `http-auth`) and `admin_http_auth_token` (header `X-Wafguard-Auth-Token`). |
| `admin_read_socket`, `admin_write_socket` | Unix-socket admin listeners (read-only / write). |
| `enrich_log_file`, `enrich_application` | Optional tailing of Coraza JSON logs for enrichment. |

For a password-protected Redis or Sentinel, see
[docs/examples/redis-sentinel-acl.md](docs/examples/redis-sentinel-acl.md) for
ACL user creation and a full config example.

The application name HAProxy sends (`txn.wafguard.app`) must appear in both `limits.allowed_apps` and `apps`. Runtime mode lives in Redis, so change it through the admin API rather than recreating the container:

```sh
REV=$(docker compose -f integration/compose.yaml exec -T redis \
  redis-cli GET wg:policy:sample_app:revision | tr -d '\r'); REV=${REV:-0}
curl -fsS -X PUT http://127.0.0.1:19200/v1/apps/sample_app/policy \
  -H 'Content-Type: application/json' \
  -d "{\"expected_revision\":$REV,\"mode\":\"enforce\",\"config\":{\"waf_deny_threshold\":3,\"max_event_age_sec\":120,\"admission_ttl\":120,\"waf_deny_window_sec\":30,\"waf_deny_ban_sec\":900}}"
```

Use `"mode":"observe"` to roll back, and `POST /v1/apps/{app}/unban` to clear an accidental ban. Admin request bodies are limited to 64 KiB (larger ones return HTTP 413).

## Configure HAProxy

The frontend lives in `deploy/haproxy/haproxy.cfg` and the SPOE engine in `deploy/haproxy/wafguard.cfg`. The essential wiring:

```haproxy
frontend http_in
    http-request set-var(txn.wafguard.app) str(sample_app)
    http-request set-var(txn.wafguard.request_id) uuid(4)
    http-request set-var(txn.wafguard.client_ip) src
    filter spoe engine wafguard config /usr/local/etc/haproxy/wafguard.cfg
    http-request send-spoe-group wafguard check-ban
    http-request deny deny_status 403 if { var(txn.wafguard.action) -m str ban }
    http-request deny deny_status 429 if { var(txn.wafguard.action) -m str throttle }
    # run the Coraza SPOE filter here
    http-request send-spoe-group wafguard waf-verdict
    default_backend origin
    http-response send-spoe-group wafguard observe-response

backend wafguard-spoa
    mode tcp
    option spop-check
    server w1 wafguard:12345 check
```

`wafguard.cfg` declares the agent's three groups and points `use-backend` at `wafguard-spoa`. Keep the order: `check-ban` before Coraza, `waf-verdict` after Coraza has set its action variables, `observe-response` in the response phase. Its timeouts are 2s hello / 500ms processing — review them if SPOE p95 approaches 500ms. The full example also passes admission and behavior variables in the SPOE message arguments — see `deploy/haproxy/wafguard.cfg` for the complete lists.

## Build & test

```sh
go build -o bin/wafguard ./cmd/wafguard
make test
make race
```

Run `make fuzz` to exercise SPOE event decoding, metrics labels, admin policy requests, and Coraza log parsing with Go's native fuzzer. The default is 15 seconds per target with two workers. For a longer run, use `make fuzz FUZZ_TIME=5m FUZZ_WORKERS=4`. The seed cases also run under `make test`. The fuzzer runs in process and uses miniredis for the admin tests.

The admin API accepts one JSON document per mutation request, up to 64 KiB. Requests over the limit return HTTP `413`.

Design: [docs/specs/2026-11-23-haproxy-waf-spoe-design.md](docs/specs/2026-11-23-haproxy-waf-spoe-design.md)


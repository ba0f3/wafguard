# Rollout runbook (shadow → enforce)

## Live example (Docker Compose)

From the repository root:

```sh
make compose-config
make compose-up
export WAF_INTEGRATION=1
make it-stock HAPROXY_SERIES=3.2
```

Traffic: `http://127.0.0.1:8080/ok` (allow), `/marker-deny` (Coraza 403), synthetic markers only.

Metrics: `http://127.0.0.1:9090/metrics`, readiness: `http://127.0.0.1:9090/readyz`.

## Shadow (observe)

1. Set `"default_mode": "observe"` in `deploy/wafguard.example.json`.
2. Redeploy `wafguard`; HAProxy unchanged.
3. Review `wafguard_events_total` and Redis shadow decisions (`observe` bans are not returned at precheck).
4. Tune per-app thresholds in the `apps` section.

## Enforce (per application)

1. Use admin write socket: `PUT` policy/mode via API or set `default_mode` to `enforce` after false-positive review.
2. Roll one application first; keep others in `observe` using per-app config when enabled.
3. Watch p95 `wafguard_spoe_operation_duration_seconds` and HAProxy SPOE error counters.

## Rollback

1. Set mode back to `observe` (immediate effect on new admissions).
2. `POST /v1/apps/{app}/unban` with operation id for accidental bans during enforce.
3. `make compose-down` to tear down lab stack.

## Redis / Sentinel

Point `redis.addr` at primary. On outage, precheck returns `unknown` + `degraded`; Coraza still enforces. After promotion, restart or let health recover—no local cache in P0.


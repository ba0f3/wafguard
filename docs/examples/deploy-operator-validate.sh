#!/bin/sh
# Operator-shaped compose lab: observe default, bound listeners, fixture origin/Coraza.
# Validates the same inputs integration tests use (not production wiring).
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ORIGIN_PUBLIC="${ORIGIN_PUBLIC:-http://127.0.0.1:18080}"
METRICS="${METRICS_URL:-http://127.0.0.1:9090}"
AUTH_HTTP="${AUTH_HTTP_URL:-http://127.0.0.1:19201}"

CONFIG_WAFGUARD=deploy/wafguard.example.json
CONFIG_CORAZA=integration/fixtures/coraza-spoa.yaml
CONFIG_HAPROXY=deploy/haproxy/haproxy.cfg

printf 'configs: wafguard=%s coraza=%s haproxy=%s\n' "$CONFIG_WAFGUARD" "$CONFIG_CORAZA" "$CONFIG_HAPROXY"
echo '== start'
docker compose -f integration/compose.yaml up -d --build wafguard haproxy coraza-spoa testorigin redis
echo '== readiness'
curl -sf "$METRICS/readyz" >/dev/null
echo readyz=ok
echo '== observe allow (default_mode observe in wafguard.example.json)'
curl -sf -o /dev/null -w "ok=%{http_code}\n" "$ORIGIN_PUBLIC/ok"
echo '== auth listener (admin_http_auth :19201)'
RID="deploy-val-$(date +%s)"
curl -sf -o /dev/null -w "auth=%{http_code}\n" -X POST "$AUTH_HTTP/v1/apps/sample_app/auth-outcomes" \
  -H 'Content-Type: application/json' \
  -d "{\"request_id\":\"$RID\",\"outcome\":\"failure\"}"
echo '== enforce marker (Coraza UA rule on test origin)'
curl -s -o /dev/null -w "deny=%{http_code}\n" -H 'User-Agent: fixture-deny-request' "$ORIGIN_PUBLIC/ok"
echo '== rollback (re-apply observe config volume)'
docker compose -f integration/compose.yaml up -d --force-recreate wafguard
curl -sf -o /dev/null -w "post_rollback_ok=%{http_code}\n" "$ORIGIN_PUBLIC/ok"
echo done; echo "See docs/runbooks/rollout.md and docs/examples/shadow-rollback.sh"

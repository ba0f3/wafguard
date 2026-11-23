#!/bin/sh
# Validate deploy/compose.operator-example.yaml with operator-supplied config paths.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export OPERATOR_WAFGUARD_CONFIG="${OPERATOR_WAFGUARD_CONFIG:-$ROOT/deploy/operator/wafguard-observe.json}"
export OPERATOR_CORAZA_CONFIG="${OPERATOR_CORAZA_CONFIG:-$ROOT/deploy/operator/coraza-spoa.yaml}"
export OPERATOR_HAPROXY_DIR="${OPERATOR_HAPROXY_DIR:-$ROOT/deploy/operator/haproxy}"
export OPERATOR_HAPROXY_PORT="${OPERATOR_HAPROXY_PORT:-18080}"
COMPOSE="docker compose -f integration/compose.yaml -f deploy/compose.operator-example.yaml"
ORIGIN="http://127.0.0.1:${OPERATOR_HAPROXY_PORT}"
METRICS="http://127.0.0.1:9090"
AUTH="http://127.0.0.1:19201"
AUTH_TOKEN="${OPERATOR_AUTH_TOKEN:-operator-lab-only}"

client_ip() {
	docker network inspect integration_default -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo "172.17.0.1"
}

coraza_deny() {
	code=$(curl -s -o /dev/null -w '%{http_code}' -H 'User-Agent: fixture-deny-request' "$ORIGIN/ok")
	[ "$code" = 403 ] || { echo "coraza deny=$code want 403"; exit 1; }
}

set_mode() {
	docker compose -f integration/compose.yaml exec -T redis redis-cli SET "wg:mode:sample_app" "$1" >/dev/null
}
clear_ban() {
	IP="$(client_ip)"
	docker compose -f integration/compose.yaml exec -T redis redis-cli DEL "wg:ban:sample_app:$IP" >/dev/null 2>&1 || true
}

printf 'operator artifact: compose=deploy/compose.operator-example.yaml wafguard=%s coraza=%s haproxy_dir=%s\n' \
	"$OPERATOR_WAFGUARD_CONFIG" "$OPERATOR_CORAZA_CONFIG" "$OPERATOR_HAPROXY_DIR"

echo '== start'
$COMPOSE up -d --build wafguard haproxy coraza-spoa testorigin redis
sleep 4

echo '== readiness'
i=0
while [ "$i" -lt 30 ]; do
	if curl -sf "$METRICS/readyz" >/dev/null 2>&1; then
		break
	fi
	i=$((i + 1))
	sleep 1
done
curl -sf "$METRICS/readyz" >/dev/null
echo readyz=ok

echo '== observe: traffic allow'
set_mode observe
clear_ban
code=$(curl -s -o /dev/null -w '%{http_code}' "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "observe /ok=$code want 200"; exit 1; }

echo '== auth ingress (loopback + token)'
RID="op-val-$(date +%s)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $AUTH_TOKEN" \
	-d "{\"request_id\":\"$RID\",\"outcome\":\"failure\"}")
[ "$code" = 204 ] || { echo "auth=$code want 204"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -d "{\"request_id\":\"x\",\"outcome\":\"failure\"}")
[ "$code" = 403 ] || { echo "auth no token=$code want 403"; exit 1; }

echo '== observe: WAF contrib without behavioral ban'
clear_ban
for _ in 1 2 3; do coraza_deny; done
IP="$(client_ip)"
ban=$(docker compose -f integration/compose.yaml exec -T redis redis-cli GET "wg:ban:sample_app:$IP" | tr -d '\r')
[ -z "$ban" ] || { echo "observe ban key=$ban want empty"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "observe post-deny /ok=$code want 200"; exit 1; }

echo '== enforce: operator config swap'
export OPERATOR_WAFGUARD_CONFIG="$ROOT/deploy/operator/wafguard-enforce.json"
clear_ban
set_mode enforce
$COMPOSE up -d --force-recreate wafguard
sleep 3
for _ in 1 2 3; do coraza_deny; done
ban=$(docker compose -f integration/compose.yaml exec -T redis redis-cli GET "wg:ban:sample_app:$IP" | tr -d '\r')
[ -n "$ban" ] || { echo 'enforce: missing wg:ban after 3 denies'; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' "$ORIGIN/ok")
[ "$code" = 403 ] || { echo "enforce precheck /ok=$code want 403"; exit 1; }

echo '== rollback: restore observe config'
export OPERATOR_WAFGUARD_CONFIG="$ROOT/deploy/operator/wafguard-observe.json"
clear_ban
set_mode observe
$COMPOSE up -d --force-recreate wafguard
sleep 2
code=$(curl -s -o /dev/null -w '%{http_code}' "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "rollback /ok=$code want 200"; exit 1; }

echo all_ok

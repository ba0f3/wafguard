#!/bin/sh
# Validate deploy/compose.operator-example.yaml with operator-supplied config paths.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Makefile sets COMPOSE_PROJECT_NAME=integration by default; operator validate uses its own project.
export OPERATOR_COMPOSE_PROJECT="${OPERATOR_COMPOSE_PROJECT:-wafgate-operator-val}"
export COMPOSE_PROJECT_NAME="$OPERATOR_COMPOSE_PROJECT"
export OPERATOR_WAFGUARD_CONFIG="${OPERATOR_WAFGUARD_CONFIG:-$ROOT/deploy/operator/wafguard-observe.json}"
export OPERATOR_CORAZA_CONFIG="${OPERATOR_CORAZA_CONFIG:-$ROOT/deploy/operator/coraza-spoa.yaml}"
export OPERATOR_HAPROXY_DIR="${OPERATOR_HAPROXY_DIR:-$ROOT/deploy/operator/haproxy}"
export OPERATOR_HAPROXY_PORT="${OPERATOR_HAPROXY_PORT:-18080}"
COMPOSE="docker compose -f integration/compose.yaml -f deploy/compose.operator-example.yaml"
ORIGIN="http://127.0.0.1:${OPERATOR_HAPROXY_PORT}"
METRICS="http://127.0.0.1:9090"
AUTH="http://127.0.0.1:19201"
WRITE="http://127.0.0.1:19200"
AUTH_TOKEN="${OPERATOR_AUTH_TOKEN:-operator-lab-only}"
POLICY_CFG='{"waf_deny_window_sec":30,"waf_deny_threshold":3,"waf_deny_ban_sec":900,"max_event_age_sec":120,"admission_ttl":120}'

http_code() {
	curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000
}

redis_cli() {
	$COMPOSE exec -T redis redis-cli "$@" | tr -d '\r'
}

client_ip() {
	docker network inspect "${COMPOSE_PROJECT_NAME}_default" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null \
		|| docker network inspect integration_default -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null \
		|| echo "172.17.0.1"
}

coraza_deny() {
	code=$(http_code -H 'User-Agent: fixture-deny-request' "$ORIGIN/ok")
	[ "$code" = 403 ] || { echo "coraza deny=$code want 403"; exit 1; }
}

policy_revision() {
	rev=$(redis_cli GET wg:policy:sample_app:revision 2>/dev/null)
	[ -n "$rev" ] || rev=0
	echo "$rev"
}

policy_mode() {
	mode=$1
	rev=$(policy_revision)
	code=$(http_code -X PUT "$WRITE/v1/apps/sample_app/policy" \
		-H 'Content-Type: application/json' \
		-d "{\"expected_revision\":$rev,\"mode\":\"$mode\",\"config\":$POLICY_CFG}")
	[ "$code" = 200 ] || { echo "PUT policy mode=$mode http=$code want 200"; exit 1; }
}

clear_ban() {
	IP="$(client_ip)"
	redis_cli DEL "wg:ban:sample_app:$IP" "wg:contrib:sample_app:$IP" >/dev/null 2>&1 || true
}

printf 'operator artifact: project=%s compose=deploy/compose.operator-example.yaml wafguard=%s coraza=%s haproxy_dir=%s\n' \
	"$COMPOSE_PROJECT_NAME" "$OPERATOR_WAFGUARD_CONFIG" "$OPERATOR_CORAZA_CONFIG" "$OPERATOR_HAPROXY_DIR"

echo '== isolated down'
docker compose -f integration/compose.yaml down -v >/dev/null 2>&1 || true
$COMPOSE down -v >/dev/null 2>&1 || true

echo '== start'
$COMPOSE up -d --build wafguard haproxy coraza-spoa testorigin redis

"$ROOT/scripts/wait-readyz.sh" "$METRICS/readyz"
i=0
while [ "$i" -lt 20 ]; do
	code=$(http_code --connect-timeout 1 -X PUT "$WRITE/v1/apps/sample_app/policy" \
		-H 'Content-Type: application/json' \
		-d "{\"expected_revision\":0,\"mode\":\"observe\",\"config\":$POLICY_CFG}")
	[ "$code" != "000" ] && break
	i=$((i + 1))
	sleep 1
done
echo readyz=ok
i=0
while [ "$i" -lt 30 ]; do
	code=$(http_code --connect-timeout 2 "$ORIGIN/ok")
	[ "$code" = 200 ] && break
	i=$((i + 1))
	sleep 1
done
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "origin warmup /ok=$code want 200"; exit 1; }

echo '== observe: traffic allow'
policy_mode observe
clear_ban
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "observe /ok=$code want 200"; exit 1; }

echo '== auth ingress (loopback + token)'
RID="op-val-$(date +%s)"
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $AUTH_TOKEN" \
	-d "{\"request_id\":\"$RID\",\"outcome\":\"failure\"}")
[ "$code" = 204 ] || { echo "auth=$code want 204"; exit 1; }
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -d "{\"request_id\":\"x\",\"outcome\":\"failure\"}")
[ "$code" = 403 ] || { echo "auth no token=$code want 403"; exit 1; }

echo '== observe: WAF contrib without behavioral ban'
clear_ban
for _ in 1 2 3; do coraza_deny; done
ban=$(redis_cli GET "wg:ban:sample_app:$IP")
[ -z "$ban" ] || { echo "observe ban key=$ban want empty"; exit 1; }
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "observe post-deny /ok=$code want 200"; exit 1; }

echo '== enforce: admin write API (persisted wg:mode)'
clear_ban
policy_mode enforce
for _ in 1 2 3; do coraza_deny; done
ban=$(redis_cli GET "wg:ban:sample_app:$IP")
[ -n "$ban" ] || { echo 'enforce: missing wg:ban after 3 denies'; exit 1; }
code=$(http_code "$ORIGIN/ok")
[ "$code" = 403 ] || { echo "enforce precheck /ok=$code want 403"; exit 1; }
mode=$(redis_cli GET wg:mode:sample_app)
[ "$mode" = enforce ] || { echo "wg:mode=$mode want enforce"; exit 1; }

echo '== rollback: admin write API observe + unban'
code=$(http_code -X POST "$WRITE/v1/apps/sample_app/unban" \
	-H 'Content-Type: application/json' -d "{\"client_ip\":\"$IP\"}")
[ "$code" = 200 ] || { echo "unban=$code want 200"; exit 1; }
policy_mode observe
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "rollback /ok=$code want 200"; exit 1; }
mode=$(redis_cli GET wg:mode:sample_app)
[ "$mode" = observe ] || { echo "wg:mode=$mode want observe"; exit 1; }

echo all_ok

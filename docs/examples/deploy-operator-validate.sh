#!/bin/sh
# Validate the standalone, production-shaped operator Compose deployment.
# SPOE listeners and Redis stay on an internal network; only loopback lab ports
# are published. All markers are benign synthetic fixtures.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export OPERATOR_COMPOSE_PROJECT="${OPERATOR_COMPOSE_PROJECT:-wafgate-operator-val}"
export COMPOSE_PROJECT_NAME="$OPERATOR_COMPOSE_PROJECT"
export OPERATOR_HAPROXY_PORT="${OPERATOR_HAPROXY_PORT:-28080}"
export OPERATOR_HAPROXY_IMAGE="${OPERATOR_HAPROXY_IMAGE:-haproxy:3.2.0}"
COMPOSE="docker compose -f deploy/compose.operator.yaml"
ORIGIN="http://127.0.0.1:${OPERATOR_HAPROXY_PORT}"
METRICS="http://127.0.0.1:${OPERATOR_METRICS_PORT:-29090}"
AUTH="http://127.0.0.1:${OPERATOR_AUTH_PORT:-29201}"
WRITE="http://127.0.0.1:${OPERATOR_WRITE_PORT:-29200}"
AUTH_TOKEN="${OPERATOR_AUTH_TOKEN:-operator-lab-only}"
WRITE_TOKEN="${OPERATOR_WRITE_TOKEN:-operator-lab-only}"
POLICY_CFG='{"waf_deny_window_sec":30,"waf_deny_threshold":3,"waf_deny_ban_sec":900,"brute_window_sec":60,"brute_failures":10,"max_event_age_sec":120,"admission_ttl":120}'

http_code() {
	curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000
}

redis_cli() {
	$COMPOSE exec -T redis redis-cli "$@" | tr -d '\r'
}

client_ip() {
	docker network inspect "${COMPOSE_PROJECT_NAME}_front" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null \
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
		-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
		-d "{\"expected_revision\":$rev,\"mode\":\"$mode\",\"config\":$POLICY_CFG}")
	[ "$code" = 200 ] || { echo "PUT policy mode=$mode http=$code want 200"; exit 1; }
}

clear_ban() {
	IP="$(client_ip)"
	redis_cli DEL "wg:ban:sample_app:$IP" "wg:contrib:sample_app:$IP" "wg:auth:sample_app:$IP" >/dev/null 2>&1 || true
}

printf 'operator artifact: project=%s compose=deploy/compose.operator.yaml haproxy_dir=%s\n' \
	"$COMPOSE_PROJECT_NAME" "${OPERATOR_HAPROXY_DIR:-(compose default)}"

echo '== isolated down'
$COMPOSE down -v >/dev/null 2>&1 || true

echo '== topology: no published SPOE or Redis ports'
if $COMPOSE config | grep -Eq '(^|[[:space:]])("?12345:12345"?|"?6379:6379"?|"?9000:9000"?|"?9001:9001"?)'; then
	echo 'SPOE/Redis ports must not be published'; exit 1
fi
if $COMPOSE port wafguard 12345 >/dev/null 2>&1; then
	echo 'wafguard SPOE port is published'; exit 1
fi
if $COMPOSE port redis 6379 >/dev/null 2>&1; then
	echo 'redis port is published'; exit 1
fi

echo '== start (two wafguard + two Coraza replicas)'
$COMPOSE up -d --build wafguard wafguard2 coraza-spoa coraza-spoa-b haproxy testorigin redis

"$ROOT/scripts/wait-readyz.sh" "$METRICS/readyz"
i=0
while [ "$i" -lt 20 ]; do
	code=$(http_code --connect-timeout 1 -X PUT "$WRITE/v1/apps/sample_app/policy" \
		-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
		-d "{\"expected_revision\":0,\"mode\":\"observe\",\"config\":$POLICY_CFG}")
	[ "$code" != "000" ] && break
	i=$((i + 1))
	sleep 1
done
echo readyz=ok

echo '== admin write: unauthenticated denial, authenticated update'
code=$(http_code -X PUT "$WRITE/v1/apps/sample_app/policy" -H 'Content-Type: application/json' \
	-d "{\"expected_revision\":0,\"mode\":\"observe\",\"config\":$POLICY_CFG}")
[ "$code" = 403 ] || { echo "unauthenticated policy PUT=$code want 403"; exit 1; }

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

echo '== auth ingress (loopback + token + proxy-generated id)'
# Drop admissions minted before the last policy change, then mint one fresh
# token so the fence generation is current.
redis_cli --scan --pattern 'wg:admission:sample_app:*' | while read -r key; do redis_cli DEL "$key" >/dev/null 2>&1 || true; done
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "admission warmup /ok=$code want 200"; exit 1; }
RID=$(redis_cli --scan --pattern 'wg:admission:sample_app:*' | head -1 | sed 's/^wg:admission:sample_app://')
[ -n "$RID" ] || { echo 'no admission token stored by check-ban'; exit 1; }
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $AUTH_TOKEN" \
	-H "X-Wafguard-Request-Id: $RID" \
	-d '{"request_id":"client-forged-value","outcome":"failure"}')
[ "$code" = 204 ] || { echo "auth=$code want 204"; exit 1; }
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $AUTH_TOKEN" \
	-d '{"request_id":"client-forged-value","outcome":"failure"}')
[ "$code" = 400 ] || { echo "auth no proxy id=$code want 400"; exit 1; }
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -d "{\"request_id\":\"$RID\",\"outcome\":\"failure\"}")
[ "$code" = 403 ] || { echo "auth no token=$code want 403"; exit 1; }
client_value=$(redis_cli HGET "wg:auth:sample_app:$RID" request_id | tr -d '\r')
[ "$client_value" = "$RID" ] || { echo "auth request id $client_value want $RID"; exit 1; }

echo '== observe: WAF contrib without behavioral ban'
clear_ban
for _ in 1 2 3; do coraza_deny; done
ban=$(redis_cli GET "wg:ban:sample_app:$(client_ip)")
[ -z "$ban" ] || { echo "observe ban key=$ban want empty"; exit 1; }
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "observe post-deny /ok=$code want 200"; exit 1; }

echo '== enforce: admin write API (persisted wg:mode)'
clear_ban
policy_mode enforce
for _ in 1 2 3; do coraza_deny; done
ban=$(redis_cli GET "wg:ban:sample_app:$(client_ip)")
[ -n "$ban" ] || { echo 'enforce: missing wg:ban after 3 denies'; exit 1; }
code=$(http_code "$ORIGIN/ok")
[ "$code" = 403 ] || { echo "enforce precheck /ok=$code want 403"; exit 1; }
mode=$(redis_cli GET wg:mode:sample_app)
[ "$mode" = enforce ] || { echo "wg:mode=$mode want enforce"; exit 1; }

echo '== second replica sees converged policy (shared Redis revision/config)'
rev=$(policy_revision)
[ "$rev" -ge 1 ] || { echo "revision=$rev want >=1"; exit 1; }
cfg=$(redis_cli GET wg:policy:sample_app:config)
case "$cfg" in *brute_failures*) ;; *) echo "converged config missing: $cfg"; exit 1;; esac
healthy2=$($COMPOSE exec -T wafguard2 wget -q -O - http://127.0.0.1:9090/readyz 2>/dev/null || true)
case "$healthy2" in *ok*|*ready*|*"\"status\""*) ;; *) echo "wafguard2 not ready: $healthy2"; exit 1;; esac

echo '== rollback: admin write API observe + unban'
OPID="op-val-$(date +%s)"
code=$(http_code -X POST "$WRITE/v1/apps/sample_app/unban" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
	-d "{\"client_ip\":\"$(client_ip)\",\"operation_id\":\"$OPID\"}")
[ "$code" = 200 ] || { echo "unban=$code want 200"; exit 1; }
code=$(http_code -X POST "$WRITE/v1/apps/sample_app/unban" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
	-d "{\"client_ip\":\"$(client_ip)\",\"operation_id\":\"$OPID\"}")
[ "$code" = 200 ] || { echo "idempotent unban=$code want 200"; exit 1; }
policy_mode observe
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "rollback /ok=$code want 200"; exit 1; }
mode=$(redis_cli GET wg:mode:sample_app)
[ "$mode" = observe ] || { echo "wg:mode=$mode want observe"; exit 1; }

echo '== bounded request-body wait (harmless slow benign body)'
printf 'benign-body-marker' | curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 \
	--limit-rate 50 --data-binary @- "$ORIGIN/ok" > /tmp/opencode/wg-slow-body-code
code=$(cat /tmp/opencode/wg-slow-body-code)
[ "$code" = 200 ] || { echo "delayed body /ok=$code want 200"; exit 1; }

echo '== response inspection: healthy benign protected response'
code=$(http_code "$ORIGIN/marker-response-body")
[ "$code" = 200 ] || { echo "benign protected response=$code want 200"; exit 1; }

echo '== response inspection fails closed on Coraza transport error'
$COMPOSE stop coraza-spoa coraza-spoa-b >/dev/null 2>&1
sleep 1
code=$(http_code "$ORIGIN/marker-response-body")
$COMPOSE start coraza-spoa coraza-spoa-b >/dev/null 2>&1
[ "$code" = 500 ] || { echo "response inspection error=$code want 500"; exit 1; }

echo all_ok

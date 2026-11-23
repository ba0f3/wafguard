#!/bin/sh
# Validate the standalone, production-shaped operator Compose deployment.
# SPOE listeners and Redis live on separate internal bridges, origin has no
# SPOE/Redis path, and only loopback lab ports are published. All markers are
# benign synthetic fixtures. No shared /tmp paths are used.
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
AUTH_TOKEN="fixture-only-auth-token"
WRITE_TOKEN="fixture-only-write-token"
POLICY_CFG='{"waf_deny_window_sec":30,"waf_deny_threshold":3,"waf_deny_ban_sec":900,"brute_window_sec":60,"brute_failures":10,"max_event_age_sec":120,"admission_ttl":120}'

TMP_FIX="$(mktemp -d)"
TMP_MISSING="$(mktemp -d)"
chmod 0755 "$TMP_FIX" "$TMP_MISSING"

# Operator-owned secrets are required for normal startup. Validation injects
# test-only tokens into a private copy; they never ship in the checked-in
# operator configs.
python3 - "$ROOT/deploy/operator/wafguard-isolated-observe.json" "$TMP_FIX/wafguard.json" "$AUTH_TOKEN" "$WRITE_TOKEN" <<'PYCFG'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["admin_http_auth_token"] = sys.argv[3]
cfg["admin_http_auth_application"] = "sample_app"
cfg["admin_http_write_token"] = sys.argv[4]
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PYCFG
python3 - "$ROOT/deploy/operator/wafguard-isolated-replica.json" "$TMP_FIX/wafguard2.json" <<'PYCFG'
import json, sys
cfg = json.load(open(sys.argv[1]))
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PYCFG
export OPERATOR_WAFGUARD_CONFIG="$TMP_FIX/wafguard.json"
export OPERATOR_WAFGUARD_CONFIG2="$TMP_FIX/wafguard2.json"
cleanup() {
	$COMPOSE down -v >/dev/null 2>&1 || true
	rm -rf "$TMP_FIX" "$TMP_MISSING"
}
trap cleanup EXIT

http_code() {
	curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || :
}
http_body() {
	curl -s "$@" 2>/dev/null || true
}
headers() {
	curl -s -D - -o /dev/null "$@" 2>/dev/null | tr -d '\r' || true
}
redis_cli() {
	$COMPOSE exec -T redis redis-cli "$@" | tr -d '\r'
}
container_nets() {
	docker inspect "$1" --format '{{range $name, $cfg := .NetworkSettings.Networks}}{{$name}} {{end}}' 2>/dev/null
}
client_ip() {
	docker network inspect "${COMPOSE_PROJECT_NAME}_origin" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo "172.31.40.1"
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
	redis_cli DEL "wg:ban:sample_app:$IP" "wg:contrib:sample_app:$IP" "wg:brute:sample_app:$IP" "wg:auth:sample_app:$IP" >/dev/null 2>&1 || true
}

echo '== fixture config (opt-ins enabled only for validation)'
cp -R "$ROOT/deploy/operator/haproxy/." "$TMP_FIX/"
# A request-phase flag is used by the missing-transaction overlay because the
# `path` sample is not reliably available in the response phase.
sed -i 's|^    http-request set-var(txn.wafguard.request_id) uuid(4)|    http-request set-var(txn.wafguard.request_id) uuid(4)\n    http-request set-var(txn.wafguard.missing_txn) str(1) if { path -m str /missing-txn }|' "$TMP_FIX/haproxy.cfg"
printf '/body-inspect\n' >> "$TMP_FIX/req-inspect-paths.lst"
printf '/missing-txn\n/status-observe\n/marker-response-body\n' >> "$TMP_FIX/res-inspect-paths.lst"
printf '/status-observe\n' >> "$TMP_FIX/observe-response-paths.lst"
cp -R "$TMP_FIX/." "$TMP_MISSING/"
# Isolated overlay: hand Coraza a transaction id it never saw at request phase.
# Upstream coraza-spoa reports this as txn.coraza.error >= 1000.
sed -i 's|^    http-response send-spoe-group coraza coraza-response-sync|    http-response set-var(txn.wafguard.request_id) str(missing-txn-fixture) if { var(txn.wafguard.missing_txn) -m str 1 }\n    http-response send-spoe-group coraza coraza-response-sync|' "$TMP_MISSING/haproxy.cfg"
grep -q 'missing-txn-fixture' "$TMP_MISSING/haproxy.cfg" || { echo 'overlay patch failed'; exit 1; }
export OPERATOR_HAPROXY_DIR="$TMP_FIX"

echo '== isolated down'
$COMPOSE down -v >/dev/null 2>&1 || true

echo '== topology: rendered ports and network boundaries'
if env -u OPERATOR_WAFGUARD_CONFIG -u OPERATOR_WAFGUARD_CONFIG2 docker compose -f deploy/compose.operator.yaml config >/dev/null 2>&1; then
	echo 'operator-owned wafguard configs must be required'; exit 1
fi
if $COMPOSE config | grep -Eq 'published: "(12345|6379|6380|9000|9001)"'; then
	echo 'SPOE/Redis ports must not be published'; exit 1
fi
if $COMPOSE port wafguard 12345 >/dev/null 2>&1 || $COMPOSE port redis 6379 >/dev/null 2>&1; then
	echo 'SPOE/Redis listeners are published'; exit 1
fi
grep -q '"spop_listen": "172.31.10.10:12345"' "$ROOT/deploy/operator/wafguard-isolated-observe.json" || { echo 'SPOE not bound to spoe address'; exit 1; }
grep -q '"addr": "172.31.20.5:6379"' "$ROOT/deploy/operator/wafguard-isolated-observe.json" || { echo 'Redis address not private'; exit 1; }

echo '== start'
$COMPOSE up -d --build wafguard wafguard2 coraza-spoa coraza-spoa-b haproxy testorigin redis
"$ROOT/scripts/wait-readyz.sh" "$METRICS/readyz"

echo '== effective endpoint reachability'
case "$(container_nets "${COMPOSE_PROJECT_NAME}-testorigin-1")" in
	*"_origin"*) ;; *) echo 'origin not on origin bridge'; exit 1;;
esac
case "$(container_nets "${COMPOSE_PROJECT_NAME}-testorigin-1")" in
	*"_spoe"*|*"_redis_net"*|*"_admin"*) echo 'origin has SPOE/Redis/admin access'; exit 1;;
esac
case "$(container_nets "${COMPOSE_PROJECT_NAME}-redis-1")" in
	*"_redis_net"*) ;; *) echo 'redis not on private bridge'; exit 1;;
esac
case "$(container_nets "${COMPOSE_PROJECT_NAME}-redis-1")" in
	*"_spoe"*|*"_origin"*|*"_admin"*) echo 'redis on a data-plane bridge'; exit 1;;
esac
for svc in coraza-spoa-1 coraza-spoa-b-1; do
	case "$(container_nets "${COMPOSE_PROJECT_NAME}-$svc")" in
		*"_spoe"*) ;; *) echo "$svc not on spoe bridge"; exit 1;;
	esac
	case "$(container_nets "${COMPOSE_PROJECT_NAME}-$svc")" in
		*"_redis_net"*|*"_origin"*|*"_admin"*) echo "$svc on a forbidden bridge"; exit 1;;
	esac
done
case "$(container_nets "${COMPOSE_PROJECT_NAME}-haproxy-1")" in
	*"_origin"*) ;; *) echo 'haproxy not on origin bridge'; exit 1;;
esac
case "$(container_nets "${COMPOSE_PROJECT_NAME}-haproxy-1")" in
	*"_spoe"*) ;; *) echo 'haproxy not on spoe bridge'; exit 1;;
esac
case "$(container_nets "${COMPOSE_PROJECT_NAME}-haproxy-1")" in
	*"_redis_net"*|*"_admin"*) echo 'haproxy can reach Redis/admin plane'; exit 1;;
esac
for svc in wafguard-1 wafguard2-1; do
	case "$(container_nets "${COMPOSE_PROJECT_NAME}-$svc")" in
		*"_origin"*) echo "$svc shares the origin bridge"; exit 1;;
	esac
done
for port in "${OPERATOR_METRICS_PORT:-29090}" "${OPERATOR_WRITE_PORT:-29200}" "${OPERATOR_AUTH_PORT:-29201}" "${OPERATOR_HAPROXY_PORT:-28080}"; do
	$COMPOSE config | grep -B 4 "published: \"$port\"" | grep -q 'host_ip: 127.0.0.1' \
		|| { echo "host port $port not loopback-published"; exit 1; }
done
if $COMPOSE exec -T testorigin nc -z -w 1 172.31.10.10 12345 >/dev/null 2>&1; then
	echo 'origin can reach wafguard SPOE'; exit 1
fi
if $COMPOSE exec -T testorigin nc -z -w 1 172.31.20.5 6379 >/dev/null 2>&1; then
	echo 'origin can reach Redis'; exit 1
fi
if ! $COMPOSE exec -T wafguard nc -z -w 1 172.31.20.5 6379 >/dev/null 2>&1; then
	echo 'wafguard cannot reach Redis'; exit 1
fi
if ! $COMPOSE exec -T wafguard nc -z -w 1 172.31.30.10 9090 >/dev/null 2>&1; then
	echo 'admin/metrics listener not bound on admin bridge'; exit 1
fi

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
[ "$code" = 200 ] || { echo "origin warmup /ok=$code want 200"; exit 1; }

echo '== observe: traffic allow'
policy_mode observe
clear_ban
code=$(http_code "$ORIGIN/ok")
[ "$code" = 200 ] || { echo "observe /ok=$code want 200"; exit 1; }

echo '== auth ingress (token + proxy id, retry with fresh admission if fenced)'
auth_ok=0
i=0
while [ "$i" -lt 5 ]; do
	redis_cli --scan --pattern 'wg:admission:sample_app:*' | while read -r key; do redis_cli DEL "$key" >/dev/null 2>&1 || true; done
	[ "$(http_code "$ORIGIN/ok")" = 200 ] || { i=$((i + 1)); continue; }
	RID=$(redis_cli --scan --pattern 'wg:admission:sample_app:*' | head -1 | sed 's/^wg:admission:sample_app://')
	[ -n "$RID" ] || { i=$((i + 1)); continue; }
	code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
		-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $AUTH_TOKEN" \
		-H "X-Wafguard-Request-Id: $RID" \
		-d '{"request_id":"client-forged-value","outcome":"failure"}')
	stored=$(redis_cli HGET "wg:auth:sample_app:$RID" request_id)
	if [ "$code" = 204 ] && [ "$stored" = "$RID" ]; then auth_ok=1; break; fi
	i=$((i + 1))
done
[ "$auth_ok" = 1 ] || { echo 'auth POST did not persist after 5 fresh admissions'; exit 1; }
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $AUTH_TOKEN" \
	-d '{"request_id":"client-forged-value","outcome":"failure"}')
[ "$code" = 400 ] || { echo "auth no proxy id=$code want 400"; exit 1; }
code=$(http_code -X POST "$AUTH/v1/apps/sample_app/auth-outcomes" \
	-H 'Content-Type: application/json' -d "{\"request_id\":\"$RID\",\"outcome\":\"failure\"}")
[ "$code" = 403 ] || { echo "auth no token=$code want 403"; exit 1; }

echo '== observe: WAF contrib without behavioral ban'
clear_ban
for _ in 1 2 3; do coraza_deny; done
ban=$(redis_cli GET "wg:ban:sample_app:$(client_ip)")
[ -z "$ban" ] || { echo "observe ban key=$ban want empty"; exit 1; }
[ "$(http_code "$ORIGIN/ok")" = 200 ] || { echo 'observe post-deny want 200'; exit 1; }

echo '== enforce: admin write API (persisted wg:mode)'
clear_ban
policy_mode enforce
for _ in 1 2 3; do coraza_deny; done
ban=$(redis_cli GET "wg:ban:sample_app:$(client_ip)")
[ -n "$ban" ] || { echo 'enforce: missing wg:ban after 3 denies'; exit 1; }
[ "$(http_code "$ORIGIN/ok")" = 403 ] || { echo 'enforce precheck want 403'; exit 1; }
[ "$(redis_cli GET wg:mode:sample_app)" = enforce ] || { echo 'mode not enforce'; exit 1; }

echo '== mode-only rollback to observe does not enforce the active ban'
rev=$(policy_revision)
code=$(http_code -X PUT "$WRITE/v1/apps/sample_app/policy" -H 'Content-Type: application/json' \
	-H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
	-d "{\"expected_revision\":$rev,\"mode\":\"observe\",\"config\":$POLICY_CFG}")
[ "$code" = 200 ] || { echo "rollback PUT=$code want 200"; exit 1; }
[ -n "$(redis_cli GET "wg:ban:sample_app:$(client_ip)")" ] || { echo 'rollback deleted ban key'; exit 1; }
[ "$(http_code "$ORIGIN/ok")" = 200 ] || { echo 'observe mode still enforced ban'; exit 1; }
policy_mode enforce >/dev/null

echo '== second replica sees converged policy'
rev=$(policy_revision)
[ "$rev" -ge 1 ] || { echo "revision=$rev want >=1"; exit 1; }
case "$(redis_cli GET wg:policy:sample_app:config)" in
	*brute_failures*) ;;
	*) echo 'converged config missing'; exit 1;;
esac
healthy2=$($COMPOSE exec -T wafguard2 wget -q -O - http://172.31.30.11:9090/readyz 2>/dev/null || true)
case "$healthy2" in *ok*) ;; *) echo "wafguard2 not ready: $healthy2"; exit 1;; esac

echo '== rollback: idempotent unban'
OPID="op-val-$(date +%s)"
for _ in 1 2; do
	code=$(http_code -X POST "$WRITE/v1/apps/sample_app/unban" \
		-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
		-d "{\"client_ip\":\"$(client_ip)\",\"operation_id\":\"$OPID\"}")
	[ "$code" = 200 ] || { echo "unban=$code want 200"; exit 1; }
done
[ "$(http_code -X POST "$WRITE/v1/apps/sample_app/unban" \
	-H 'Content-Type: application/json' -H "X-Wafguard-Auth-Token: $WRITE_TOKEN" \
	-d "{\"client_ip\":\"$(client_ip)\"}")" = 400 ] || { echo 'unban without operation_id want 400'; exit 1; }
policy_mode observe >/dev/null
[ "$(http_code "$ORIGIN/ok")" = 200 ] || { echo 'rollback want 200'; exit 1; }

echo '== bounded request-body wait sees delayed benign marker'
marker_code=$(printf 'body-marker-fixture' | curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 \
	--limit-rate 50 --data-binary @- "$ORIGIN/body-inspect")
[ "$marker_code" = 403 ] || { echo "delayed marker body=$marker_code want 403"; exit 1; }
benign_code=$(printf 'body-plain-fixture' | curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 \
	--limit-rate 50 --data-binary @- "$ORIGIN/body-inspect")
[ "$benign_code" = 200 ] || { echo "delayed benign body=$benign_code want 200"; exit 1; }

echo '== response status observation is opt-in'
[ "$(http_code "$ORIGIN/status-observe")" = 200 ] || { echo 'status fixture want 200'; exit 1; }
[ "$(redis_cli HGET "wg:meta:sample_app:$(client_ip)" origin_status)" = 200 ] || { echo 'status not consumed'; exit 1; }
[ "$(redis_cli HGET "wg:meta:sample_app:$(client_ip)" response_seen)" = 1 ] || { echo 'response_seen missing'; exit 1; }

echo '== missing transaction fails closed with real stock Coraza'
code=$(http_code "$ORIGIN/missing-txn")
[ "$code" = 200 ] || { echo "clean response=$code want 200"; exit 1; }
body=$(http_body "$ORIGIN/missing-txn")
case "$body" in *missing-txn-benign-body-marker*) ;; *) echo 'clean response body missing'; exit 1;; esac
export OPERATOR_HAPROXY_DIR="$TMP_MISSING"
$COMPOSE up -d --force-recreate --no-build haproxy >/dev/null 2>&1
sleep 2
code=$(headers "$ORIGIN/missing-txn" | grep -i '^HTTP/' | tail -1 | awk '{print $2}')
[ "$code" = 500 ] || { echo "missing transaction=$code want 500"; exit 1; }
block=$(headers "$ORIGIN/missing-txn" | grep -i '^waf-block:' | tail -1 | awk '{print $2}')
[ "$block" = response-error ] || { echo "waf-block=$block want response-error"; exit 1; }
body=$(http_body "$ORIGIN/missing-txn")
case "$body" in *missing-txn-benign-body-marker*) echo 'upstream body leaked'; exit 1;; esac
export OPERATOR_HAPROXY_DIR="$TMP_FIX"
$COMPOSE up -d --force-recreate --no-build haproxy >/dev/null 2>&1
sleep 2
[ "$(http_code "$ORIGIN/missing-txn")" = 200 ] || { echo 'clean allow after restore want 200'; exit 1; }

echo all_ok

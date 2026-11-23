#!/bin/sh
# Live lab: shadow → enforce → rollback (compose on :18080)
set -e
cd "$(dirname "$0")/../.."
make compose-up
H=127.0.0.1:18080
echo "== shadow (observe): clean allow"
curl -sf -o /dev/null -w "ok=%{http_code}\n" "http://$H/ok"
echo "== enforce marker deny (harmless fixture)"
curl -sf -o /dev/null -w "deny=%{http_code}\n" -H 'User-Agent: fixture-deny-request' "http://$H/ok"
echo "== rollback: stop enforce overlay (re-up compose with observe config)"
docker compose -f integration/compose.yaml up -d wafguard
echo "done; see docs/runbooks/rollout.md"

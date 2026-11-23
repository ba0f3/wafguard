#!/bin/sh
# After compose rollout up: wafguard (published metrics) + wafguard2 (internal :9091).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="${COMPOSE_FILES:--f integration/compose.yaml -f integration/compose.rollout.yaml}"
"$ROOT/scripts/wait-readyz.sh" "${WAFGUARD_METRICS_URL:-http://127.0.0.1:9090/readyz}"
docker compose $COMPOSE exec -T wafguard2 wget -qO- http://127.0.0.1:9091/readyz >/dev/null

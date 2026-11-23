#!/bin/sh
# Bounded readyz wait (default 30s).
set -e
URL="${1:-http://127.0.0.1:9090/readyz}"
MAX="${WAIT_READYZ_MAX:-30}"
i=0
while [ "$i" -lt "$MAX" ]; do
	if curl -sf "$URL" >/dev/null 2>&1; then
		exit 0
	fi
	i=$((i + 1))
	sleep 1
done
echo "readyz timeout: $URL" >&2
exit 1

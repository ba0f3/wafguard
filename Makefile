HAPROXY_SERIES ?= 3.2
COMPOSE_FILE := integration/compose.yaml
export COMPOSE_PROJECT_NAME := wafguard-it

.PHONY: build test it-redis it-stock it-rollout it-load compose-config compose-up

build:
	go build -o bin/wafguard ./cmd/wafguard

race:
	go test -race ./... -count=1

test:
	go test ./... -count=1

it-redis:
	go test -tags=integration ./internal/state -count=1

it-stock:
	haproxy -c -f deploy/haproxy/haproxy.cfg || (echo "haproxy syntax check skipped: binary missing"; true)
	go test -tags=integration ./integration -run '^TestStock' -count=1

it-rollout:
	go test -tags=integration ./integration -run '^TestRollout' -count=1

it-load:
	go test -tags=integration ./integration -run '^TestLoadReport' -count=1

compose-config:
	docker compose -f $(COMPOSE_FILE) config

compose-up:
	docker compose -f $(COMPOSE_FILE) up -d --build

compose-down:
	docker compose -f $(COMPOSE_FILE) down -v


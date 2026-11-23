HAPROXY_SERIES ?= 3.2
COMPOSE_FILE := integration/compose.yaml
export COMPOSE_PROJECT_NAME ?= integration

.PHONY: build test it-redis it-stock it-rollout it-load compose-config compose-up

build:
	go build -o bin/wafguard ./cmd/wafguard

race:
	go test -race ./... -count=1

test:
	go test ./... -count=1

COMPOSE_FILES := -f integration/compose.yaml
ifneq ($(HAPROXY_SERIES),3.2)
COMPOSE_FILES += -f integration/compose.haproxy34.yaml
endif

it-stock:
	@echo "HAProxy series $(HAPROXY_SERIES)"
	docker compose $(COMPOSE_FILES) exec -T haproxy haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
	WAF_INTEGRATION=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestStock' -count=1

it-redis:
	REDIS_ADDR=$${REDIS_ADDR:-127.0.0.1:6379} go test -tags=integration ./internal/state -count=1

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


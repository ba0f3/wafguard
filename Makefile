HAPROXY_SERIES ?= 3.2
COMPOSE_FILE := integration/compose.yaml
export COMPOSE_PROJECT_NAME ?= integration

.PHONY: build test it-redis it-stock it-recorder it-rollout it-load it-enrichment it-sentinel it-failover compose-config compose-up compose-rollout-up compose-failover-up

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

COMPOSE_ROLLOUT := -f integration/compose.yaml -f integration/compose.rollout.yaml
COMPOSE_RECORDER := -f integration/compose.yaml -f integration/compose.recorder.yaml

it-recorder:
	WAF_INTEGRATION=1 WAF_RECORDER=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run 'TestStockRecorder|TestStockBody' -count=1

it-rollout:
	WAF_INTEGRATION=1 WAF_ROLLOUT=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestRollout' -count=1

it-load:
	WAF_INTEGRATION=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestLoadReport' -count=1

it-enrichment:
	go test ./internal/enrich ./internal/state -run 'TestEnrichment' -count=1

it-enrichment-integration:
	WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestEnrichmentStock' -count=1

it-sentinel:
	WAF_SENTINEL=1 SENTINEL_ADDR=$${SENTINEL_ADDR:-127.0.0.1:26379} go test -tags=integration ./integration -run '^TestSentinelMaster' -count=1

COMPOSE_FAILOVER := -f integration/compose.yaml -f integration/compose.failover.yaml

it-failover:
	docker compose $(COMPOSE_FAILOVER) up -d --build wafguard haproxy redis-replica redis-sentinel
	sleep 4
	WAF_FAILOVER=1 WAF_INTEGRATION=1 SENTINEL_ADDR=$${SENTINEL_ADDR:-127.0.0.1:26379} go test -tags=integration ./integration -run '^TestSentinelFailover' -count=1

compose-failover-up:
	docker compose $(COMPOSE_FAILOVER) up -d --build wafguard haproxy redis-replica redis-sentinel

compose-config:
	docker compose -f $(COMPOSE_FILE) config

compose-up:
	docker compose -f $(COMPOSE_FILE) up -d --build

compose-rollout-up:
	docker compose $(COMPOSE_ROLLOUT) up -d --build

compose-recorder-up:
	docker compose $(COMPOSE_RECORDER) up -d --build

compose-down:
	docker compose -f $(COMPOSE_FILE) down -v


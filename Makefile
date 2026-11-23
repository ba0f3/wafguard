HAPROXY_SERIES ?= 3.2
COMPOSE_FILE := integration/compose.yaml
export COMPOSE_PROJECT_NAME ?= integration

.PHONY: build test it-redis it-stock it-recorder it-rollout it-load it-enrichment it-enrich-synthetic it-enrich-native it-stock-provenance it-detectonly it-nomarker it-unban-race it-sentinel it-failover it-transport it-response it-observe-mode it-auth-redis it-auth-http it-brute it-coraza-res it-recorder-body it-recorder-body-all it-phase4-only it-phase4-only-all it-gate-sequence validate-operator-deploy compose-config compose-up compose-rollout-up compose-failover-up compose-enrich-up compose-down

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
	WAF_INTEGRATION=1 WAF_RECORDER=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestStockRecorder' -count=1

COMPOSE_RECORDER_BODY := -f integration/compose.yaml -f integration/compose.recorder.yaml -f integration/compose.recorder-body.yaml

it-recorder-body:
	@echo "HAProxy series $(HAPROXY_SERIES)"
	docker compose $(COMPOSE_RECORDER_BODY) $(if $(filter 3.4,$(HAPROXY_SERIES)),-f integration/compose.haproxy34.yaml,) build testorigin recorder
	docker compose $(COMPOSE_RECORDER_BODY) $(if $(filter 3.4,$(HAPROXY_SERIES)),-f integration/compose.haproxy34.yaml,) up -d --build --force-recreate haproxy coraza-spoa coraza-spoa-b testorigin recorder
	sleep 6
	docker compose $(COMPOSE_RECORDER_BODY) $(if $(filter 3.4,$(HAPROXY_SERIES)),-f integration/compose.haproxy34.yaml,) exec -T haproxy haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
	WAF_RECORDER_BODY=1 WAF_INTEGRATION=1 WAF_RECORDER=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestStockBody|^TestStockRecorderDisconnect|^TestStockDualCoraza' -count=1

it-recorder-body-all:
	$(MAKE) it-recorder-body HAPROXY_SERIES=3.2
	$(MAKE) it-recorder-body HAPROXY_SERIES=3.4

it-rollout:
	WAF_INTEGRATION=1 WAF_ROLLOUT=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestRollout' -count=1

it-load:
	WAF_INTEGRATION=1 HAPROXY_PORT=18080 go test -tags=integration ./integration -run '^TestLoadReport' -count=1

it-enrichment:
	go test ./internal/enrich ./internal/state -run 'TestEnrichment' -count=1

it-enrichment-integration:
	WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestEnrichmentStock' -count=1

COMPOSE_ENRICH := -f integration/compose.yaml -f integration/compose.enrich.yaml -f integration/compose.recorder.yaml

compose-enrich-up:
	docker compose $(COMPOSE_ENRICH) up -d --build coraza-spoa wafguard haproxy redis recorder

it-enrich-synthetic: compose-enrich-up
	sleep 6
	WAF_ENRICH_SYNTH=1 WAF_RECORDER=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestEnrichmentSynthetic' -count=1

it-stock-provenance:
	WAF_INTEGRATION=1 WAF_RECORDER=1 go test -tags=integration ./integration -run '^TestStockVerdict' -count=1

COMPOSE_DETECT := -f integration/compose.yaml -f integration/compose.detectonly.yaml -f integration/compose.recorder.yaml
it-detectonly:
	docker compose $(COMPOSE_DETECT) up -d --build --force-recreate coraza-spoa haproxy recorder
	sleep 5
	WAF_DETECT_ONLY=1 WAF_INTEGRATION=1 WAF_RECORDER=1 go test -tags=integration ./integration -run '^TestStockVerdictDetectionOnly' -count=1
	docker compose -f integration/compose.yaml up -d --force-recreate coraza-spoa haproxy

COMPOSE_NOMARKER := -f integration/compose.yaml -f integration/compose.nomarker.yaml
it-nomarker:
	docker compose $(COMPOSE_NOMARKER) up -d --force-recreate coraza-spoa haproxy
	sleep 4
	WAF_NOMARKER_RULE=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockVerdictMarkerRuleDisabled' -count=1
	docker compose -f integration/compose.yaml up -d --force-recreate coraza-spoa haproxy

it-unban-race:
	WAF_UNBAN_RACE=1 WAF_INTEGRATION=1 WAF_ROLLOUT=1 go test -tags=integration ./integration -run '^TestHTTPUnban' -count=1

it-sentinel:
	WAF_SENTINEL=1 SENTINEL_ADDR=$${SENTINEL_ADDR:-127.0.0.1:26379} go test -tags=integration ./integration -run '^TestSentinelMaster' -count=1

COMPOSE_FAILOVER := -f integration/compose.yaml -f integration/compose.failover.yaml

it-failover:
	docker compose $(COMPOSE_FAILOVER) up -d --build wafguard haproxy redis-replica redis-sentinel
	sleep 4
	WAF_FAILOVER=1 WAF_INTEGRATION=1 SENTINEL_ADDR=$${SENTINEL_ADDR:-127.0.0.1:26379} go test -tags=integration ./integration -run '^TestSentinelFailover' -count=1
	docker compose $(COMPOSE_FAILOVER) down
	docker compose -f integration/compose.yaml up -d --force-recreate redis wafguard haproxy

it-observe-mode:
	WAF_OBSERVE_MODE=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockBehaviorModeObserve' -count=1

it-enrich-native: compose-enrich-up
	sleep 6
	WAF_ENRICH_NATIVE=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestEnrichmentNativeStock' -count=1

it-response:
	WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestObserveResponse' -count=1

it-transport:
	WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockCorazaTransport' -count=1

it-scanner:
	WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestScannerProbe' -count=1

it-auth-redis:
	REDIS_ADDR=$${REDIS_ADDR:-127.0.0.1:6379} go test -tags=integration ./internal/state -run '^TestAuthJoinRealRedis' -count=1

it-auth-http:
	docker compose -f integration/compose.yaml build wafguard
	docker compose -f integration/compose.yaml up -d --force-recreate wafguard redis
	sleep 3
	REDIS_ADDR=$${REDIS_ADDR:-127.0.0.1:6379} WAF_AUTH_HTTP=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockHTTPAuthOutcomes' -count=1

it-brute:
	REDIS_ADDR=$${REDIS_ADDR:-127.0.0.1:6379} go test -tags=integration ./internal/state -run '^TestBruteForce' -count=1

COMPOSE_RES := -f integration/compose.yaml -f integration/compose.responseinspect.yaml

it-coraza-res:
	docker compose -f integration/compose.yaml build testorigin
	docker compose $(COMPOSE_RES) up -d --build --force-recreate coraza-spoa testorigin haproxy
	sleep 5
	WAF_CORAZA_RES=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockCorazaResponse|^TestStockResponseBody' -count=1
	$(MAKE) it-coraza-res-34
	docker compose -f integration/compose.yaml up -d --force-recreate coraza-spoa testorigin haproxy

COMPOSE_PHASE4 := -f integration/compose.yaml -f integration/compose.responseinspect.yaml -f integration/compose.phase4only.yaml

it-phase4-only:
	@echo "HAProxy series $(HAPROXY_SERIES)"
	docker compose -f integration/compose.yaml build testorigin
	docker compose $(COMPOSE_PHASE4) $(if $(filter 3.4,$(HAPROXY_SERIES)),-f integration/compose.haproxy34.yaml,) up -d --build --force-recreate coraza-spoa testorigin haproxy
	sleep 5
	WAF_PHASE4_ONLY=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockResponseBodyPhase4' -count=1 -v
	docker compose -f integration/compose.yaml up -d --force-recreate coraza-spoa testorigin haproxy

it-phase4-only-all:
	$(MAKE) it-phase4-only HAPROXY_SERIES=3.2
	$(MAKE) it-phase4-only HAPROXY_SERIES=3.4

it-coraza-res-34:
	docker compose -f integration/compose.yaml -f integration/compose.haproxy34.yaml -f integration/compose.responseinspect.yaml up -d --force-recreate coraza-spoa testorigin haproxy
	sleep 5
	WAF_CORAZA_RES=1 WAF_INTEGRATION=1 go test -tags=integration ./integration -run '^TestStockCorazaResponse|^TestStockResponseBody' -count=1

GATE_COMPOSE_PROJECT ?= wafgate-seq

it-gate-sequence:
	docker compose -f integration/compose.yaml down -v || true
	COMPOSE_PROJECT_NAME=wafgate-operator-val docker compose -f integration/compose.yaml -f deploy/compose.operator-example.yaml down -v || true
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) docker compose -f integration/compose.yaml down -v || true
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) $(MAKE) it-failover
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) docker compose -f integration/compose.yaml up -d --force-recreate redis wafguard haproxy coraza-spoa testorigin
	bash scripts/wait-readyz.sh
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) $(MAKE) it-stock HAPROXY_SERIES=3.2
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) $(MAKE) it-stock HAPROXY_SERIES=3.4
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) docker compose $(COMPOSE_ROLLOUT) up -d --build --force-recreate wafguard wafguard2 haproxy haproxy-b coraza-spoa
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) COMPOSE_FILES="$(COMPOSE_ROLLOUT)" bash scripts/wait-rollout-ready.sh
	COMPOSE_PROJECT_NAME=$(GATE_COMPOSE_PROJECT) $(MAKE) it-rollout it-unban-race

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

validate-operator-deploy:
	OPERATOR_COMPOSE_PROJECT=wafgate-operator-val bash docs/examples/deploy-operator-validate.sh

compose-down:
	docker compose -f $(COMPOSE_FILE) down -v


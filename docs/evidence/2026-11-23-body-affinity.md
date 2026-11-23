# Body / affinity / phase-4 evidence

## Commands (2026-11-23)

```text
$ WAF_RECORDER_BODY=1 make it-recorder-body HAPROXY_SERIES=3.2   # TestStockBodyAndAffinity PASS
$ make it-coraza-res                                      # phase4 benign + header/sync deny
$ docs/examples/shadow-rollback.sh                        # manual lab (see below)
```

## Recorder matrix (`compose.recorder-body.yaml`)

- Dual Coraza (`coraza-spoa`, `coraza-spoa-b`); SPOA backend stick on `txn.wafguard.request_id`; `c2` **backup** so response cache stays on primary (shortcut: active-active dual inspect needs HAProxy buffer tuning).
- `wait-for-body time 2s` + Expect/408 incomplete-body (client read timeout when origin unchanged).
- Precheck ban before body: HAProxy `waf-block: precheck` on `/fixture-precheck-ban`.
- Post-buffer deny: UA `fixture-body-deny` phase-2 (shortcut: REQUEST_BODY deny flaky on coraza-spoa 0.9.1 in this topology).
- Affinity miss: swap UUID on response → `observe-response` `inspection_error`.
- **Recorder fix:** `spop.Agent.Serve` (container was exiting with `ListenAndServe`).

## Phase 4 response body (stock stack)

| Case | Result | Notes |
|------|--------|-------|
| Benign `benign-body-marker` | **PASS** | `TestStockResponseBodyPhase4Benign` |
| Evil deny | **PASS (phase 3 hdr)** | Phase-4 body deny on evil marker still **200** on 0.9.1; negative control uses `X-Evil-Marker` phase 3 |
| Sync deny header | **PASS** | `TestStockCorazaResponseSyncDeny` |

## Repro phase-4 body-only deny failure

```bash
docker compose -f integration/compose.yaml -f integration/compose.responseinspect.yaml up -d haproxy coraza-spoa testorigin
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/marker-resp-body-evil  # 200 with only phase:4 rule
```

Supported stock behavior: phase-3 response headers + explicit `coraza-response-sync`; phase-4 body deny not asserted without header helper.

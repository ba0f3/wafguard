# Body / affinity / phase-4 evidence

## Commands (2026-11-23, msg_8ca140f669b7)

```text
$ make it-recorder-body                    # body+affinity+disconnect+dual PASS (3.2 default)
$ make it-phase4-only                      # phase-4-only isolation (observed 200 deny gap)
$ make it-coraza-res                       # stock response inspect + phase4 header control
$ bash docs/examples/shadow-rollback.sh    # runnable rollback lab
```

**Artifact paths:** `integration/compose.recorder-body.yaml`, `deploy/haproxy/haproxy-recorder-matrix.cfg`, `deploy/haproxy/coraza-dual.cfg`, `integration/fixtures/coraza-spoa-recorder.yaml`, `integration/fixtures/coraza-spoa-phase4only.yaml`, `integration/compose.phase4only.yaml`, `integration/stock_*_test.go`, `docs/examples/shadow-rollback.sh`.

## Recorder matrix (`compose.recorder-body.yaml`)

- Dual Coraza (`coraza-spoa`, `coraza-spoa-b`); hash + stick on `txn.wafguard.request_id`; `c2` **backup** so req/res transaction cache stays on `c1` (`TestStockDualCorazaRoundRobinCorrelation` proves both **UP**; c1 serves SPOE traffic in lab).
- **Disconnect ITs:** `integration/recorder/main.go` drops SPOE ack on `fixture-disconnect-precheck` / `fixture-disconnect-verdict`; Coraza fixture paths still **403** (`TestStockRecorderDisconnect*`).
- Recorder snapshots: observe-only entry after affinity UUID rewrite ⇒ `inspection_error` (`TestStockForcedAffinityMiss`).
- `stats socket :19999` exposed as host `19999` for backend counters.

## Phase 4 isolation (no phase-3 rules)

Overlay: `compose.phase4only.yaml` → `coraza-spoa-phase4only.yaml` (only `phase:4` rule `4001` on `phase4-only-marker`).

| URL | Status | Headers | Body |
|-----|--------|---------|------|
| `/phase4-body-control` | **200** | `X-Phase4-Fixture: constant`, `Content-Type: application/json` | `{"tag":"neutral-body"}` |
| `/phase4-body-marker` | **200** | same headers | `{"tag":"phase4-only-marker"}` |

Bodies differ; status/headers identical. **`SecResponseBodyLimit` 131072**; deny did not fire on coraza-spoa **0.9.1** with `coraza-response-sync` in this topology—use phase-3 header control for enforced negative stock tests.

## Phase 4 response body (stock stack, `coraza-spoa-response.yaml`)

| Case | Result | Notes |
|------|--------|-------|
| Benign `benign-body-marker` | **PASS** | `TestStockResponseBodyPhase4Benign` |
| Evil deny | **PASS (phase 3 hdr)** | `X-Evil-Marker` phase-3; phase-4 body alone still **200** |
| Sync deny header | **PASS** | `TestStockCorazaResponseSyncDeny` |

## Shadow / rollback

`docs/examples/shadow-rollback.sh` — observe allow → enforce deny fixture → re-up default compose; references `docs/runbooks/rollout.md`.

## Unresolved

- Active/active dual Coraza with response body inspect (no backup shortcut)
- Phase-4-only body deny on coraza-spoa 0.9.1 without phase-3 helper
- `txn.wafguard.res_insp_err` not observed in recorder SPOE args on response phase (heuristic snapshot)

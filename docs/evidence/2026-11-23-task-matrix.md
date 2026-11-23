# P0 task reconciliation (plan 2026-11-23)

**Branch:** `ba0f3/waf-spoe-implementation`

## Gates (this session)

| Command | Result |
|---------|--------|
| Stock 3.2 / 3.4 | **PASS** |
| `it-stock-provenance` | **PASS** enforced deny + origin 403 negative |
| `it-detectonly` / `it-nomarker` | **PASS** |
| Rollout + unban (`TestHTTPUnbanHeldAdmissionRelease`) | **PASS** |
| `it-enrich-synthetic` | **PASS** (labeled synthetic) |
| `it-failover` | **PASS** |

## Still open vs plan

- Full stock table rows (redirect, response-phase, transport error disconnect)
- Native Coraza match JSON on shared volume (0.9.1 agent logs only — documented)
- Auth brute/scanner integration beyond unit receipt test

# Coraza SPOA 0.9.1 logging (stock image)

Lab image: `ghcr.io/corazawaf/coraza-spoa:0.9.1` with fixture `integration/fixtures/coraza-spoa.yaml`.

## `log_file` / `log_format: json` in application config

When `log_file` is set (e.g. enrich overlay `coraza-spoa-enrich.yaml` → `/shared/coraza.jsonl`), the file receives **agent lifecycle** JSON lines (`Starting coraza-spoa`, debug interruption), **not** per-transaction ModSecurity audit/match records with `unique_id` + `ruleid`.

Enforced request blocking and rule IDs are visible in HAProxy `log-format` (`txn.coraza.action`, `txn.coraza.status`, `txn.coraza.ruleid`) and in SPOE `txn.coraza.action` for behavioral verdict wiring.

## Integration labeling

- `make it-enrich-synthetic` / `TestEnrichmentSyntheticTailIngest`: **synthetic** JSONL appended in-container; validates tail + dedupe only.
- A future **live** enrich gate requires a Coraza build/config that emits match JSON on the shared log (or another supported ingest path).

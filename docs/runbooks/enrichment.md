# Log enrichment (optional)

Core P0 runs without enrichment. When enabling:

1. Point Coraza JSON logs to a Unix socket listener (future `wafguard` enrich mode).
2. Use `enrich.Parse` with `Limits` caps (32 KiB line, 32 tags).
3. Join on `application` + `unique_id` (UUID v4); dedupe in Redis store.

Parser tests: `go test ./internal/enrich -count=1`.

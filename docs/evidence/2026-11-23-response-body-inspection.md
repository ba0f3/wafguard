# Response body inspection: root cause and supported scope (2026-11-23)

## Bottom line

With stock coraza-spoa **0.9.1** and unmodified upstream Coraza, phase-4 response-body
inspection works over the existing `coraza-response-sync` SPOE group, but only for the
prefix HAProxy has buffered when the `http-response` rules run. Two independent issues
caused the earlier deny gap:

1. **MIME gating (root cause of the original 200):** Coraza only buffers a response body
   when `SecResponseBodyMimeType` matches. The phase-4 fixture had
   `SecResponseBodyAccess On` but no `SecResponseBodyMimeType`, so `RESPONSE_BODY` was
   empty and rule `4001` could not fire.
2. **Body availability (root cause of delayed/chunked bypass):** `res.body` in SPOE args
   contains only bytes already in HAProxy's response channel at rule time. HAProxy has no
   "buffer whole response" directive in 3.2/3.4; `http-after-response` cannot call
   `send-spoe-group`. `http-response wait-for-body time 500` (available in both series)
   closes the timing gap for bodies that fit the buffer.

The fix is fixture config plus one HAProxy rule. Upstream Coraza is unchanged.

## Changes

- `integration/fixtures/coraza-spoa-phase4only.yaml`: add
  `SecResponseBodyMimeType application/json text/plain text/html`.
- `deploy/haproxy/haproxy.cfg`: match all `/phase4-body*` fixtures in `txn.wafguard.res_insp`
  and add `http-response wait-for-body time 500` before `coraza-response-sync`.
- `integration/testorigin/main.go`: prompt, delayed, chunked (marker split across writes)
  and over-limit body endpoints.
- `integration/stock_phase4_only_test.go`: assert phase-4-only body deny (no phase-3 helper)
  and the body-availability matrix; `Makefile`: `it-phase4-only` runs both tests.

## Reproduction

```bash
make test
make race
make it-phase4-only-all        # 3.2 and 3.4, stock coraza-spoa:0.9.1

# Focused run against an already-up lab:
WAF_PHASE4_ONLY=1 WAF_INTEGRATION=1 \
  go test -tags=integration ./integration -run '^TestStockResponseBodyPhase4' -count=1 -v
```

The lab used for the measurements below used alternate host ports because another compose
lab owned 18080/8081/9000; no body contents were logged. Only `res.body_len` (a sample
fetch returning a byte count) was exposed via a temporary `X-Diag-Res-Body-Len` response
header in a throwaway HAProxy config under `/tmp/opencode/wafbody/haproxy-diag/` (not
committed). That length is the body handed to Coraza in the `body=` argument of
`spoe-message coraza-res`.

## Evidence: body length at SPOE call time

`SecResponseBodyLimit 131072`, default HAProxy `tune.bufsize`, stock image 0.9.1.
"len" = `res.body_len`; denied responses have no diagnostic header.

| Origin endpoint | Body shape | Before `wait-for-body` | After `wait-for-body` |
|---|---|---|---|
| `/phase4-body-control` | prompt, 22 B, no marker | len 22, **200** | len 22, **200** |
| `/phase4-body-marker` | prompt, marker | **403** `waf-block: response` | **403** `waf-block: response` |
| `/phase4-body-delayed` | headers flushed, body after 250 ms | len 0, **200** (bypass) | **403** `waf-block: response` |
| `/phase4-body-chunked` | marker split across two flushed writes, 250 ms apart | len 20, **200** (bypass) | **403** `waf-block: response` |
| `/phase4-body-large-early` | 200 kB, marker in first bytes | **403** `waf-block: response` | **403** `waf-block: response` |
| `/phase4-body-large-late` | 200 kB, marker after 200 kB padding | len 8022 (3.2), **200** (bypass) | len 15105 (3.2) / 15113 (3.4), **200** (bypass) |

The same outcomes were observed on `haproxy:3.2.0` and `haproxy:3.4.0`. Removing the
`SecResponseBodyMimeType` line makes `/phase4-body-marker` return 200 again (verified red),
so the MIME line is a regression guard, not incidental. Removing `wait-for-body` makes the
delayed and chunked cases return 200 again (verified red).

## Supported scope and exact limitation

- **Supported:** phase-4 inspection of the response-body bytes HAProxy has buffered when
  `coraza-response-sync` runs, for MIME types listed in `SecResponseBodyMimeType`, on paths
  marked `txn.wafguard.res_insp`. `wait-for-body` waits up to 500 ms for the body; a body
  arriving later makes HAProxy answer 504, not a WAF verdict.
- **Positive control:** a marker within the buffered prefix is denied (403 `waf-block: response`) on both HAProxy 3.2.0 and 3.4.0 for prompt, delayed and chunked bodies.
- **Negative limitation:** a marker beyond the buffered prefix is not blocked (200) on both releases; this is the measured marker-beyond-buffer case, not a verdict-application bug.
- **Operator example:** `deploy/operator/haproxy/res-inspect-paths.lst` sets the inspected URL prefixes and `SecResponseBodyMimeType` in `deploy/operator/coraza-spoa.yaml` sets the inspected MIME types; neither uses a fixture route as a production feature.
- **Not guaranteed:** full-response coverage. A response larger than HAProxy's buffer is
  truncated before it reaches Coraza (measured ~15 kB of a 200 kB body with default
  `tune.bufsize`). A marker after that prefix is **not blocked** and the client receives
  200. Do not claim guaranteed blocking of arbitrary response bodies.
- **Also out of scope:** bodies whose Content-Type is not in `SecResponseBodyMimeType`,
  `http-after-response` SPOE calls (not available in 3.2/3.4), and responses that exceed
  the 500 ms wait.

## Concrete buffering integration option for full-body coverage

To cover bodies larger than the buffer without touching Coraza, put a buffering reverse
proxy between HAProxy and the origin and size HAProxy's channel to match:

1. Origin path: `client -> HAProxy -> buffering proxy -> origin`. Configure the proxy
   (e.g. NGINX) with `proxy_buffering on; proxy_buffer_size 1m; proxy_buffers 8 1m;`
   so HAProxy receives one complete, `Content-Length`-delimited response.
2. In HAProxy `global`, set `tune.bufsize` to at least the maximum body to inspect
   (measured: with `tune.bufsize 65536`, `res.body_len` for the 200 kB fixture rose from
   ~15 kB to 64257 bytes). On 3.4, `tune.bufsize.large` plus
   `http-response wait-for-body time 500 use-large-buffer` can avoid raising the global
   buffer for every connection.
3. Bound `SecResponseBodyLimit` and the wait timeout to the same maximum, and fail closed
   for bodies above it (deny/observe per deployment mode) instead of relying on partial
   inspection.

This trades memory and added latency for deterministic full-body coverage; it is a
deployment option, not enabled in the default compose lab.

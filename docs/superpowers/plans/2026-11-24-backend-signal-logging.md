# Backend Signal Logging Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Log every policy counter increment and add 401/404 backend signals with higher thresholds; 5xx log-only.
**Architecture:** Return structured signals from observe.lua and log them in Go; add one scanner zset key.
**Tech Stack:** Redis Lua (gopher-lua via miniredis in tests), Go 1.27.4.
**Spec:** `docs/superpowers/specs/2026-11-24-backend-signal-logging.md`

## Global Constraints
- 401 uses brute zset with `rid` member so it cannot double-count with auth-failure counting.
- 404 uses a new scanner zset; thresholds come from `scanner_responses`/`scanner_window_sec`.
- 500–504 must never set a ban key; log only.
- All new thresholds default above the WAF threshold of 3 per 30s.
- Existing `ban issued` / `ban would fire` lines must keep working.

## Review Focus
- A request with both auth failure and 401 must not be counted twice in the brute zset.
- Signals must still be logged when a ban happens (no early return before collection).
- 5xx on an otherwise clean IP must not create any ban key.
- Empty/absent origin_status must not create phantom signals.

---

### Task 1: Lua signal collection and new counters
**Files:** Modify `internal/state/scripts/observe.lua`

- [ ] **Step 1: Add `signals` table, `emit(reason,count,threshold)`, `bump(key,window,threshold,reason)` and `finish()` helpers; all return paths go through `finish()` or `{status,''}`.**
- [ ] **Step 2: Replace the early-return brute ban with `bump(KEYS[8], ...)` plus deferred `maybeBan`.**
- [ ] **Step 3: Add 401 → brute bump, 404 → `bump(KEYS[12],...)`, 5xx → `emit('backend_5xx', status, 0)`.**
- [ ] **Step 4: Keep WAF deny counting and emit `waf_deny` with count/threshold.**

### Task 2: Go wiring and logging
**Files:** Modify `internal/state/redis.go`

- [ ] **Step 1: Add scanner key helper and pass `KEYS[12]`, `ARGV[19]`, `ARGV[20]` to the script.**
- [ ] **Step 2: Parse `{status, banReason, signals...}` and log `counter +1` / `backend_5xx` / `ban issued` / `ban would fire`.**

### Task 3: Tests (RED then GREEN)
**Files:** Modify `internal/state/redis_test.go`

- [ ] **Step 1: Write a test feeding WAF deny events with `origin_status` 401, 404 and 500 and assert the log lines with reasons.**
- [ ] **Step 2: Run RED, then GREEN after Tasks 1–2.**
- [ ] **Step 3: Run the existing ban/shadow tests to prove the return-shape change did not regress them.**

### Task 4: Verification
- [ ] **Step 1: Run `make lint`, `make vet`, `make test`.**
- [ ] **Step 2: Confirm no ban key is written for a 500-only event.**

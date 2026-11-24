# Log Levels Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Add info/debug log levels with info as default.
**Architecture:** Small atomic-level wrapper over stdlib log; config field selects level at startup.
**Tech Stack:** Go 1.27.4 stdlib only.
**Spec:** `docs/superpowers/specs/2026-11-24-log-levels.md`

## Global Constraints
- Default info; `log_level: "debug"` enables per-request lines.
- No new dependency; keep existing log output format and `log.SetOutput` test capture.
- Startup, counter, ban, backend 5xx, and all non-ok SPOE results stay at info.
- Unknown level values fall back to info.

## Review Focus
- Tests must restore the previous level to avoid cross-test leakage.
- A failed SPOE request must still be visible at info.
- `ban issued` must carry the crossing count/threshold.

---

### Task 1: logging package (RED then GREEN)
**Files:** Create `internal/logging/logging.go`, `internal/logging/logging_test.go`

- [ ] **Step 1: Write a test asserting `Debugf` is silent at info and visible at debug, and `Infof` is always visible. Run RED.**
- [ ] **Step 2: Implement atomic level, `ParseLevel`, `SetLevel`, `Infof`, `Debugf`. Run GREEN.**

### Task 2: Wire config and call sites
**Files:** Modify `cmd/wafguard/main.go`, `internal/spoa/handler.go`, `internal/state/redis.go`

- [ ] **Step 1: Add `LogLevel` to `fileConfig`; call `logging.SetLevel(logging.ParseLevel(fc.LogLevel))` first in `run()`.**
- [ ] **Step 2: Replace startup/listener/admin lines with `logging.Infof`; keep `log.Fatal`.**
- [ ] **Step 3: In `HandleSPOE`, emit the per-request line at `Debugf` and add an `Infof` for `result != "ok"`.**
- [ ] **Step 4: Replace counter/ban/backend lines with `logging.Infof`; add count/threshold to `ban issued`.**
- [ ] **Step 5: Update tests that assert the `spoe` line to set debug level.**

### Task 3: Docs and verification
- [ ] **Step 1: Add `log_level` to README config table.**
- [ ] **Step 2: Run `make lint`, `make vet`, `make test`.**

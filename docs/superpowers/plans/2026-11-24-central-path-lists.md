# Centralised Path Lists Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Drive req/res/observe inspection flags from Redis config via the check-ban ACK instead of local HAProxy files.
**Architecture:** Path prefix lists in policy.Config; Store.Check sets flags on Decision; ACK writes them as HAProxy transaction vars.
**Tech Stack:** Go 1.27.4, Redis Lua, HAProxy SPOE.
**Spec:** `docs/superpowers/specs/2026-11-24-central-path-lists.md`

## Global Constraints
- Empty/absent lists = feature disabled (current default).
- Prefix semantics must match HAProxy `path -m beg`.
- No new Redis keys, no new per-request network calls, no HAProxy reload on changes.
- Admin PUT policy must be able to update the lists.

## Review Focus
- A path matching two lists must set both flags.
- A stale/invalid policy config must not silently disable inspection — keep fail-closed error.
- HAProxy must not depend on any `.lst` file after the change.

---

### Task 1: Config + domain types
**Files:** `internal/policy/policy.go`, `internal/event/event.go`

- [ ] **Step 1: Add `ReqInspectPaths`, `ResInspectPaths`, `ObserveResponsePaths` (`[]string`, omitempty) to `policy.Config`; leave defaults empty.**
- [ ] **Step 2: Add `policy.PathMatches(path string, prefixes []string) bool` using `strings.HasPrefix`.**
- [ ] **Step 3: Add three bool fields to `event.Decision`.**

### Task 2: Store.Check sets flags
**Files:** `internal/state/redis.go`

- [ ] **Step 1: In `Check`, after parsing `rev`, call `appCfgAt(ctx, app, rev)` and set the three Decision booleans from `PathMatches(cfg.*, req.Path)`. Run RED first via a test.**

### Task 3: ACK writes HAProxy vars
**Files:** `internal/spoa/decode.go`

- [ ] **Step 1: In `writeAdmissionACK`, set `req_insp`, `res_insp`, `observe_response` to `"1"` when the corresponding Decision bool is true. Test the encoded ACK contains the var names.**

### Task 4: HAProxy + docs cleanup
- [ ] **Step 1: Remove the three ACL and three set-var lines from `deploy/operator/haproxy/haproxy.cfg`.**
- [ ] **Step 2: Delete the three `.lst` files; update validate script, runbook and README to use admin PUT.**

### Task 5: Verification
- [ ] **Step 1: `make lint`, `make vet`, `make test`, `goreleaser check`.**
- [ ] **Step 2: `grep -rn 'inspect-paths\|observe-response-paths'` returns no active references.**

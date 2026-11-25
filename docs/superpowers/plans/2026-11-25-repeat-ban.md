# Repeat Ban Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Escalate a repeat offender's ban to 30 days and expose ban reason.
**Architecture:** Ban history zset + ban info hash in observe.lua; config-driven thresholds; richer BanInfo.
**Tech Stack:** Redis Lua, Go 1.27.4.
**Spec:** `docs/superpowers/specs/2026-11-25-repeat-ban.md`

## Global Constraints
- First ban stays `waf_deny_ban_sec` (default 900s).
- Second ban within 7 days gets `repeat_ban_ttl_sec` (default 30 days).
- Ban key value stays numeric so check.lua needs no change.
- Unban must not clear ban history.

## Review Focus
- History must survive unban so escalation still applies later.
- Count/threshold must be reported in the ban log and in `ban list`.
- Expired history entries must be trimmed.

---

### Task 1: Config fields
- [ ] **Step 1: Add `repeat_ban_threshold`, `repeat_ban_window_sec`, `repeat_ban_ttl_sec` to policy.Config with defaults and validation. Test.**

### Task 2: Lua escalation
- [ ] **Step 1: Add KEYS[13] history zset, KEYS[14] info hash; ARGV[21..23] threshold/window/repeat_ttl.**
- [ ] **Step 2: On each ban, record history, compute count and ttl, write info hash, return reason/count/ttl/repeat.**
- [ ] **Step 3: Go passes new keys/args and logs the richer ban line.**

### Task 3: Read path
- [ ] **Step 1: Extend `BanInfo` with Reason/BanCount; `BannedIPs` reads info hash. Test.**
- [ ] **Step 2: `wafctl ban list` prints reason/count (generic printer is fine).**

### Task 4: Verification
- [ ] **Step 1: `make lint`, `make vet`, `make test`, `goreleaser check`.**
- [ ] **Step 2: Test 2 bans within window => 30-day TTL; first ban => 900s.**

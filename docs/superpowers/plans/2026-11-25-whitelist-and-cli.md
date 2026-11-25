# Whitelist and CLI Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Add IP/CIDR whitelist to policy and a Go CLI over the admin API.
**Architecture:** policy.Config holds whitelist; Check/Observe short-circuit; admin API gains read + whitelist endpoints; wafctl wraps them.
**Tech Stack:** Go 1.27.4 stdlib, netip, net/http.
**Spec:** `docs/superpowers/specs/2026-11-25-whitelist-and-cli.md`

## Global Constraints
- Whitelist entries are IP or CIDR strings, per app, in existing policy config.
- Whitelisted requests: allow, no counters, no ban; Coraza still inspects.
- Whitelist writes must go through SetPolicy (CAS + fence), never raw Redis.
- CLI uses admin HTTP API only; no direct Redis.

## Review Focus
- CIDR must match correctly for both IPv4 and IPv6.
- Whitelisted event must still carry an Admission so waf-verdict is not dropped.
- CAS conflicts must surface to the CLI as a clear error.

---

### Task 1: Domain whitelist
**Files:** `internal/policy/policy.go`, `internal/event/event.go`, `internal/state/redis.go`
- [ ] **Step 1: Add `WhitelistIPs` to Config and `IPInList(ip, entries)` with netip prefix/addr parsing. Test RED then GREEN.**
- [ ] **Step 2: Add `Whitelisted bool` to Decision.**
- [ ] **Step 3: In `Check`, load app config first; whitelisted → allow with synthetic Admission and `Whitelisted=true`. Test.**
- [ ] **Step 4: In `Observe`, return early for whitelisted IP. Test.**

### Task 2: Admin API
**Files:** `internal/state/redis.go`, `internal/admin/handler.go`
- [ ] **Step 1: Add `Store.Policy(ctx, app) (Config, uint64, Mode, error)` reading revision/config/mode.**
- [ ] **Step 2: Add GET policy/status/whitelist and POST/DELETE whitelist endpoints; CAS via SetPolicy. Tests with httptest + miniredis.**

### Task 3: CLI
**Files:** `cmd/wafctl/main.go` (+ tests)
- [ ] **Step 1: Implement flag parsing, token resolution (-token / WAFGUARD_TOKEN / .env), HTTP helper.**
- [ ] **Step 2: Implement subcommands: status, policy get, mode get/set, whitelist list/add/remove, unban, inspect.**
- [ ] **Step 3: Tests against httptest server for at least status and whitelist add.**

### Task 4: Docs and verification
- [ ] **Step 1: README section for wafctl and whitelist_ips.**
- [ ] **Step 2: `make lint`, `make vet`, `make test`, `goreleaser check`.**

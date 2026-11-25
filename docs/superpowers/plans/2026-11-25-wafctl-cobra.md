# wafctl v2 Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Cobra-based wafctl with full config/ban/status management.
**Architecture:** Cobra command tree over admin HTTP API; generic config edits via CAS policy PUT.
**Tech Stack:** Go 1.27.4, spf13/cobra, net/http.
**Spec:** `docs/superpowers/specs/2026-11-25-wafctl-cobra.md`

## Global Constraints
- CLI uses admin HTTP API only; no Redis client.
- Config field names are the JSON tags of `policy.Config`.
- All mutations CAS through PUT /policy; server-side validation remains authoritative.
- Existing `-token` / env / `.env` resolution must keep working.

## Review Focus
- Unknown config keys must be rejected before any PUT.
- `config add/del` must not corrupt other fields of the config JSON.
- Ban listing must include expiry and handle an empty result.

---

### Task 1: Cobra dependency + admin ban endpoint
- [ ] **Step 1: `go get github.com/spf13/cobra`.**
- [ ] **Step 2: Add `Store.BannedIPs(ctx, app)` scanning `wg:ban:<app>:*` with TTL. Test.**
- [ ] **Step 3: Add `GET /v1/apps/{app}/bans` to admin handler. Test.**

### Task 2: Rewrite cmd/wafctl with Cobra
- [ ] **Step 1: Root command with persistent flags and env/.env resolution.**
- [ ] **Step 2: HTTP helper + JSON printer shared by commands.**
- [ ] **Step 3: status, config list/get/set/add/del, mode, whitelist, ban list, unban, inspect, metrics.**
- [ ] **Step 4: Tests against httptest server for config set/add and ban list.**

### Task 3: Docs and verification
- [ ] **Step 1: README CLI section rewrite.**
- [ ] **Step 2: `make lint`, `make vet`, `make test`, `goreleaser check`, `make build`.**

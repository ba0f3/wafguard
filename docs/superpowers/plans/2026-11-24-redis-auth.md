# Redis and Sentinel Authentication Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** Make wafguard authenticate to Redis and Sentinel via JSON config.
**Architecture:** Add optional credential fields to the existing config structs and pass them to go-redis option builders; split builders into testable helpers.
**Tech Stack:** Go 1.27.4, `github.com/redis/go-redis/v9` v9.17.2.
**Spec:** `docs/superpowers/specs/2026-11-24-redis-auth.md`

## Global Constraints
- Credentials are plaintext JSON; no env expansion, no new dependency.
- Existing unauthenticated configs must keep working when new fields are empty.
- `redis.username`/`password` feed master auth; `redis.sentinel.username`/`password` feed sentinel auth only.
- Do not change timeouts, `state.New`, Lua scripts, or validation.

## Review Focus
- Sentinel credentials must not be copied onto master auth by mistake, and vice versa.
- Failover client must still receive master credentials.
- Empty credentials must leave existing behaviour unchanged.

---

### Task 1: Config fields and client wiring
**Files:** Modify `cmd/wafguard/main.go`

- [ ] **Step 1: Add `Username`/`Password` json fields to `redisOptions` and to `sentinelOptions`**
- [ ] **Step 2: Extract `newRedisOptions(ro redisOptions) *redis.Options` and `newFailoverOptions(ro redisOptions) *redis.FailoverOptions`, carrying existing timeouts plus master `Username`/`Password`; failover also carries `SentinelUsername`/`SentinelPassword` from `ro.Sentinel`.**
- [ ] **Step 3: Make `newRedisClient` call those helpers so behaviour is unchanged apart from credentials.**

### Task 2: Tests (RED then GREEN)
**Files:** Modify `cmd/wafguard/main_test.go`

- [ ] **Step 1: Write `TestRedisAuthOptions` asserting `newRedisOptions(redisOptions{Addr, Username, Password})` returns those values.**
- [ ] **Step 2: Run it; expected RED because helpers do not exist.**
- [ ] **Step 3: Write `TestFailoverAuthOptions` asserting master and sentinel credentials land on separate fields of `newFailoverOptions(...)`.**
- [ ] **Step 4: Run both; expected RED, then GREEN after Task 1.**
- [ ] **Step 5: Run `make test`.**

### Task 3: Config examples and docs
**Files:** Modify `deploy/wafguard.sentinel.json`, `README.md`

- [ ] **Step 1: Add commented-style placeholder fields (empty strings) to the sentinel example without breaking its validity.**
- [ ] **Step 2: Add the four fields to the README config table, noting plaintext/mount-permission risk.**

### Task 4: Final verification
- [ ] **Step 1: Run `make lint`, `make vet`, `make test`, `goreleaser check`.**
- [ ] **Step 2: Confirm unauthenticated example configs still load.**

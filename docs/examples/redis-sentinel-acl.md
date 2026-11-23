# Redis + Sentinel ACL example for wafguard

These are lab-grade examples. Replace usernames, passwords and addresses before
using them anywhere real. wafguard reads credentials from its mounted JSON
config (`redis.username`/`redis.password`, `redis.sentinel.username`/
`redis.sentinel.password`); it never creates users itself.

## 1. ACL user on the Redis data nodes (master + replicas)

Create the user on **every** Redis node, not just the current master — after a
failover wafguard connects to whichever node Sentinel elects.

```sh
redis-cli -h redis-1 -p 6379 --user default -a '<redis-admin-password>' \
  ACL SETUSER wg ON '>wg-secret' '~wg:*' '&*' \
    +@read +@write +@script +ping +hello +time +client\|setinfo
```

- `~wg:*` matches the namespace hardcoded in `state.New` (`Namespace: "wg"`).
- `+@script` covers `SCRIPT LOAD`/`EVALSHA`, which wafguard uses for its Lua
  scripts; `+time` is needed by `check.lua` (`redis.call('TIME')`).
- Verify: `redis-cli -h redis-1 --user wg -a wg-secret PING` → `PONG`.

To persist instead of doing it at runtime, add the same line to `redis.conf`
(or to the `aclfile`) on every node:

```
user wg on >wg-secret ~wg:* &* +@read +@write +@script +ping +hello +time +client|setinfo
```

## 2. ACL user on each Sentinel node

go-redis only needs discovery/role commands on Sentinel. This is the minimal
set taken from go-redis v9's own `SentinelAclAuth` test:

```sh
redis-cli -h sentinel-1 -p 26379 --user default -a '<sentinel-admin-password>' \
  ACL SETUSER sentinel-user ON '>sentinel-secret' '-@all' \
    +auth +client\|getname +client\|id +client\|setname +client\|setinfo \
    +command +hello +ping +role \
    +sentinel\|get-master-addr-by-name +sentinel\|master \
    +sentinel\|myid +sentinel\|replicas +sentinel\|sentinels
```

Run it on **all** Sentinel nodes. Verify from a client host:

```sh
redis-cli -h sentinel-1 -p 26379 --user sentinel-user -a sentinel-secret \
  SENTINEL get-master-addr-by-name mymaster
```

To persist, add to `sentinel.conf` on every Sentinel:

```
user sentinel-user on >sentinel-secret -@all +auth +client|getname +client|id +client|setname +client|setinfo +command +hello +ping +role +sentinel|get-master-addr-by-name +sentinel|master +sentinel|myid +sentinel|replicas +sentinel|sentinels
```

Note: `SENTINEL` subcommand permissions use the `+sentinel|<subcommand>` form —
`+sentinel` alone is too broad (it also grants `SENTINEL SET`, which lets a
client rewrite Sentinel configuration).

## 3. wafguard config

```json
{
  "version": 1,
  "spop_listen": "0.0.0.0:12345",
  "metrics_listen": "0.0.0.0:9090",
  "default_mode": "observe",
  "redis": {
    "db": 0,
    "username": "wg",
    "password": "wg-secret",
    "sentinel": {
      "master_name": "mymaster",
      "addrs": ["sentinel-1:26379", "sentinel-2:26379", "sentinel-3:26379"],
      "username": "sentinel-user",
      "password": "sentinel-secret"
    }
  },
  "limits": { "max_inflight": 256, "allowed_apps": ["sample_app"] }
}
```

`db` selects a database on the **master**, not on Sentinel. Keep the mounted
config file private — these credentials are plaintext.

## 4. Startup check

On start, wafguard logs either `redis ok target=...` or
`redis ping failed target=... err=... (continuing; requests will degrade)`.
An ACL mistake shows up there. If Redis accepts the connection but the ACL
denies a Lua command, you instead see `result=observe_error` on `waf-verdict`
lines with the underlying reason in `reason=`.

Check Sentinel-side denials with `redis-cli ... LATENCY DOCTOR`/`INFO stats`
on the Sentinel node, or the Redis log: `ACL DENIED`.

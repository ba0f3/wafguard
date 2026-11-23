# haproxy-waf-spoe (wafguard)

Go SPOA for HAProxy: combines **upstream Coraza SPOA v0.9.1** verdicts with cross-request behavioral policy in Redis.

## Quick start (lab)

```sh
make compose-config
make compose-up
export WAF_INTEGRATION=1
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/ok
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/marker-deny
make it-stock HAPROXY_SERIES=3.2
```

See [docs/runbooks/rollout.md](docs/runbooks/rollout.md) for shadow/enforce and rollback.

## Build & test

```sh
go build -o bin/wafguard ./cmd/wafguard
make test
make race
```

Design: [docs/specs/2026-11-23-haproxy-waf-spoe-design.md](docs/specs/2026-11-23-haproxy-waf-spoe-design.md)


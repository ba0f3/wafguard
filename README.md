# haproxy-waf-spoe (wafguard)

Go SPOA for HAProxy: combines **upstream Coraza SPOA v0.9.1** verdicts with cross-request behavioral policy in Redis.

## Quick start (lab)

```sh
make compose-config
make compose-up
export WAF_INTEGRATION=1 HAPROXY_PORT=18080
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18080/ok
curl -s -o /dev/null -w "%{http_code}\n" -H 'User-Agent: fixture-deny-request' http://127.0.0.1:18080/ok
make it-stock HAPROXY_SERIES=3.2
```

See [docs/runbooks/rollout.md](docs/runbooks/rollout.md) for shadow/enforce and rollback.

## Build & test

```sh
go build -o bin/wafguard ./cmd/wafguard
make test
make race
```

Run `make fuzz` to exercise SPOE event decoding, metrics labels, admin policy requests, and Coraza log parsing with Go's native fuzzer. The default is 15 seconds per target with two workers. For a longer run, use `make fuzz FUZZ_TIME=5m FUZZ_WORKERS=4`. The seed cases also run under `make test`. The fuzzer runs in process and uses miniredis for the admin tests.

The admin API accepts one JSON document per mutation request, up to 64 KiB. Requests over the limit return HTTP `413`.

Design: [docs/specs/2026-11-23-haproxy-waf-spoe-design.md](docs/specs/2026-11-23-haproxy-waf-spoe-design.md)


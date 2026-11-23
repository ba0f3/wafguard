# HAProxy WAF SPOE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xây dựng Go SPOA đọc verdict từ Coraza nguyên bản, phát hiện hành vi qua nhiều HTTP request và áp dụng ban có thời hạn trên toàn cụm HAProxy.

**Architecture:** HAProxy tạo UUID, gọi precheck trước Coraza và gửi observation tại các điểm đã định trong HTTP lifecycle. Go SPOA xác thực event và thực hiện policy bằng một giao dịch Redis trên primary trước khi ACK. Admin quản lý policy revision, trạng thái observe và enforce, exemption và unban qua Unix socket.

**Tech Stack:** Go, HAProxy SPOE/SPOP, Coraza SPOA, Redis primary/Sentinel, Lua, Prometheus, Docker Compose.

**Spec:** [docs/specs/2026-11-23-haproxy-waf-spoe-design.md](../../specs/2026-11-23-haproxy-waf-spoe-design.md)

## Global Constraints

- Coraza `corazawaf/coraza-spoa` **v0.9.1**, commit `c9b34f409e04cfb60219602bd1ad711afd15eaa3`. **Chỉ dùng binary/image Coraza upstream nguyên bản.**
- Các biến thuộc namespace `txn.coraza.*`. Dịch vụ mới chỉ trả biến của mình dưới `txn.wafguard.*`.
- P0 dùng Redis primary/Sentinel cho quyết định chung, không local cache. P0 không native Redis Cluster.
- HAProxy **3.2.0** là mốc tái kiểm tra routing. Gate tương thích chạy Coraza thật với HAProxy **3.2** và build/runtime riêng với **3.4**.
- Giữ `app` là argument đầu theo contract upstream. Bật tùy chọn `exportRuleIDs=true` khi cần danh sách best-effort.
- Chuẩn hóa IP bằng `netip.Addr.Unmap`, mặc định /32 hoặc /128.
- Không gửi body, token, cookie hoặc mật khẩu vào behavioral core.
- Counter update và ban mới phải commit atomic trước ACK. Không tuyên bố exactly-once ngoài dedupe retention.
- Observe dùng state riêng, không ảnh hưởng enforcement. Khi service/Redis timeout, mặc định continue Coraza và báo degraded.
- Mặc định scope application. Escalation có trần và decay. 5xx đơn lẻ hoặc tăng theo backend chỉ tạo cảnh báo.

## Review Focus

- HTTP/2 multiplex và HTTP/1.1 keep-alive phải giữ UUID, identity và verdict riêng cho từng stream. Task 1, `TestStockStreamIsolation`.
- Precheck mất ACK nhưng Coraza có verdict hợp lệ thì request vẫn theo Coraza. Event thiếu admission chỉ ghi telemetry. Task 2, `TestMissingAdmission`.
- Redis timeout sau commit và retry qua replica khác vẫn giữ một contribution và một thời điểm hết hạn. Task 3, `TestLostCommitReply`.
- Auth failure HTTP 200 có receipt đến trước observation vẫn chỉ tăng một lần. Task 4, `TestAuthReceiptOrdering`.
- Event đang chờ response qua hai lần đổi mode phải bị fence kể cả khi mode mới trùng mode lúc admission. Task 5, `TestModeRevisionFence`.

---

## Cấu trúc và phạm vi

| File hoặc thư mục | Trách nhiệm |
|---|---|
| `deploy/haproxy/{haproxy.cfg,coraza.cfg,wafguard.cfg}`, `integration/{compose.yaml,images.env,stock_test.go,testorigin/,recorder/}`, `Makefile`, `go.mod`, `go.sum` | Wiring HTTP/SPOE, origin kiểm thử, recorder và CI entry point cho stock Coraza. |
| `internal/event/{event.go,event_test.go}`, `internal/spoa/{handler.go,handler_test.go}` | Kiểu dữ liệu v1, validation biên SPOP, ACK. |
| `internal/state/{redis.go,redis_test.go,scripts/}`, `internal/policy/{policy.go,policy_test.go}`, `deploy/wafguard.example.json` | Admission, TTL, ban, atomic update và policy theo app. |
| `internal/admin/{handler.go,handler_test.go}`, `cmd/wafguard/{main.go,main_test.go}`, `internal/telemetry/{metrics.go,metrics_test.go}` | Admin, cấu hình runtime, process lifecycle và telemetry. |
| `integration/{rollout_test.go,load_test.go}`, `docs/runbooks/rollout.md` | Acceptance gate, cách đo trên topology thật, shadow và rollback. |
| `internal/enrich/{coraza.go,coraza_test.go}`, `docs/runbooks/enrichment.md` | Tích hợp log tùy chọn sau P0. Core chạy đầy đủ khi tắt adapter. |

Task 1–7 là một kế hoạch P0 vì event contract, atomic state và enforcement dùng chung admission. Task 8 có thể thực hiện riêng sau P0. Giữ structured HAProxy syslog và P2 maps là các mốc có điều kiện ở cuối kế hoạch.

Go module dùng `github.com/ba0f3/haproxy-waf-spoe`, Go floor `1.25.7`, `github.com/dropmorepackets/haproxy-go v0.1.1` theo upstream. Task 3 pin `github.com/redis/go-redis/v9 v9.17.2`. Task 6 pin `github.com/prometheus/client_golang v1.24.1`. Đây là điểm xuất phát của plan. Chạy lại gate liên quan trước khi đổi pin. [Coraza go.mod tại commit baseline](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/go.mod) · [go-redis v9.17.2](https://github.com/redis/go-redis/releases/tag/v9.17.2).

## P0.1 · Contract với Coraza nguyên bản

### Task 1: HAProxy wiring và stock integration

**Files**

- Tạo `go.mod`, `go.sum`, `Makefile`, `deploy/haproxy/{haproxy.cfg,coraza.cfg,wafguard.cfg}`, `integration/{compose.yaml,images.env,stock_test.go,testorigin/main.go,recorder/main.go}`, `integration/fixtures/{coraza.yaml,coraza-rules.conf}`.

**Interfaces**

- Produces: HTTP SPOE groups `check-ban`, `waf-verdict`, `observe-response` và nhóm Coraza explicit `coraza-response-sync`. Đặt tên message behavioral giống group. Recorder task này chỉ đọc UUID, identity, request snapshot và status. Task 2 hoàn thiện wire v1. Giữ message names `coraza-req`, `coraza-res`.
- Produces: `make it-stock HAPROXY_SERIES=3.2` và `make it-stock HAPROXY_SERIES=3.4`. Mỗi lệnh chạy `haproxy -c` và `go test -tags=integration ./integration -run '^TestStock' -count=1` với topology của series tương ứng. Fixture origin có `/status/404`, `/status/500`, `/ok`, `/echo` và fixture status 200 có response marker. Recorder chỉ thay behavioral SPOA và ghi event theo UUID. Gate bắt buộc fail nếu thiếu container hoặc test nào skip.

- [ ] Viết các case trong `TestStockLifecycle`, `TestStockStreamIsolation` và `TestStockBodyAndAffinity`. Dùng rule SecLang fixture khớp marker vô hại của riêng test trong header, path, body hoặc response. Dùng transport disconnect làm fixture Coraza error. `calls` là tên group recorder nhận theo một UUID và `snapshot` là request verdict recorder nhận.

  ```go
  // TestStockLifecycle
  require.Equal(t, []string{"check-ban", "waf-verdict"}, denied.calls)
  require.Equal(t, 403, denied.clientStatus)
  require.Zero(t, dropped.originHits)
  require.Equal(t, "drop", dropped.snapshot.Action)
  require.Equal(t, 500, corazaError.clientStatus)
  require.True(t, corazaError.snapshot.InspectionError)
  require.Equal(t, 200, detectionOnly.clientStatus)
  require.Equal(t, "hypothetical", detectionOnly.snapshot.Source)
  require.Nil(t, exportOff.snapshot.RuleIDs)
  require.Equal(t, forcedUUID, correlated.corazaID)
  require.Equal(t, 404, origin404.originStatus)
  require.Equal(t, 500, origin500.originStatus)
  require.Equal(t, 0, statusOnly.corazaResCalls)
  require.Equal(t, 1, responseDeny.corazaResCalls)
  require.Equal(t, 200, responseDeny.originStatus)
  require.Equal(t, 403, responseDeny.clientStatus)
  require.Nil(t, responseDeny.spoeFinalStatus)
  require.Equal(t, "allow", responseDeny.snapshot.Action)
  ```

  Dùng `require` ở đây làm ký hiệu assertion cho cả plan. Triển khai bằng `testing` hoặc helper của test đang viết, không cần dependency test mới. Với local 503 do kết nối backend thất bại, assert client status 503 và `calls == ["check-ban", "waf-verdict"]`. Với redirect, assert 302 và `waf-verdict` đến trước terminal action. Chạy thêm deny marker khi recorder ngắt kết nối tại precheck và khi ngắt tại verdict, assert Coraza vẫn chặn trong cả hai case. Inject một Coraza value cũ hồi đầu request và hồi trước response trong fixture test. Assert reset làm mất action, error và optional values cũ, còn request snapshot và Coraza ID giữ nguyên qua response. Trace SPOE chỉ trong fixture để đếm message stock; assert `app` ở index 0 cho cả hai phase.

  ```go
  // TestStockStreamIsolation, chạy lại trên HTTP/1.1 và HTTP/2
  require.NotEqual(t, first.requestID, second.requestID)
  require.NotEqual(t, clientSuppliedID, first.requestID)
  require.Equal(t, first.requestID, first.corazaID)
  require.Equal(t, second.requestID, second.corazaID)
  require.Equal(t, 403, first.clientStatus)
  require.Equal(t, 200, second.clientStatus)
  require.Equal(t, socketPeer, spoofedForwarding.clientIP)
  require.Equal(t, configuredClient, trustedOverwrite.clientIP)

  // TestStockBodyAndAffinity
  require.Equal(t, 403, bannedExpectBeforeBody.status)
  require.False(t, bannedExpectBeforeBody.corazaCalled)
  require.Equal(t, 403, allowedPrecheckBodyMarker.status)
  require.Equal(t, 408, incompleteBody.status)
  require.False(t, incompleteBody.originReached)
  require.Equal(t, requestCorazaInstance, responseCorazaInstance)
  require.True(t, forcedAffinityMiss.snapshot.InspectionError)
  ```

  Trường `forcedAffinityMiss.snapshot` ở đây là verdict response. Mô phỏng peer trusted gửi nhiều giá trị forwarded hoặc IP lỗi rồi assert fallback về socket peer. Thêm case IP IPv4-mapped, Host ngoài allowlist và response async. Assert identity Coraza và detector trùng nhau, Host lạ đi qua WAF với app fallback đã cấu hình nhưng không mở namespace mới, và async chỉ gửi origin status cùng request snapshot.

- [ ] Chạy `make it-stock HAPROXY_SERIES=3.2`. Red phải chỉ ra topology hoặc rule contract còn thiếu. Ghi rõ lỗi setup trước khi đánh giá assertion.
- [ ] Tạo topology với bản official Coraza pin digest hoặc build từ checkout sạch tại commit baseline cùng toolchain và dependency lock của upstream. Ghi digest HAProxy cho từng series vào `integration/images.env`, chạy thêm `3.2.0` để tái kiểm tra routing. Chọn explicit response group, bỏ event binding của `coraza-res`, gửi response vào cùng instance với request qua cùng lựa chọn backend cố định theo transaction. Dùng `uuid(4)` cho `txn.wafguard.request_id`, truyền UUID vào stock argument `id` và truyền client IP canonical vào `src-ip`. Giữ client IP hành vi, WAF và Redis đồng nhất. Phần request chạy `check-ban → wait-for-body → coraza-req → snapshot → waf-verdict → terminal`. Khi precheck trả ban hoặc throttle, đánh dấu own rejection và kết thúc bằng 403 hoặc 429 trước buffering. Phần response chạy `origin_status → reset → coraza-response-sync → observe-response → terminal`. Profile status-only bỏ group Coraza response. Dùng configured WAF mode để áp dụng verdict và tag `enforced`, `hypothetical`, `error` hoặc `unknown`. Chỉ đánh dấu clean allow khi stock trả `txn.coraza.id` trùng UUID và phase không có Coraza error; với response giữ ID để correlation và dùng kết quả transport riêng. Đăng ký các biến ACK qua `register-var-names`. Dùng `option set-on-error` riêng cho từng engine và reset biến lỗi theo phase. Phase reset unset `action,status,data,ruleid,error,rules_hit,anomaly_score,rule_ids`; giữ `id` và request snapshot qua response. Lưu snapshot tại HAProxy để khi behavioral agent mất kết nối, stock Coraza vẫn áp dụng đúng verdict. [Stock SPOE config](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/example/haproxy/coraza.cfg) · [Stock agent](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/internal/agent.go) · [HAProxy 3.2](https://docs.haproxy.org/3.2/configuration.html) · [HAProxy 3.4](https://docs.haproxy.org/3.4/configuration.html).
- [ ] Chạy `make it-stock HAPROXY_SERIES=3.2`, `make it-stock HAPROXY_SERIES=3.4` và `make it-stock HAPROXY_SERIES=3.2.0`. Pass khi hai binary thực đều qua runtime assertions, kể cả bật và tắt response inspection. Ghi lỗi về cache affinity, buffering hoặc semantics stock vào kết quả gate nếu gặp.
- [ ] Commit `test: verify stock Coraza SPOE lifecycle`.

## P0.2 · Core và shared state

### Task 2: Event v1 và SPOP adapter

**Files**

- Tạo `internal/event/{event.go,event_test.go}`, `internal/spoa/{handler.go,handler_test.go}`. Sửa `deploy/haproxy/{haproxy.cfg,wafguard.cfg}` và `integration/recorder/main.go` để cùng dùng tên argument v1.

**Interfaces**

- Produces: `event.Request` gồm `SchemaVersion uint16`, `NodeID, RequestID, Application, Backend, Method, Path, RouteGroup string`, `ClientIP, PeerIP netip.Addr`. `event.Admission{Generation string, At time.Time, Revision uint64, Mode event.Mode}`. `event.Event{Request event.Request, ID string, Kind event.Kind, Phase event.Phase, Admission *event.Admission, RequestWAF event.Verdict, ResponseWAF *event.Verdict, OriginStatus, FinalClientStatus *int, OwnRejection bool}`.
- Produces: `event.Verdict` gồm `Action, Source string`, `InspectionError bool`, `RuleID, RulesHit, AnomalyScore *int64`, `RuleIDs []uint32` với `nil` là absent. `event.Decision` gồm `Action event.Action`, `Admission *event.Admission`, `ExpiresAt time.Time`, `Degraded bool`. `Action` nhận `unknown`, `allow`, `ban`, `throttle`. `Mode` nhận `observe` hoặc `enforce`.
- Produces: `spoa.NewHandler(backend spoa.Backend, limits event.Limits) *spoa.Handler`. `spoa.Backend` có `Check(context.Context, event.Request) (event.Decision, error)` và `Observe(context.Context, event.Event) error`. Handler triển khai `HandleSPOE(context.Context, *encoding.ActionWriter, *encoding.Message)`.

- [ ] Viết `TestWireV1`, `TestInvalidWire`, `TestMissingAdmission` với SPOP message thực và backend giả.

  ```go
  require.Equal(t, netip.MustParseAddr("192.0.2.8"), decoded.Request.ClientIP)
  require.Equal(t, "waf-verdict", string(decoded.Kind))
  require.Equal(t, decoded.ID, retriedOnOtherReplica.ID)
  require.Nil(t, decoded.RequestWAF.AnomalyScore)
  require.Equal(t, int64(0), *observedZero.RequestWAF.AnomalyScore)
  require.Nil(t, decoded.FinalClientStatus)
  require.Equal(t, "unknown", string(timeoutACK.Action))
  require.True(t, timeoutACK.Degraded)
  require.Nil(t, timeoutACK.Admission)
  require.Zero(t, missingAdmissionBackend.observeCalls)
  ```

  Invalid cases gồm version 2, UUID thiếu/sai, app ngoài config, phase/kind sai cặp, status ngoài 100–599, rule IDs quá giới hạn, forwarding IP có zone và metadata chứa control character. Assert `observeCalls == 0` và reason telemetry tương ứng. Gửi `path=/ok?secret=fixture` và assert backend không nhận query. Kiểm tra ACK sau một `Observe` bị giữ bằng channel chỉ xuất hiện sau khi backend trả thành công hoặc timeout.

- [ ] Chạy `go test ./internal/event ./internal/spoa -run 'Test(WireV1|InvalidWire|MissingAdmission)' -count=1`. Red vì type, decoder hoặc assertions chưa qua.
- [ ] Dùng `schema_version=1` và argument snake_case từ struct. Ba group lần lượt dùng phase `admission`, `request`, `response`. Event ID do handler tạo từ tuple `application, request_id, kind` bằng encoding có độ dài cho mỗi phần. Truyền `admission_at_ms`, `admission_generation`, `policy_revision`, `behavior_mode` từ ACK precheck qua transaction. ACK precheck chỉ ghi namespace `txn.wafguard.*`. WAF observation ACK chỉ ghi kết quả xử lý và degraded, giữ nguyên action precheck. Wire cho WAF verdict dùng prefix `request_waf_` và `response_waf_`. Chỉ truyền metadata từ mục 6 của spec, thêm `backend` đã map để outage guard dùng. Đặt `path` ở HAProxy từ path bỏ query và loại các đoạn chứa credential theo route config. Bỏ `coraza.data` trên wire behavioral. Đặt `max-frame-size 16380` trong behavioral SPOE agent và chỉ cho các peer HAProxy nội bộ đã cấu hình kết nối. SPOP library v0.1.1 nhận giới hạn frame từ peer, nên giới hạn này phụ thuộc vào transport và cấu hình HAProxy. Cap path 1 KiB, tối đa 64 rule IDs, trường danh mục 64 byte và chỉ nhận UUID v4. Giới hạn dữ liệu trước khi copy metadata vào event. Trường giới hạn và app/backend allowlist thuộc `event.Limits`. Unknown hoặc timeout giữ `unknown`, thiếu admission chỉ ghi telemetry và tiếp tục xử lý theo Coraza. SPOE origin status luôn dùng trường riêng với final status.
- [ ] Chạy command ở bước red và `make it-stock HAPROXY_SERIES=3.2`. Pass khi test decoder và wire fixture dùng đúng argument v1, timeout vẫn tiếp tục Coraza.
- [ ] Commit `feat: validate behavioral SPOE events`.

### Task 3: Redis admission, dedupe và atomic WAF-deny

**Files**

- Tạo `internal/state/{redis.go,redis_test.go,scripts/check.lua,scripts/observe.lua}`. Sửa `go.mod`, `go.sum`, `integration/{compose.yaml,images.env}`, `Makefile`.

**Interfaces**

- Consumes: `event.Request`, `event.Event`, `spoa.Backend` từ Task 2.
- Produces: `state.New(client redis.UniversalClient, cfg state.Config) (*state.Store, error)`. `*state.Store` implements `spoa.Backend`. `Config` gồm namespace, caps, TTL và cấu hình app ban đầu. Mode và revision khởi tạo bằng ghi có điều kiện. `make it-redis` chạy `go test -tags=integration ./internal/state -count=1` với Redis thật, namespace riêng mỗi test và fail nếu Redis thiếu.

- [ ] Viết `TestSharedBan`, `TestLostCommitReply`, `TestSlowResponseAdmission`. Tạo hai store trên cùng Redis, deadline theo clock của Redis. Dùng shim chuyển tiếp cho test đọc reply đã commit rồi hủy delivery trước khi caller nhận ACK.

  ```go
  require.Equal(t, "allow", string(preThird.Action))
  require.Equal(t, "ban", string(nextReplicaCheck.Action))
  require.Equal(t, 3, ban.Explain.RequestCount)
  require.WithinDuration(t, thirdCommit.Add(15*time.Minute), ban.ExpiresAt, time.Second)
  require.Equal(t, ban.ExpiresAt, afterRetry.ExpiresAt)
  require.Equal(t, 3, afterRetry.Explain.RequestCount)
  require.Equal(t, "allow", string(otherApp.Action))
  require.Equal(t, "allow", string(afterExpiry.Action))
  require.True(t, insideConfiguredAge.Applied)
  require.False(t, outsideConfiguredAge.Applied)
  ```

  Case admission clock dùng cửa sổ cấu hình đủ lớn để một fixture cách admission 45 giây vẫn hợp lệ, còn event quá `max_event_age` bị bỏ. Tạo timestamp bằng fixture Redis, tránh chờ thật. Gửi cùng UUID ở `waf-verdict` và snapshot `observe-response`, assert policy WAF có đúng một contribution. Với mode observe, assert shadow decision tồn tại trong Redis và precheck trả allow.

- [ ] Chạy `make it-redis`. Red vì Store và script còn thiếu.
- [ ] Dùng client direct hoặc Sentinel failover hướng primary và đặt `MaxRetries: -1` cho client policy. Retry event chỉ qua stable event ID. `check.lua` đọc mode/revision, exemption, ban và fence với Redis TIME trong một round trip. `observe.lua` xác thực mode/revision, age, admission generation, dedupe và caps trước khi ghi. Lua chạy tuần tự trên Redis nhưng lỗi runtime không tự rollback write trước đó. Validate input, key type và giới hạn trước mutation. Dùng fixed schema do một service sở hữu và một operation atomic cho dedupe, window, evidence và decision. Chỉ ACK success sau reply thành công. Dùng ZSET theo thời gian Redis cho rolling windows và record theo UUID cho các field cần tính lại sau khi prune. Giới hạn số item mỗi window và từ chối update trước mutation nếu vượt cap. Dùng prefix theo deployment, mode, application và IP canonical được encode, cùng revision và generation cho window/contribution. Giữ ban theo mode/app/IP để sống qua thay đổi policy revision khi mode không đổi. Task 5 thêm mode epoch. Event ID dedupe tách khỏi khóa contribution `request_id + policy`. Giữ danh sách sample UUID tối đa 8, có reason, policy, revision, count, window và timestamps. WAF policy tính deny/drop thực thi, không inspection error, 3 request trong rolling 30 giây, ban 15 phút. Dùng default admission và `max_event_age` 120 giây trong fixture, kiểm tra chúng lớn hơn timeout end-to-end đã chọn. Dedupe/fence retention tối thiểu bằng thời gian admission còn hợp lệ. Ban, evidence, window và index đều có expiry. Dùng budget records toàn deployment và caps event, subject, unique path theo policy. Khi đầy, trả degraded có metric thay vì bỏ một entry dedupe còn hiệu lực. Giữ Redis `noeviction` và để bộ nhớ dự trữ cho script, admin, index và replication.
- [ ] Chạy `make it-redis` và `go test ./...`. Pass với duplicate cùng phase, cross-phase, timeout sau commit và observe. Kiểm tra ban nhận ở replica khác ngay sau ACK.
- [ ] Commit `feat: commit shared ban decisions atomically`.

### Task 4: Các policy theo response và auth outcome

**Files**

- Tạo `internal/policy/{policy.go,policy_test.go}`, `deploy/wafguard.example.json`. Sửa `deploy/haproxy/haproxy.cfg` và `internal/state/{redis.go,redis_test.go,scripts/observe.lua}` và tạo `internal/state/scripts/auth.lua`.

**Interfaces**

- Consumes: `event.Event`, `state.Store`, policy revision từ Task 3.
- Produces: `policy.Validate(cfg policy.Config) error`, `policy.Classify(e event.Event, cfg policy.Config) policy.Evidence`. `Evidence` gồm `WAFDeny, DetectionMatch, ResponseSeen, Eligible4xx, ProbePath, Backend5xx bool` và `PathKey string`. Lua áp ngưỡng trên dữ liệu đã phân loại và ghi decision.
- Produces: `state.Store.RecordAuth(ctx context.Context, receipt policy.AuthReceipt) error`. `AuthReceipt` có `Application, RequestID, SourceID, AccountKey string`, `Outcome policy.AuthOutcome` là `success` hoặc `failure`. Task 5 đưa receipt vào qua Unix socket có quyền ghi auth. HAProxy đặt `X-Wafguard-Request-ID` bằng UUID nội bộ, ghi đè header client trước khi chuyển đến login origin đã cấu hình. `AccountKey` là ID giả danh ổn định do nguồn nội bộ tạo, có thể để trống.

- [ ] Viết `TestClassify`, `TestScannerThreshold`, `TestAuthReceiptOrdering`, `TestOutageGuard` và `TestPolicyBoundaries`.

  ```go
  require.False(t, corazaError.WAFDeny)
  require.False(t, own429.Eligible4xx)
  require.False(t, expectedRefresh401.Eligible4xx)
  require.False(t, detectionOnly.WAFDeny)
  require.True(t, detectionOnly.DetectionMatch)
  require.False(t, responseDisclosure.WAFDeny)
  require.Equal(t, 30, mixedStatusWindow.ResponseCount)
  require.Equal(t, 15, mixedStatusWindow.UniquePaths)
  require.Equal(t, "ban", string(scannerWithProbe.Action))
  require.Equal(t, "allow", string(scannerWithoutProbe.Action))
  require.Equal(t, "allow", string(login200NoReceipt.Action))
  require.Equal(t, 10, duplicateAndOutOfOrderReceipts.RequestCount)
  require.Equal(t, "throttle", string(tenRealFailures.Action))
  require.Equal(t, 10, sprayedAccount.AccountFailureCount)
  require.Equal(t, 1, sprayedAccount.LastIPFailureCount)
  require.True(t, sharedBackend503.OutageActive)
  require.Equal(t, 0, sharedBackend503.StatusStrikesAdded)
  require.Equal(t, "ban", string(wafDenyDuringOutage.Action))
  ```

  Dùng 29 rồi 30 response, 14 rồi 15 path, 14 rồi 15 response 4xx hợp lệ trong tổng 30 để pin ranh giới scanner. Trong case NAT, 30 response 4xx ở cùng route expected không tạo ban. Assert 4xx burst chung và 5xx từ một IP tạo evidence hoặc cảnh báo với action `allow`. Assert slow scanner thiếu probe evidence không ban. Assert IP khác trong cùng subnet vẫn allow. Kiểm tra tuổi/fence cho cả hai thứ tự của auth join, receipt từ app/source sai và receipt mâu thuẫn trên cùng UUID.

- [ ] Chạy `go test ./internal/policy -count=1` và `make it-redis`. Red vì chưa có classification và atomic policy update tương ứng.
- [ ] Dùng rolling windows theo Redis TIME, lấy tổng cả successful responses. Scanner mặc định shadow dùng 30 response, 15 path, ít nhất 50% 4xx hợp lệ và probe route hoặc WAF evidence trong 60 giây, với ban thử 5 phút. Slow scanner bật riêng theo app, mặc định tắt, fixture dùng 5 path probe khác nhau trong 10 phút với ban thử 5 phút. Giữ path escape theo semantics route, bỏ query, hash path đã canonicalize trước khi lưu state. Route config map expected refresh, asset và business errors ra ngoài numerator. Response disclosure và summary tích lũy chỉ làm evidence mô tả. Mapping rule IDs có revision, validate duplicate và loại hợp lệ, fallback `waf-deny`; detection-only chỉ góp strike nếu policy riêng được bật rõ ràng. Theo dõi 500/502/503/504 ở mỗi backend. Bật outage guard 60 giây sau khi có 5 IP riêng trong cửa sổ 60 giây, kiểm tra guard trong cùng script trước khi cộng status evidence. Giữ WAF deny độc lập. Brute force mặc định 10 failure thật trong 60 giây tại login route và throttle IP 2 phút. Redis join receipt với observation theo app/UUID ở cả hai thứ tự, validate receipt và admission đang còn hạn lúc join, giữ một outcome thực cho mỗi request rồi áp caps và fence. Bucket account độc lập với IP dùng làm evidence spraying, không khóa account. App policy cấu hình threshold, exemptions và TTL phù hợp NAT. Nếu bật escalation thử 2x trong 1 giờ, cap 30 phút và để history decay sau 1 giờ, không refresh do own rejection. P0 giữ application scope. Các số ngoài spec là seed shadow để kiểm thử, phải qua review theo app trước enforce.
- [ ] Chạy lại hai lệnh red. Pass cả test pure classification và Redis thật cho policy, expiry và concurrent evidence.
- [ ] Commit `feat: evaluate behavioral policies and auth outcomes`.

### Task 5: Admin, policy revisions và unban fence

**Files**

- Tạo `internal/admin/{handler.go,handler_test.go}`, `internal/state/scripts/{unban.lua,admin.lua}`. Sửa `internal/state/{redis.go,redis_test.go}`, `internal/policy/policy.go`, `deploy/wafguard.example.json`.

**Interfaces**

- Consumes: `state.Store`, `policy.Config`, `policy.AuthReceipt`.
- Produces: `admin.New(store *state.Store, access admin.Access) http.Handler`. `Access` chứa `Role admin.Role` và `SourceID, Application string` để gắn với auth socket. Roles gồm `admin.Read`, `admin.Write`, `admin.Auth`. Task 6 gắn mỗi role với Unix socket riêng và filesystem ACL. `Auth` chỉ ghi receipt cho source/app được gắn với socket, không tin `SourceID` trong body.
- Produces: `(*state.Store).Unban(ctx context.Context, req state.UnbanRequest) (state.UnbanResult, error)`. Request gồm `Application string`, `ClientIP netip.Addr`, `Mode event.Mode`, `OperationID, Reason string`, `Suppression time.Duration`. Result gồm `Generation string`, `SuppressedUntil time.Time`. `(*state.Store).SetPolicy(ctx context.Context, app string, expectedRevision uint64, cfg policy.Config, mode event.Mode) (uint64, error)` tăng revision bằng compare-and-set. `(*state.Store).Inspect(ctx context.Context, app string, mode event.Mode, ip netip.Addr) (state.Inspection, error)`, `(*state.Store).List(ctx context.Context, app string, mode event.Mode, cursor string, limit int) (state.Page, error)`. `Inspection` chứa action, expiry, suppression, revision và explanation. `Page` mang `Items []state.Inspection` và `NextCursor string`.

- [ ] Viết `TestAdminRoles`, `TestUnbanFence`, `TestModeRevisionFence` và `TestDryRun`.

  ```go
  require.Equal(t, 403, writeViaReadSocket.StatusCode)
  require.Equal(t, 403, unbanViaAuthSocket.StatusCode)
  require.Equal(t, 409, reusedOperationChangedPayload.StatusCode)
  require.Equal(t, firstUnban, retriedUnban)
  require.Equal(t, "allow", string(firstCheckAfterUnban.Action))
  require.False(t, delayedOldAdmission.Applied)
  require.False(t, duringSuppression.Applied)
  require.True(t, postSuppressionNewAdmission.Applied)
  require.Equal(t, "allow", string(afterRollback.Action))
  require.False(t, afterModeRoundTripOldEvent.Applied)
  require.Equal(t, 409, stalePolicyWrite.StatusCode)
  require.Equal(t, beforeSnapshot, afterDryRunSnapshot)
  ```

  Tạo concurrency test hãm response trước `Observe`, unban ở replica khác rồi thả event. Assert event cũ bị bỏ kể cả có ngưỡng đủ strike. Assert audit và explanation gồm reason, policy, timestamp, counts và sample IDs, không có credential, body hoặc query. Assert list pagination có giới hạn. Tạo exemption có hạn, assert precheck allow khi exemption còn hiệu lực và áp lại decision còn hạn sau khi exemption hết.

- [ ] Chạy `go test ./internal/admin -count=1` và `make it-redis`. Red vì endpoint hoặc script chưa thực hiện role, fence và revision.
- [ ] Tạo endpoints `GET /v1/apps/{app}/decisions`, `GET /v1/apps/{app}/decisions/{ip}` có explanation, `GET /v1/apps/{app}/policy`, `PUT /v1/apps/{app}/policy`, `POST /v1/apps/{app}/policy/dry-run`, `POST /v1/apps/{app}/unban`, `PUT /v1/apps/{app}/exemptions/{ip}` và `POST /v1/apps/{app}/auth-outcomes`. Read/list cần mode rõ ràng, cap 100 record mỗi trang. Exemption có expiry và reason, scope chính xác theo IP/app. Dry-run dùng `policy.Validate` và fixture event được cung cấp để trả classification cùng policy revision, không ghi counters hoặc decisions. Cập nhật policy và mode qua một revision canonical trên Redis để mọi replica cùng kiểm tra. Chuyển observe bỏ qua ban enforce ngay lần precheck sau. Nếu bật enforce lại, chỉ enforce ban được tạo trong epoch enforce hiện hành. Tách epoch mode khỏi revision để chỉnh threshold trong cùng mode không xóa ban đang hiệu lực. Unban atomic thay generation bằng token ngẫu nhiên mới, xóa ban và áp suppression nếu có. Giữ fence ít nhất đến khi hết admission cũ, giữ fence mới lâu hơn nếu precheck tiếp tục cấp admission. Không tái dùng generation default khi vẫn còn admission hợp lệ. Canonicalize operation payload, lưu hash và result cùng giao dịch, trả 409 nếu operation ID trùng nhưng hash khác. Retention operation ID mặc định 24 giờ. Audit mutation cần idempotent và có retention. Không ghi raw receipt, account ID hoặc raw path vào audit.
- [ ] Chạy lại hai lệnh red. Pass khi race test qua nhiều replica, Redis state giữ idempotency và API role giới hạn đúng.
- [ ] Commit `feat: add fenced admin operations and policy revisions`.

### Task 6: Chạy Go SPOA và quan sát lỗi

**Files**

- Tạo `cmd/wafguard/{main.go,main_test.go}`, `internal/telemetry/{metrics.go,metrics_test.go}`, `deploy/Dockerfile`. Sửa `internal/spoa/{handler.go,handler_test.go}`, `deploy/wafguard.example.json`, `integration/compose.yaml`, `go.mod`, `go.sum`.

**Interfaces**

- Consumes: `spoa.NewHandler`, `state.New`, `admin.New`.
- Produces: `wafguard -config <file>` chạy listener SPOA nội bộ, Unix socket admin và metrics nội bộ `GET /metrics`, `GET /readyz`. `loadConfig(r io.Reader) (config, error)` và `run(ctx context.Context, cfg config) error` trong `cmd/wafguard`. Observe là mặc định khi khởi tạo app mới.
- Produces: `wafguard_spoe_operation_duration_seconds` histogram theo operation/result, `wafguard_events_total` counter theo kind/result, `wafguard_events_dropped_total` theo reason, `wafguard_redis_failures_total` theo operation và `wafguard_requests_inflight` gauge. Nhãn dùng tập giá trị hữu hạn.

- [ ] Viết `TestConfigValidation`, `TestOverload` và `TestMetricLabels`. Với fixture giới hạn 2 operation, giữ hai handler rồi gửi thứ ba. Với Redis mất kết nối, assert readiness 503 và listener vẫn phản hồi `unknown`.

  ```go
  require.Error(t, configWithAdmissionTTLBelowRequestTimeout)
  require.Error(t, configWithReadWriteSocketCollision)
  require.Equal(t, "unknown", string(overloadedACK.Action))
  require.True(t, overloadedACK.Degraded)
  require.Equal(t, 1, overloadDrops)
  require.LessOrEqual(t, maxInflight, 2)
  require.NotContains(t, metricsBody, "192.0.2.")
  require.NotContains(t, metricsBody, "/private-path")
  require.NotContains(t, metricsBody, fixtureRequestID)
  ```

- [ ] Chạy `go test ./cmd/wafguard ./internal/spoa ./internal/telemetry -count=1`. Red vì process wiring, saturation handling hoặc metric chưa có.
- [ ] Cấu hình listener nội bộ và Redis direct hoặc Sentinel rõ ràng, bật TLS/ACL cho Redis nếu network deployment yêu cầu. Giới hạn số connection, in-flight operation, Redis pool, body admin và deadline ngắn hơn SPOE processing timeout. Dùng semaphore có giới hạn và shed load ngay khi đầy. Scheduler của SPOP v0.1.1 có queue riêng hữu hạn và có thể chờ trước callback. Cap connection ở listener, đặt deadline I/O và đếm timeout trên HAProxy cho event bị mất trước callback. Bật `option continue-on-error` cho wafguard tại HAProxy và dùng `set-on-error` cùng log format có group/error để đếm event lỗi tại HAProxy khi SPOA không nhận được event. Giữ error policy Coraza độc lập. Tách socket admin theo role, mỗi auth source được cấp socket và app config tương ứng. Dùng mode filesystem và ownership cấu hình để cấp quyền. Xác thực config và version config trước bind, giới hạn request context, shutdown có deadline, đóng listener trước khi drain. Hệ thống quan sát cả backlog và drop reason tại điểm mất event. Dùng Prometheus histogram và counter với labels hữu hạn. Redis failure cho readiness degraded nhưng tiếp tục phục vụ precheck dạng unknown để Coraza xử lý. [SPOP scheduler v0.1.1](https://github.com/dropmorepackets/haproxy-go/blob/v0.1.1/spop/scheduler.go) · [HAProxy 3.2.0 SPOE specification](https://github.com/haproxy/haproxy/blob/v3.2.0/doc/SPOE.txt).
- [ ] Chạy command red, `go test -race ./...` và `go build ./cmd/wafguard`. Pass khi binary start/stop qua test lifecycle, mọi queue/concurrency có giới hạn và overload mất event có số đo.
- [ ] Commit `feat: run wafguard with bounded SPOA processing`.

## P0.3 · Rollout

### Task 7: Compatibility matrix và rollout theo app

**Files**

- Tạo `integration/{rollout_test.go,load_test.go}`, `docs/runbooks/rollout.md`. Sửa `integration/{compose.yaml,images.env}`, `Makefile`, `README.md`.

**Interfaces**

- Consumes: các lệnh integration Tasks 1 và 3, binary Task 6, admin endpoints Task 5.
- Produces: `make it-rollout HAPROXY_SERIES=3.2`, lệnh tương ứng cho 3.4 và `make it-load HAPROXY_SERIES=3.2`. `it-rollout` chạy `go test -tags=integration ./integration -run '^TestRollout' -count=1` với 2 HAProxy, 2 wafguard, stock Coraza, Redis primary/replica và Sentinel quorum. `it-load` chạy `TestLoadReport` và xuất p95/p99, throughput và event loss theo fixture topology, concurrency và phiên bản.

- [ ] Viết `TestRolloutSharedState`, `TestRolloutBackendSignals`, `TestRolloutOutages` và `TestLoadReport`. Tái dùng stock rule fixtures, đếm lần origin được gọi và chạy `it-stock` trong release gate để giữ coverage body, affinity và HTTP streams.

  ```go
  require.Equal(t, 200, sameIPAppB.StatusCode)
  require.Equal(t, 200, shadowAfterThreshold.StatusCode)
  require.Equal(t, 200, acceptedThresholdTrigger.StatusCode)
  require.Equal(t, 403, nextOnOtherHAProxy.StatusCode)
  require.Equal(t, 200, afterUnbanOnOtherHAProxy.StatusCode)
  require.Equal(t, 200, afterRollback.StatusCode)
  require.Equal(t, 429, afterTenConfirmedLogin200Failures.StatusCode)
  require.Equal(t, 503, localUnavailableOrigin.StatusCode)
  require.Zero(t, local503AttackStrikes)
  require.Zero(t, sharedBackendOutageAttackStrikes)
  require.Equal(t, 403, redisDownStockDeny.StatusCode)
  require.True(t, redisDownPrecheck.Degraded)
  require.True(t, resumedAfterSentinelPromotion)
  ```

  Tạo ban thử từ scanner response để assert request kích ngưỡng vẫn hoàn tất. Với Redis down có ban tồn tại, assert request là unknown ở precheck và vẫn qua Coraza. Với Sentinel failover, assert Redis đã promote một primary, precheck đọc từ primary mới, service phục hồi sau promotion và không dựa vào local cache. Cho phép mất write đã ACK theo semantics replication. Với overload, assert vẫn giữ verdict Coraza và có lost-event counter. So sánh cùng workload với Coraza standalone và Coraza + behavioral agent, ghi nhóm healthy và overload, đếm generated/accepted/drop/unknown. Assert report có phiên bản, topology, concurrency, p95/p99, throughput và loss. Đo lại trên topology rollout trước khi ký SLO.

- [ ] Chạy `make it-rollout HAPROXY_SERIES=3.2` và `make it-load HAPROXY_SERIES=3.2`. Red vì topology production-like hoặc release checks còn thiếu.
- [ ] Kết nối binary thật với configs deploy, cung cấp fixture auth 200, NAT và outage. Tạo runbook với kiểm tra persistence, `noeviction`, Redis memory, clock, Sentinel failover và budget latency/loss do operator phê duyệt từ số đo. Ghi cách bắt đầu shadow, xem false positives theo app/route, exemptions/TTL cho NAT và scanner được phép, chuyển từng app sang enforce và rollback qua revision CAS. Ghi hậu quả của cache affinity miss, Redis timeout và replication lag. Pure SPOE bỏ sót local 503 và các response kết thúc trước backend, nên báo riêng từ access logs/health telemetry khi có. Dùng p95/p99 overhead đo trên topology thật và tránh tuyên bố capacity cao hơn số đo. Khi nâng cấp Coraza, pin artifact hoặc digest mới và chạy lại contract/lifecycle matrix trước khi công bố.
- [ ] Chạy `go test -race ./...`, `make it-redis`, `make it-stock` và `make it-rollout` cho cả hai HAProxy series, cùng `make it-load HAPROXY_SERIES=3.2`. Pass khi cả hai runtime gate dùng binary thực, không skip và report có số đo thực. Nếu chưa có topology rollout thật, ghi app vẫn ở shadow và nêu gate còn chờ dữ liệu.
- [ ] Commit `test: gate behavioral rollout on stock integration`.

## Adapter tùy chọn sau P0

### Task 8: Enrichment từ stock Coraza JSON log

**Files**

- Tạo `internal/enrich/{coraza.go,coraza_test.go}`, `internal/state/scripts/enrich.lua`, `integration/enrichment_test.go`, `docs/runbooks/enrichment.md`. Sửa `internal/state/redis.go`, `cmd/wafguard/main.go`, `integration/compose.yaml` và `Makefile`.

**Interfaces**

- Consumes: admission mode/revision/generation từ Task 2, Redis fence và evidence từ Tasks 3–5.
- Produces: `enrich.Parse(r io.Reader, source enrich.Source, limits enrich.Limits) (enrich.Match, error)`. `Source` có `Application, Identity string` gắn với transport. `Match` có `Application, RequestID string`, `RuleID uint32`, `Tags []string`, `Severity, PhaseID int`. Field types từ stock JSON được parse theo fixture thực.
- Produces: `(*state.Store).Enrich(ctx context.Context, match enrich.Match) error`. `make it-enrichment HAPROXY_SERIES=3.2` chạy `TestEnrichmentStock` với adapter tắt và bật.

- [ ] Viết `TestEnrichmentJoin` và `TestEnrichmentStock`. Dùng stock log fixture thu bằng rule marker, qua socket của application đúng hoặc sai và phát lại cùng record.

  ```go
  require.Equal(t, corazaRequestID, matched.RequestID)
  require.Equal(t, 1, afterDuplicate.MatchRows)
  require.Equal(t, beforeLog.RequestCount, afterLog.RequestCount)
  require.Zero(t, missingUUID.JoinedRows)
  require.Zero(t, unknownSource.JoinedRows)
  require.Zero(t, expiredOrFenced.JoinedRows)
  require.NotContains(t, serializedEvidence, fixtureMatchedData)
  require.Equal(t, stockThresholdWithoutLog, stockThresholdWithLog)
  ```

- [ ] Chạy `go test ./internal/enrich -count=1` và `make it-enrichment HAPROXY_SERIES=3.2`. Red vì adapter hoặc gate integration chưa có.
- [ ] Tạo listener tùy chọn gắn source với app qua Unix socket có ACL. Accept dòng JSON stock tối đa 32 KiB, tối đa 32 tags, 128 byte mỗi tag. Whitelist các trường trong `Match` trước ghi Redis. Parse `unique_id` thành UUID và join với evidence SPOE theo app/UUID, dedupe theo app/UUID/phase/rule ID. Log tới trước observation có thể chờ trong buffer Redis hữu hạn 30 giây, kiểm tra age và fence tại thời điểm attach. Log thiếu hoặc đến muộn không đổi decision, verdict hay strike. Publish số bản ghi parse error, không join, late, duplicate và redacted theo labels hữu hạn. [Stock Coraza logging code](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/internal/application.go).
- [ ] Chạy lại lệnh red và `make it-rollout HAPROXY_SERIES=3.2` với adapter tắt. Pass khi default không cần log, fixture stock join được khi bật, và mọi gate reject đều bỏ payload.
- [ ] Commit `feat: enrich evidence from stock Coraza logs`.

### Mốc cần quyết định riêng

- Structured HAProxy syslog có thể bổ sung local error và final status. Khi chọn triển khai, kiểm chứng nguồn xác thực, join bằng UUID, telemetry-only khi thiếu UUID, redaction, ordering và dedupe trước khi dùng dữ liệu này. Core P0 có gate riêng cho giới hạn coverage.
- Chỉ mở P2 maps nếu p95/p99 cho thấy precheck round trip là chi phí cần bỏ. Thiết kế P2 phải có expiry, snapshot/reconcile theo revision, gate reload và unban lag. Runtime API chỉ đổi memory. HAProxy peers ghi đè thay vì cộng counter active-active. [HAProxy Runtime API](https://www.haproxy.com/documentation/haproxy-runtime-api/) · [HAProxy peers](https://docs.haproxy.org/3.2/configuration.html#11.2).

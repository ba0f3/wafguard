# haproxy-waf-spoe — Thiết kế v2 dùng Coraza upstream nguyên bản

**Ngày:** 2026-11-23. **Trạng thái:** specification; chưa triển khai service production.

**Baseline:** `corazawaf/coraza-spoa` **v0.9.1**, commit `c9b34f409e04cfb60219602bd1ad711afd15eaa3`. Tài liệu này thay thế thiết kế trước cho phần triển khai tại repository `ba0f3/haproxy-waf-spoe`.

## 1. Mục tiêu và ranh giới

Xây dựng Go SPOA độc lập để kết hợp verdict Coraza với response status, phát hiện scanner, brute force, burst và tự tạo ban có thời hạn dùng chung cho cụm HAProxy. Coraza tiếp tục kiểm tra payload SQLi, RFI, RCE và chặn request hiện tại; service mới quản lý hành vi qua nhiều request và chặn các request tiếp theo.

**Chỉ dùng binary/image Coraza upstream nguyên bản.** Toàn bộ behavioral core, Redis adapter, admin API, policies và HAProxy adapter nằm trong repository này. Không sửa Coraza, không duy trì fork, không phụ thuộc biến riêng của fork hoặc trích xuất engine từ fork. Thay đổi HAProxy/SPOE configuration để truyền những trường upstream hỗ trợ là cấu hình triển khai bình thường.

P0 dùng Redis primary/Sentinel cho quyết định chung, không local cache. Response detection không thu hồi request đã tới ứng dụng; request đồng thời có thể tiếp tục trước khi ban commit. Không tuyên bố nhận diện được toàn bộ một chiến dịch chỉ bằng địa chỉ IP.

## 2. Những tín hiệu upstream thực sự có

Baseline đã xuất các trường sau; không cần patch để sử dụng.[1][2]

| Trường Coraza | Cách sử dụng |
|---|---|
| `action`, `status`, `data` | Interruption/verdict; `status` không mặc nhiên là origin hoặc final HTTP status |
| `ruleid`, `id`, `error` | Rule interruption, transaction correlation và lỗi xử lý |
| `rules_hit`, `anomaly_score` | Metadata tổng hợp nếu tồn tại |
| `rule_ids` | Danh sách best-effort khi bật argument `exportRuleIDs=true` |

Các biến thuộc namespace `txn.coraza.*`. Dịch vụ mới chỉ trả biến của mình dưới `txn.wafguard.*`.

Phân biệt chế độ WAF với chế độ observe/enforce của behavioral service. HAProxy truyền chế độ enforcement đã cấu hình và nguồn quyết định; không suy ra chế độ từ việc thiếu biến. Policy đếm WAF-deny chỉ nhận action deny/drop không có inspection error và phù hợp với điều kiện enforcement thực tế. Verdict giả định trong detection-only được ghi riêng; muốn dùng matched-rule evidence để tự ban trong chế độ đó phải có policy riêng bật rõ ràng.

`rule_ids` bị lọc và không mang đầy đủ tag, severity, phase cho từng match. Core phải hoạt động khi thiếu metadata bổ sung: lưu evidence `waf-deny`, không tự gán SQLi/RCE chỉ vì thấy 403 hoặc rule tổng hợp. Mapping ID sang loại tấn công phải được cấu hình, version và kiểm tra; không coi danh sách này là toàn bộ match.

Sau response inspection, metrics có thể chứa match tích lũy của transaction. Không suy ra “match phase response” từ thời điểm export, không đếm lại request match.

## 3. Giới hạn event đã kiểm chứng

Harness HAProxy **3.2.0**, hai SPOE engine và agent giả lập verdict cho kết quả:

| Trường hợp | `on-tcp-response` / `on-http-response` | `http-after-response set-header` |
|---|---|---|
| Local 403 do `http-request deny` | Không chạy | Có chạy |
| Backend trả 404/500 | Đều chạy | Có chạy |
| Local 503 vì upstream không kết nối được | Không chạy | Có chạy |

`http-after-response` không hỗ trợ `send-spoe-group`; tài liệu 3.4 cũng không cung cấp action này.[4][5] Kết quả trên chỉ kiểm chứng định tuyến event bằng stub, **chưa kiểm chứng Coraza thật hoặc HAProxy 3.4 thực chạy**.

Vì vậy, `on-http-response` và `on-tcp-response` không đủ để thu deny xảy ra trước backend. Với HTTP, không dùng cả hai event cho cùng observation vì sẽ tạo bản ghi trùng. TCP passthrough không cung cấp HTTP status hoặc payload HTTP đã giải mã để áp dụng các policy này.

## 4. Luồng tích hợp và thứ tự rule

Ba group của service mới:

1. **`check-ban`:** chạy mỗi HTTP request, sau khi xác định identity/application, trước Coraza.
2. **`waf-verdict`:** chạy ngay sau Coraza request inspection, trước terminal deny/drop/redirect.
3. **`observe-response`:** nhận origin status và request verdict snapshot; nếu bật Coraza response inspection đồng bộ thì chạy sau inspection và trước terminal response action.

Quan sát HTTP status **không yêu cầu bật `response_check` của Coraza**. Nếu chỉ cần hành vi/error code, không thêm body inspection vì mục đích này.

Đối với Coraza response, chọn đúng một cách wiring: giữ message tự chạy bằng event, hoặc chuyển message stock `coraza-res` sang explicit group do cấu hình triển khai khai báo. Phương án explicit giúp kiểm soát thứ tự: đặt tên group `coraza-response-sync`, chứa message stock `coraza-res`, đăng ký group với agent và bỏ event binding của chính message đó. Không vừa giữ event vừa gọi group, tránh inspection hai lần.

**Fragment request, không phải cấu hình đầy đủ để chạy:** engine/backend/group/arguments/timeout/reset/snapshot phải được khai báo. Error action 500 minh họa chính sách trong example upstream; triển khai giữ error policy Coraza đã chọn, độc lập với lỗi behavioral service.

```haproxy
http-request set-var(txn.wafguard.action) str(unknown)
http-request send-spoe-group wafguard check-ban
http-request deny deny_status 403 if { var(txn.wafguard.action) -m str ban }
http-request deny deny_status 429 if { var(txn.wafguard.action) -m str throttle }

# Reset kết quả Coraza; giữ identity đã tạo.
http-request send-spoe-group coraza coraza-req
# Snapshot request verdict vào txn.wafguard.*.
http-request send-spoe-group wafguard waf-verdict
http-request redirect code 302 location %[var(txn.coraza.data)] if { var(txn.coraza.action) -m str redirect }
http-request deny deny_status 403 if { var(txn.coraza.action) -m str deny }
http-request silent-drop if { var(txn.coraza.action) -m str drop }
http-request deny deny_status 500 if { var(txn.coraza.error) -m int gt 0 }
```

Khi check không có kết quả, action giữ `unknown`, luồng tiếp tục Coraza. Response explicit theo thứ tự: lưu `status` vào `txn.wafguard.origin_status` → reset kết quả phase, giữ id/snapshot → gọi `coraza-response-sync` → gọi `observe-response` → áp dụng đầy đủ Coraza redirect/deny/drop/error policy. Không gọi `coraza-response-sync` nếu tắt inspection hoặc giữ event binding. Group này do cấu hình triển khai khai báo, không phải tên mặc định upstream.

Nếu giữ automatic response event, phải snapshot request verdict và reset những biến phase-sensitive ở cuối request rules sau các kiểm tra terminal, trước khi chờ backend. Rule `http-response` đầu tiên chạy sau event nên không được dùng nó để reset rồi vô tình xóa verdict response vừa nhận. Phương án explicit response group được ưu tiên khi cần quản lý reset/thứ tự này.

Chế độ response inspection bất đồng bộ không bảo đảm verdict hoàn chỉnh trong ACK ban đầu; P0 vẫn dùng status và request snapshot, không dựa vào kết quả chưa sẵn sàng. Lỗi behavioral service tuyệt đối không tắt hoặc bỏ qua WAF.

`option http-buffer-request` trên frontend/listen có thể chờ body trước mọi `http-request` rule. Phương án dễ kiểm soát là bỏ buffering kế thừa trên frontend, rồi chạy `check-ban → wait-for-body → coraza-req` trong thứ tự explicit. Phương án khác phải chuyển **cả buffering và Coraza request inspection** xuống backend sau frontend precheck; chỉ chuyển buffering nhưng vẫn inspection ở frontend có thể kiểm tra trước khi body sẵn sàng. Phải kiểm thử body/Expect/timeout và giữ bao phủ WAF khi thay đổi.

## 5. Identity, reset và lifecycle

HAProxy tạo UUID nội bộ, lưu `txn.wafguard.request_id`; truyền cùng ID vào argument `id` của `coraza-req`. Giữ `app` là argument đầu theo contract upstream. Không lấy request-ID header của client làm khóa dedupe. Lưu method/path/application/client IP trong `txn` trước response.

Chỉ tin forwarded IP khi socket peer là trusted proxy có quy tắc overwrite rõ ràng; còn lại dùng peer IP. Application phải map về danh sách cấu hình, không dùng Host tùy ý làm namespace. Chuẩn hóa IP bằng `netip.Addr.Unmap`, mặc định /32 hoặc /128; Coraza, detector và enforcer dùng cùng identity.

Trước mỗi inspection phase, reset các interruption/error/metric variable có thể stale. Dùng unset cho metric optional hoặc presence flag; không bịa zero thay cho dữ liệu thiếu. Giữ request verdict snapshot độc lập và **không xóa Coraza transaction ID** trước response. Unknown/transport failure phải khác với verdict allow.

Full response inspection giữ nguyên yêu cầu affinity của stock Coraza: request và response cùng transaction phải tới instance giữ cache tương ứng. Các replica behavioral service không cần affinity vì event tự chứa metadata và state nằm chung Redis.

Không có cancel message để tự dọn stock transaction. Khi `waf-verdict` vừa tạo ban sau một request đã được Coraza cho phép và đang chờ response, mặc định cho request kích hoạt ngưỡng hoàn tất; precheck chặn các request sau. Nếu triển khai chọn chặn ngay tại điểm đó, phải chấp nhận và giới hạn transaction mồ côi sống tới cache TTL, có capacity test và metric; không giả định đã hủy transaction.

## 6. Event contract và trạng thái HTTP

Event tự chứa `schema_version`, node/request ID, loại event, emission phase, application, client/peer IP, thời điểm admission, method/path/route group, request WAF snapshot, origin status và policy revision. Admission generation/token bảo vệ unban fence. `phase` của event không phải phase từng rule.

Backend 200 bị WAF thay bằng 403 có origin status 200 và final status khác. Observation trước terminal action chưa chứng minh status cuối đã gửi cho client; dùng field `final_client_status` chỉ khi nguồn đó thực sự biết. Không biến intended status thành observed status.

Tùy chọn nhận structured syslog trực tiếp từ HAProxy để bổ sung local errors và status muộn; không bắt buộc scrape file. Kênh này phải được cấu hình và kiểm thử riêng. Pure SPOE không hứa bao phủ mọi response. Thiếu UUID thì chỉ dùng telemetry tổng thể, không ghép mơ hồ theo IP/timestamp để ban.

Giới hạn frame, chuỗi, số rule, unique path và event age. Không gửi body, token, cookie hoặc mật khẩu vào behavioral core.

## 7. Policy khởi điểm

Đây là **ngưỡng đề xuất chạy shadow**, chưa phải giá trị production:

| Detector | Điều kiện khởi điểm | Kết quả dự kiến |
|---|---|---|
| WAF deny lặp lại | 3 request có verdict deny hợp lệ/30 giây, application policy cho phép | Ban application 15 phút |
| Scanner | ≥30 response/60 giây, ≥15 path khác nhau, tỷ lệ lỗi cao và probe path/WAF evidence | Ban application ngắn |
| Brute force | ≥10 auth failure thực/60 giây tại route đã khai báo | Throttle hoặc ban ngắn |
| Slow scanner | Evidence lặp trong cửa sổ dài dù rate thấp | Policy riêng, ban khi đủ evidence |
| 4xx burst chung | Lỗi tăng theo route/IP | Evidence phụ; không mặc định ban |
| 5xx burst | 500/502/503/504 tăng theo backend/IP | Cảnh báo; không tự ban riêng tín hiệu này |

Một request có nhiều rule/anomaly score/403 chỉ góp một strike cho cùng policy. Muốn tỷ lệ lỗi phải nhận cả response thành công để có mẫu số. Normalization path phải khớp semantics ứng dụng, giới hạn decoding/cardinality.

Brute force không chỉ dựa vào 401/403: login có thể thất bại với HTTP 200. Cần auth outcome đáng tin cậy từ ứng dụng hoặc nguồn nội bộ tùy chọn. Nếu có account identifier an toàn, dùng bucket IP và account độc lập; bucket ghép IP+account không đủ bắt password spraying.[9]

Mặc định scope application. Global ban cần policy mạnh hơn. NAT, nhà mạng và văn phòng dùng ngưỡng/TTL phù hợp; không tự mở rộng subnet. Health checks và scanner được ủy quyền có exemption quản lý được.

## 8. Tránh ban nhầm

Không tạo attack strike từ lỗi Coraza, SPOE timeout, Redis outage, hoặc denial của chính `wafguard`. Đánh dấu own rejection bằng namespace của service; không tìm biến autoban riêng trong Coraza. Không gia hạn ban chỉ vì IP bị ban tiếp tục nhận 403/429.

Nếu nhiều IP cùng gặp 5xx ở một backend, bật outage guard và ngừng tăng evidence dựa trên status của backend đó. Giữ detection từ request exploit evidence độc lập. Response rule phát hiện backend lộ dữ liệu không tự chứng minh client có tội; legacy summary không đủ phân biệt phase nên không tự dùng làm response attack strike.

Loại hoặc giảm trọng số expected auth refresh, asset thiếu và business errors theo route policy. Ban phải giải thích được: evidence nào, cửa sổ nào, số request nào, không chỉ một điểm tổng không rõ nguồn.

## 9. Redis, dedupe và unban

Đọc/ghi trên Redis primary hoặc primary được Sentinel xác định; P0 không native Redis Cluster. Atomic script kiểm tra admission generation, dedupe, cập nhật window và ghi decision. Không negative cache; P0 cũng không positive cache để unban hiển thị ở lần check kế tiếp.

Mỗi event có ID ổn định qua replica/retry. Giới hạn một contribution trên `request_id + policy`; nếu policy kết hợp nhiều phase thì gom evidence trước khi phát strike một lần. Snapshot request ở response không tăng strike lần hai. Không tuyên bố exactly-once ngoài dedupe retention.

TTL áp dụng cho cửa sổ, dedupe, evidence và ban; cap cardinality/memory rõ ràng. `max_event_age` và admission TTL do service này định nghĩa, tương thích response chậm và request timeout. Không dùng một giới hạn 30 giây kế thừa từ hệ thống khác.

Unban tăng generation/fence: event admission cũ không tạo lại ban sau thao tác admin. Có suppression tùy chọn và operation ID idempotent. Cùng operation ID nhưng payload khác phải bị từ chối. Escalation có trần và decay; mặc định không permanent auto-ban.

## 10. API, failure semantics và SLO

Admin qua Unix socket hoặc API nội bộ xác thực, phân quyền read/write: observe/enforce, inspect/list/explain, unban, exemption có hạn, policy dry-run và revision. Observe dùng state riêng, không ảnh hưởng enforcement. Audit có reason/policy/timestamps/counts/request IDs mẫu, không lưu payload nhạy cảm.

Khi service/Redis timeout, mặc định continue Coraza và báo degraded. Do không có local cache, **ban đã tồn tại trong Redis cũng không được bảo đảm enforce khi Redis không đọc được**. Không coi lỗi hệ thống là allow sạch hoặc attack.

Counter update và ban mới phải commit atomic trước ACK nếu cam kết lần precheck tiếp theo nhìn thấy ban. Audit có thể bất đồng bộ. Timeout có thể xảy ra sau commit; retry chỉ bằng ID/dedupe/fence đã kiểm thử, không increment mù. Queue/concurrency phải hữu hạn và có metric khi mất event.

Redis replication bất đồng bộ có thể mất thay đổi vừa xác nhận khi failover. Theo dõi persistence, memory/noeviction, failover và clock; không hứa consistency tuyệt đối qua mọi sự cố.

Đo latency overhead p95/p99, event loss và capacity trên topology thực. `check-ban` thêm round trip mỗi request; không đưa benchmark chưa chạy. IP/path không làm nhãn Prometheus cardinality cao.

## 11. Log enrichment upstream — tùy chọn

Stock `log_format: json` có thể xuất `match.rule_id`, `tags`, `severity`, `phase_id`, `unique_id` và metadata khác.[3] Adapter trong repository này có thể dùng chúng để enrichment; core chạy đầy đủ generic verdict policies khi **không có log**.

Chỉ nhận từ transport/source đã xác thực hoặc giới hạn tin cậy; map source với application cấu hình. Join bằng HAProxy-generated UUID đã truyền vào Coraza `id`, không dựa Host/IP đơn lẻ. Redact matched data/payload trước lưu trữ; giới hạn parser và retention.

Không hứa log là đầy đủ hay đúng thứ tự: rule logging, transport và timeout có thể làm thiếu event. Không đếm lại strike đã tạo từ SPOE. Log thiếu không làm verdict thành sạch; log tới muộn không vượt fence hoặc `max_event_age`. Không yêu cầu thay đổi source/export schema của Coraza.

## 12. Triển khai và acceptance gates

**P0.1 — Contract/integration:** build harness dùng official release v0.9.1 nguyên bản, pin image digest nếu dùng image hoặc build reproducible từ commit đã nêu; không patch/private variable. Test request deny, drop, error, detection-only, optional metrics thiếu, stale reset, argument order, snapshot, UUID và response group chỉ chạy một lần.

**P0.2 — Core/state:** Go SPOP adapter, Redis atomic policies, admin fence và observe mode. Test nhiều HAProxy/replica cùng IP, duplicate delivery, cross-phase dedupe, timeout sau commit, unban khi event đang bay và response chậm.

**P0.3 — Rollout:** test Coraza thật với payload test được phép, backend status, login200, NAT, outage 503, keepalive/HTTP2, body buffering, affinity, Redis failover và overload. Chạy shadow, review false positive; bật enforce từng application với rollback sang observe.

**P2 — Maps tùy chọn:** chỉ thêm khi số đo cần bỏ round trip. Map chứa expiry, snapshot/reconcile/revision và xử lý reload/unban lag. Runtime API chỉ thay memory; peers không cộng counter active-active.[6][7][8]

Compatibility matrix tối thiểu:

| Trục | Gate |
|---|---|
| Coraza v0.9.1 baseline | Official artifact hoặc build từ source nguyên bản; đủ tests request/response/error/log optional |
| Coraza mới hơn | Pin version/digest; chạy lại contract/lifecycle matrix trước công bố hỗ trợ |
| HAProxy 3.2 | Integration thực; stub routing test hiện có chưa đủ |
| HAProxy 3.4 | Build/runtime integration riêng; không suy từ docs |
| Response inspection tắt/bật | Status-only hoạt động; bật thì giữ affinity, không orphan không giới hạn |
| Log enrichment tắt/bật | Core không phụ thuộc log; join/dedupe/redaction đúng khi bật |

## Nguồn tham chiếu

1. [Official baseline](https://github.com/corazawaf/coraza-spoa/tree/c9b34f409e04cfb60219602bd1ad711afd15eaa3), [README](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/README.md).
2. [Stock agent và exported variables](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/internal/agent.go), [SPOE config](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/example/haproxy/coraza.cfg).
3. [Stock application logging](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/internal/application.go), [configuration](https://github.com/corazawaf/coraza-spoa/blob/c9b34f409e04cfb60219602bd1ad711afd15eaa3/example/coraza-spoa.yaml).
4. [HAProxy 3.2 configuration](https://docs.haproxy.org/3.2/configuration.html), [SPOE specification](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt).
5. [HAProxy 3.4 configuration](https://docs.haproxy.org/3.4/configuration.html).
6. [Runtime API persistence](https://www.haproxy.com/documentation/haproxy-runtime-api/).
7. [Atomic map replacement](https://www.haproxy.com/documentation/haproxy-runtime-api/reference/prepare-map/).
8. [Peers overwrite without aggregation](https://docs.haproxy.org/3.2/configuration.html#11.2).
9. [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html).
10. [Go SPOP library](https://pkg.go.dev/github.com/dropmorepackets/haproxy-go/spop). Pin dependency khi triển khai; không dùng latest không kiểm thử.

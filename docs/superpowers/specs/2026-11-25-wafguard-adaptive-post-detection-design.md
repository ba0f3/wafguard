# Phát hiện chủ động và tự học hành vi POST trong wafguard

Ngày 2026-11-25. Bản thiết kế chờ duyệt.

## Mục tiêu

Wafguard phát hiện POST đáng ngờ trên các route nhạy cảm mà Coraza cho đi tiếp, kể cả khi origin trả HTTP 200. Bộ phát hiện bổ sung kiểm tra contract của route và học đường cơ sở hành vi theo app và nhóm route. Coraza giữ quyền quyết định có chuyển request hiện tại đến origin hay không. Cảnh báo là mặc định cho route được bật. App có thể bật ban tự động có thời hạn.

Vụ SQLi qua POST là động lực cho thiết kế. Bản đầu kiểm chứng riêng khả năng nhìn thấy body và khả năng phát hiện dựa trên contract của route. Một POST đúng kiểu và đúng cấu trúc vẫn có thể khai thác truy vấn SQL không an toàn. Query có tham số ở backend là yêu cầu độc lập. Autoban áp dụng từ lần `check-ban` sau khi ban đã commit. Request đang được đánh giá và request đồng thời có thể đã qua bước kiểm tra ban.

Thiết kế kế thừa luồng SPOE, admission, các policy Coraza và auth hiện tại, Redis primary/Sentinel và admin API của wafguard. Phạm vi bản đầu gồm route POST JSON đăng ký rõ ràng. Upload, các body stream và LLM nằm ngoài bản đầu. [Thiết kế wafguard hiện tại](../../specs/2026-11-23-haproxy-waf-spoe-design.md)

## Các hướng đã cân nhắc

| Hướng | Giá trị và chi phí |
|---|---|
| Contract theo route | Phát hiện một request lạ với lý do rõ và chi phí thấp. Operator phải mô tả dữ liệu hợp lệ của các route ưu tiên. |
| Contract kết hợp baseline nội bộ | Phát hiện cả một POST sai contract và thay đổi kéo dài qua nhiều request. Cần dữ liệu sạch để học và theo dõi tỷ lệ báo nhầm. Đây là hướng đã chốt cho bản đầu. |
| LLM đánh giá cụm cảnh báo | Có thể hỗ trợ phân loại các ca mơ hồ. Cần ngân sách và kiểm chứng giá trị tăng thêm. Xem xét sau khi đã có dữ liệu từ bản đầu. |

## Cấu hình và phạm vi

Khai báo policy theo revision bằng admin API hiện tại. Mỗi app chọn `warning` hoặc `autoban` cho bộ phát hiện mới. App có danh sách nhóm route, mã nhóm do operator đặt, điều kiện khớp path theo cấu hình và một contract JSON cho mỗi nhóm. Chỉ POST khớp nhóm route được chọn mới đi vào luồng mới. App chưa có nhóm route giữ hành vi hiện tại. Kiểu khớp path dựa trên đường dẫn tới origin đã được HAProxy xử lý, và test phải kiểm tra cùng một request được phân vào đúng nhóm trên cả hai replica. Khi nhiều nhóm khớp, chọn prefix dài nhất và từ chối cấu hình có prefix trùng.

Contract bản đầu giới hạn JSON object với tên trường định trước. Operator chỉ định trường bắt buộc, kiểu, giới hạn tạo bởi schema như độ dài hoặc khoảng số, và tập giá trị cho trường có miền hữu hạn. Operator chọn cho phép hay từ chối trường ngoài contract theo route. Tên trường trùng hoặc JSON có dữ liệu thừa sau object phải cho kết quả xác định và được kiểm thử với parser của origin trước khi bật autoban. Cấu hình sai phải bị từ chối trước khi tăng revision. Cấu hình mẫu dùng tên và giá trị tổng hợp.

Mode `observe` hiện tại là giới hạn trên cho toàn app. Chỉ khi app ở `enforce` **và** bộ phát hiện ở `autoban` thì nhánh mới được ghi ban. `warning` vẫn học và ghi cảnh báo, độc lập với cách app cấu hình các policy Coraza hoặc brute force khác.

## Luồng request và giới hạn dữ liệu

1. `check-ban` vẫn kiểm tra ban chung trước. ACK xác định nhóm route đủ điều kiện theo cùng revision với admission. Chỉ cho phép cấu hình bộ phát hiện trên nhóm route đã được bao phủ bởi `req_inspect_paths`. Operator bật chờ body riêng và chấp nhận timeout hiện có của nhóm route đó. Chuyển sang `warning` không tự bật chờ body.
2. HAProxy dùng bước chờ body có giới hạn hiện có và gọi `coraza-req` trước. Nếu rule hiện hành sẽ kết thúc xử lý bằng `deny`, `drop`, `redirect` của Coraza hoặc lỗi Coraza dẫn tới từ chối request, gửi `waf-verdict` với metadata cũ để policy hiện có nhận verdict. Bỏ phần body khỏi message và bỏ qua parser, bộ chấm điểm và cập nhật baseline của tính năng mới. Dùng cùng điều kiện quyết định kết thúc request ở cả bước chọn dữ liệu gửi đi và bước thực thi, kể cả khi mode của wafguard là `warning`. Một kết quả chỉ để quan sát từ Coraza đang chạy detection-only không được xem là quyết định kết thúc request.
3. Với POST đủ điều kiện mà HAProxy sẽ chuyển tiếp, gắn dữ liệu body có điều kiện vào lần gọi `waf-verdict` có sẵn. Wafguard kiểm tra contract và đánh giá hành vi trước khi chuyển tiếp. Giữ hợp đồng cũ cho node chưa bật tính năng. Phần kiểm tra mới chỉ cảnh báo hoặc tạo ban cho request tiếp theo.
4. Bộ trích xuất tín hiệu ở biên SPOE đọc JSON từ bộ nhớ tạm. Chỉ chuyển kết quả có kiểu, cờ chất lượng, mã nhóm route và số đếm sang policy. Body và giá trị trường không nằm trong event hành vi, hàng đợi, audit, metrics, log, Redis hoặc dữ liệu dùng để học. Lỗi parser chỉ xuất mã cố định.
5. Chỉ gửi body khi thuộc loại JSON được cấu hình, không nén, có đúng một độ dài khai báo hợp lệ và số byte có sẵn khớp độ dài đó. HAProxy kiểm tra giới hạn **trước khi** gắn body vào frame. Bản đầu giới hạn 8 KiB body, tối đa 8 tầng và 128 trường JSON. Tổng frame phải nằm trong giới hạn SPOE hiện tại, kể cả metadata. Một POST không đủ dữ liệu đi với mã `unknown` và lý do có tập giá trị hữu hạn. JSON đọc đủ nhưng sai cú pháp hoặc sai contract là kết quả riêng.
6. Body thừa giới hạn, body đến thiếu, kiểu không hỗ trợ, revision không còn hiệu lực và lỗi SPOE/Redis không được tính là bằng chứng tấn công hay mẫu sạch. Luồng xử lý hiện tại tiếp tục theo policy HAProxy của app, gồm timeout request nếu bước chờ body đã được bật. Đếm riêng các POST kết thúc ở Coraza và POST thiếu dữ liệu để operator biết phạm vi được kiểm tra. Bỏ cả hai khỏi mẫu học baseline.

V1 không cần egress. URL, hostname, địa chỉ IP, UUID, query, header, body và hash định danh không được gửi tới LLM hoặc dịch vụ bên ngoài. Riêng đường dữ liệu mới, body chỉ tồn tại trong HAProxy và adapter SPOE của wafguard trên mạng nội bộ đã cách ly. Wafguard dùng IP nội bộ để liên kết request và áp ban theo app. Nhãn metrics chỉ dùng mã hữu hạn. Cấu hình triển khai phải giữ log HAProxy và audit Coraza chứa dữ liệu thô trong hệ thống hoặc lọc dữ liệu trước khi log rời hệ thống. Kiểm thử privacy bao gồm cả cấu hình các log hiện có và log của tính năng mới.

Xuất cảnh báo qua log có cấu trúc nội bộ với quyền đọc giới hạn. Cảnh báo lưu ID cảnh báo riêng, mã lý do, mã nhóm, khoảng thời gian, số đếm đã gộp và phiên bản policy/baseline. Gộp cảnh báo theo nhóm lý do và giới hạn tần suất theo app và nhóm route. Operator lấy mẫu và gắn nhãn theo ID cảnh báo trong quá trình shadow. Các trường hợp cần đối chiếu IP dùng giao diện admin nội bộ có sẵn.

## Phát hiện từng request và hành vi theo thời gian

Bộ phát hiện có ba nhóm tín hiệu. Mỗi nhóm chỉ đóng góp một lần vào quyết định dù nhiều chỉ số cùng vượt ngưỡng.

| Nhóm tín hiệu | Dữ liệu | Khi đứng riêng |
|---|---|---|
| Contract | JSON sai cú pháp khi đã đọc đủ, kiểu hoặc miền giá trị sai, trường bắt buộc thiếu | Cảnh báo có mã lý do. |
| Hành vi | Tần suất POST qua nhiều cửa sổ theo app, nhóm route và IP | Cảnh báo khi vượt baseline bền vững và đủ mẫu. Tỷ lệ sai contract là số đo phục vụ chẩn đoán. |
| Xác thực | Lịch sử auth outcome đã được chấp nhận từ trước, do caller đã xác thực báo và gắn với admission hợp lệ, đúng app | Chỉ bổ sung bằng chứng cho lần đánh giá request kế tiếp. Outcome đến muộn không kích hoạt đánh giá lại request cũ. Outcome thiếu không tính thành thất bại. Policy brute force hiện tại tiếp tục có quy tắc riêng. |

Ở `autoban`, cho phép ba tổ hợp đủ bằng chứng trong cửa sổ đánh giá. Sai contract cùng bất thường tần suất, sai contract cùng chuỗi thất bại auth đã xác nhận, hoặc bất thường tần suất cùng chuỗi thất bại auth đã xác nhận. Coraza verdict và HTTP status có thể xuất hiện cùng cảnh báo cũ. Nhánh mới phải vượt ca kiểm thử khi cả hai tín hiệu đó vắng mặt. Một POST đơn lẻ sai schema chỉ tạo cảnh báo. Dùng whitelist, suppression và cơ chế unban hiện có. Ban hết hạn theo TTL tối đa do app phê duyệt, với phạm vi app. Không kéo dài ban từ các request đã bị từ chối.

Khi nhận event, Redis kiểm tra lại mode, policy revision, admission và fence cùng lúc với khử trùng lặp, cập nhật bộ đếm và ghi ban. Dùng cùng `request_id` nội bộ để một request chỉ góp một lần cho mỗi policy dù thử lại ở replica khác. Mode `warning` và `observe` không được gieo bộ đếm enforcement. Khi tắt `autoban`, lần kiểm tra kế tiếp ngừng áp ban do nhánh mới tạo. Bật lại bắt đầu một phiên enforcement mới với bằng chứng mới. Lưu nguồn và phiên enforcement của ban, để rollback vẫn giữ hiệu lực của ban do policy khác tạo. Nếu vượt ngân sách quan sát, bỏ phần đánh giá mới và ghi metric lỗi theo mã cố định. Luồng precheck và Coraza vẫn dùng ngân sách hiện có.

## Học và cập nhật baseline

Học từ số đếm và tỷ lệ, không học giá trị trường hay nội dung request. Chỉ giữ thống kê theo nhóm route đã cấu hình và bộ đếm ngắn hạn theo IP. Số lượng nhóm, số bộ đếm đang hoạt động và TTL phải có giới hạn. Khi chạm giới hạn, giảm quan sát và báo metric. Không phát ban dựa trên hồ sơ thiếu dữ liệu.

V1 dùng cửa sổ ứng viên 5 phút để tính tần suất POST theo IP, rồi lấy phân phối theo app và nhóm route. Tách tỷ lệ sai contract và tỷ lệ đọc đủ body thành số đo chẩn đoán và chất lượng dữ liệu. Chỉ học từ cửa sổ đạt số mẫu tối thiểu, có tỷ lệ quan sát đủ cao và không nằm trong sự cố hoặc rollout. Mẫu từ đối tượng đã cảnh báo, bị ban hoặc được whitelist để miễn kiểm tra không được cập nhật baseline. Mỗi IP có giới hạn đóng góp vào một cửa sổ. Dùng thống kê phân vị trên các mẫu đủ điều kiện để giảm ảnh hưởng của giá trị cực đoan. Khi app đổi contract hoặc route, mở thế hệ baseline mới và giữ ở chế độ cảnh báo đến khi có đủ dữ liệu.

Operator duyệt baseline tham chiếu đầu tiên. Sau đó tác vụ nội bộ tự tạo ứng viên định kỳ và chỉ tự nâng phiên bản khi chất lượng dữ liệu đạt và biến động nằm trong biên operator cấu hình quanh baseline đã duyệt. Biên này cố định cho đến lần duyệt sau. Mẫu thiếu, phân phối đổi mạnh hoặc tỷ lệ báo nhầm tăng sẽ giữ baseline hiện hành và báo cần xem xét. Phiên bản và thời điểm cập nhật được lưu cùng audit, có thể quay lại phiên bản trước. Học baseline không đổi contract và không tự bật `autoban`.

Kế hoạch triển khai chọn thuật toán thống kê, thời gian giữ baseline, mức mẫu, biên thay đổi, số cửa sổ liên tiếp và ngân sách dựa trên traffic đã đo. Operator phải đưa các giá trị đã chọn vào cấu hình kiểm thử trước khi cho phép ban. Nếu thiếu baseline, vẫn chạy cảnh báo contract.

## Kiểm chứng trước khi bật autoban

- Dùng POST tổng hợp vô hại để kiểm tra đường đi thật qua HAProxy, Coraza upstream và wafguard. Có ca sai contract tạo cảnh báo với Coraza không có verdict và origin HTTP 200, cùng ca bình thường không tạo cảnh báo.
- Kiểm thử các quyết định kết thúc request của Coraza và lỗi Coraza khiến HAProxy từ chối. Xác nhận verdict cũ vẫn đến policy, frame `waf-verdict` không chứa body, số lượt phân tích body ở wafguard bằng 0 và request không góp vào baseline hoặc autoban mới. Với Coraza detection-only và một POST vẫn được chuyển tiếp, xác nhận kiểm tra contract vẫn chạy nếu đủ điều kiện.
- Kiểm tra JSON thiếu, bị cắt, sai cấu trúc, quá sâu, quá lớn, khác parser, không xác định độ dài và body đến chậm. Kiểm tra route ngoài cấu hình, HTTP/2, Redis chậm, retry và cấu hình đổi giữa admission và verdict.
- Chứng minh `warning` không tạo ban, `autoban` cần đủ bằng chứng, ban có TTL và chỉ áp dụng đúng app trên hai replica. Chạy lại với whitelist, unban, mode rollback, ban từ policy khác, và Redis mất kết nối hoặc đổi primary.
- Chạy shadow với traffic đã gắn nhãn hoặc lấy mẫu do operator đánh giá. Báo tỷ lệ cảnh báo đúng, tỷ lệ báo nhầm, phần trăm POST đủ dữ liệu, p95/p99 và số lượt Redis. So sánh với lần chạy feature tắt. Operator duyệt ngưỡng chất lượng, phạm vi quan sát và ngân sách độ trễ cho từng app trước khi bật ban.
- Kiểm tra không có giá trị fixture nhạy cảm trong log, metrics, Redis, dữ liệu học và egress. Đối với ca SQLi đã xảy ra, dùng bằng chứng nội bộ được phép để xác minh tín hiệu phát hiện và bản sửa truy vấn. Spec và fixture chia sẻ dùng dữ liệu tổng hợp.

## Điều kiện để xem xét LLM sau bản đầu

Chỉ thử nếu kết quả shadow cho thấy các cụm khó phân loại đủ nhiều và có bộ dữ liệu gắn nhãn để so sánh. LLM chạy ngoài luồng request, với giới hạn lượt gọi và chi phí. Adapter xuất dữ liệu theo danh sách trường cho phép, gồm số liệu chia khoảng và mã tín hiệu, loại bỏ nhóm quá ít mẫu. Có kiểm tra egress và test chống lọt dữ liệu. Đầu ra là phân loại hoặc giải thích cho operator. Policy nội bộ vẫn giữ quyền thực thi.

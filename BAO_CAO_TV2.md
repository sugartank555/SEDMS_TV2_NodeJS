# Đặc tả Giai đoạn 1 — Mã hóa và phê duyệt tài liệu (TV2, Node.js)

## Mục tiêu và phạm vi

Module TV2 bảo vệ bí mật tài liệu lưu trữ và chỉ cho phép phát hành khi có hai người phê duyệt độc lập. Prototype gồm mã hóa phong bì AES-256-GCM và chính sách hai chữ ký ECDSA P-256. Module cung cấp hàm Node.js để tích hợp, chưa gồm đăng nhập, API, DB, nhật ký bất biến, FIM và liên kết chia sẻ.

## Mã hóa phong bì

Đầu vào là byte tài liệu, mã tài liệu, phiên bản và KEK 256 bit do môi trường tin cậy cung cấp. Hệ thống tính SHA-256 của bản rõ và đưa vào manifest cùng mã tài liệu, phiên bản, thuật toán và định dạng giao thức. Manifest được tuần tự hóa JSON xác định để sử dụng thống nhất khi ký và làm dữ liệu xác thực bổ sung (AAD).

Mỗi tài liệu được cấp một DEK 256 bit ngẫu nhiên. AES-256-GCM mã hóa nội dung bằng DEK với nonce 96 bit. DEK được mã hóa bảo vệ bằng KEK qua một thao tác AES-256-GCM khác, có nonce riêng và AAD được phân biệt mục đích. Thư viện Node.js trả tag 128 bit riêng; package lưu tag cạnh nonce và ciphertext. Base64 chỉ là cách biểu diễn dữ liệu nhị phân trong JSON, không phải thuật toán mã hóa.

Khi giải mã, hệ thống dùng KEK để phục hồi DEK, dùng DEK để phục hồi nội dung, sau đó đối chiếu SHA-256. Sai khóa, sai tag hoặc thay đổi AAD làm quá trình giải mã thất bại. Hash bản mã được cung cấp riêng để TV3 có thể quét tệp mã hóa; cần bảo vệ giá trị tham chiếu khi tích hợp.

Nonce ngẫu nhiên phải được quản lý để tránh trùng dưới cùng khóa; hệ thống quy mô lớn cần chính sách giới hạn lượng sử dụng và luân chuyển KEK. Bản demo không triển khai KMS hoặc theo dõi vòng đời khóa qua nhiều lần chạy.

## Ký số và xác minh 2-of-2

Hai người phê duyệt có hai cặp khóa ECDSA P-256 độc lập. Người ký tạo chữ ký bằng khóa riêng trên manifest. Bên xác minh sử dụng khóa công khai gắn với danh tính đã đăng ký. Module từ chối hai danh tính dùng cùng khóa công khai và từ chối người ký ngoài danh sách cho phép.

Mỗi chữ ký được xác minh trước khi ghi nhận. Một người chỉ đóng góp một lần vào ngưỡng. Trạng thái ban đầu là `PENDING_APPROVAL`; một chữ ký hợp lệ cho trạng thái `PENDING_SECOND_SIGNATURE`; đủ hai chữ ký hợp lệ mới là `ISSUED`. Cổng `requireIssued()` xác minh lại và từ chối phát hành nếu thiếu chữ ký.

Hai chữ ký độc lập ở đây là chính sách phê duyệt của ứng dụng, không phải thuật toán chữ ký ngưỡng tổng hợp. Chữ ký được lưu rời, không nhúng vào PDF. Khi thay đổi nội dung hay phiên bản phải tạo manifest và đợt duyệt mới.

## Kịch bản và bằng chứng kiểm thử

| Mã | Thực hiện trong prototype | Kết quả đã quan sát | Bằng chứng cần nhóm tự chụp |
|---|---|---|---|
| TC-NORM-01 (phần TV2) | Mã hóa PDF, bọc DEK, giải mã | Byte và SHA-256 phục hồi trùng bản gốc | CMD + PDF gốc/phục hồi |
| TC-SEC-03 (mô phỏng quyền ký bị chiếm) | Admin 1 ký rồi yêu cầu phát hành, thử ký lặp | Thiếu 1 chữ ký và ký trùng bị chặn | CMD có 1/2 và thông báo từ chối |
| TC-NORM-02 (phần TV2) | Admin 2 ký cùng manifest | Hai chữ ký được xác minh; trạng thái ISSUED | CMD có 2/2 |

Trong môi trường chuẩn bị, ba luồng demo chạy thành công và 10 kiểm thử tự động đạt. Thời gian và kết quả cụ thể được ghi trong `KET_QUA_DEMO.txt`, `KET_QUA_KIEM_THU.txt`. Môi trường thực chạy: Node.js v24.22.1; máy người dùng hiển thị v24.21.0 và cần kiểm thử lại tại đó. Chưa có bằng chứng đăng nhập thật, HTTP 403, log CHAIN_VALID, trạng thái DB hoặc giao diện chia sẻ; các tiêu chí đó chỉ được xác nhận sau khi ghép các module của nhóm và kiểm thử lại.

## Giới hạn và yêu cầu tích hợp

Danh sách người ký, khóa công khai, manifest và chính sách phê duyệt là dữ liệu tin cậy cần được bảo vệ. Nếu kẻ tấn công điều khiển cả tiến trình xác minh hoặc thay thế tùy ý gốc tin cậy thì riêng chữ ký trong prototype không bảo đảm ngăn phát hành giả. Mô hình chỉ chứng minh khả năng chặn khi một danh tính/khóa bị chiếm trong khi người ký thứ hai và bộ xác minh còn tin cậy.

Trạng thái demo nằm trong RAM. Backend hoàn chỉnh cần xác thực, phân quyền, kiểm soát đồng thời, lưu bền chữ ký, xác minh lại khi phát hành và ghi nhật ký qua TV3. KEK phải được quản lý bền vững ở kho bí mật riêng; khóa riêng của từng người phải được bảo vệ độc lập. Kiểm tra header PDF trong demo chưa thay thế xác thực PDF/A hay quét mã độc.

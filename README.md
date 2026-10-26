# SEDMS — Thành viên 2 — Node.js

Phần việc: mã hóa phong bì AES-256-GCM và phê duyệt tài liệu bằng hai chữ ký ECDSA P-256 độc lập (2-of-2).

## 1. Mở và chạy trên Windows

Ảnh môi trường của bạn hiển thị Node.js v24.21.0 và npm 11.19.0. Mã dùng các thư viện có sẵn `node:crypto`, `node:fs`, `node:test`; không cần cài package npm, không cần Python hoặc VMware để chạy demo riêng TV2.

1. Giải nén gói ZIP.
2. Mở thư mục có `package.json` và `demo.js`.
3. Bấm thanh địa chỉ File Explorer, nhập `cmd`, Enter.
4. Gõ:

```bat
node demo.js
```

Hoặc `npm run demo`. Chạy PDF riêng:

```bat
node demo.js --file "D:\TaiLieu\HopDong.pdf"
```

Chương trình mặc định tạo PDF mẫu và tự chạy các tình huống. Đầu ra nằm trong thư mục `output` cạnh demo.js. Mỗi lần chạy sinh khóa mới trong RAM và ghi đè bằng chứng demo cũ; muốn giữ từng lần chạy hãy sao chép output trước lần tiếp theo. Bản PDF bạn truyền vào chỉ được đọc, không bị sửa.

## 2. Các bước cần hiểu và chụp ảnh

### A. Tải tài liệu, mã hóa và giải mã đối chiếu — TC-NORM-01

- Tính SHA-256 của byte PDF gốc.
- Sinh DEK 32 byte riêng cho tài liệu.
- Mã hóa PDF bằng AES-256-GCM với DEK, nonce 12 byte, tag 16 byte.
- Bọc DEK bằng KEK 32 byte bằng thao tác GCM riêng, nonce riêng.
- Giải bọc DEK và giải mã nội dung, đối chiếu byte và SHA-256 với bản gốc.

**CHỤP ẢNH 1:** CMD có `TC-NORM-01: PASS` và hai dòng SHA-256 giống nhau.

**CHỤP ẢNH 2:** mở `output/document_original.pdf` và `output/document_recovered.pdf` để đối chiếu nội dung.

`document.enc` là phần ciphertext nhị phân, không phải PDF để mở bằng trình đọc PDF. `package.json` lưu nonce, tag, bản mã, DEK đã bọc và manifest; không chứa DEK/KEK bản rõ. Tag GCM được lưu riêng trong gói Node.js này.

Kiểm tra header `%PDF-` mới là kiểm tra sơ bộ, chưa kiểm tra toàn bộ PDF/A hay quét mã độc. TC-NORM-01 của hệ thống đầy đủ còn yêu cầu kiểm tra audit chain; bộ TV2 chưa có phần đó. Cần ghép log của TV3 rồi kiểm thử lại.

### B. Chỉ một Admin ký — TC-SEC-03

Demo giả lập bên tấn công đã dùng được quyền ký của Admin 1, sau đó thử phát hành. Kết quả:

```text
Admin 1 signed: PENDING_SECOND_SIGNATURE (1/2)
TC-SEC-03: PASS - publication/share gate BLOCKED: INSUFFICIENT_SIGNATURES (1/2)
Admin 1 signs again: BLOCKED - DUPLICATE_APPROVER (still 1/2)
```

**CHỤP ẢNH 3:** ba dòng trên. Một người ký nhiều lần vẫn không được tính thành hai người.

Đây là mô phỏng quyền ký bị chiếm, chưa có trang đăng nhập thật. `requireIssued()` ném lỗi khi chưa đủ chữ ký; backend phải gọi hàm này và ánh xạ lỗi sang HTTP 403 trước khi phát hành hoặc cấp liên kết.

### C. Admin thứ hai ký — TC-NORM-02

Admin 2 ký đúng manifest bằng khóa riêng độc lập. Hệ thống xác minh chữ ký bằng khóa công khai đã đăng ký. Sau hai chữ ký hợp lệ:

```text
TC-NORM-02: PASS - two verified signatures -> ISSUED (2/2)
```

**CHỤP ẢNH 4:** dòng trên. Các chữ ký xuất ra `output/signatures.json`; khóa công khai nằm trong `admin1_public.pem`, `admin2_public.pem`.

Demo tự thực thi tuần tự tất cả các bước A–C trong một lần chạy. Bạn có thể phóng to CMD hoặc chụp toàn bộ cửa sổ có đủ kết quả, rồi cắt các phần tương ứng cho báo cáo.

## 3. Chạy kiểm thử

```bat
node --test test_tv2.js
```

Hoặc `npm test`.

**CHỤP ẢNH 5:** kết quả có `tests 10`, `pass 10`, `fail 0`.

Các kiểm tra gồm: giải mã phục hồi đúng; mỗi lần mã hóa cho kết quả khác; sửa ciphertext, nonce hoặc tag bị từ chối; sửa DEK đã bọc bị từ chối; sai KEK bị từ chối; thay mã tài liệu/phiên bản/hash làm xác minh thất bại; hai người ký thành công; một người và ký trùng không phát hành được; sai khóa/người ký ngoài danh sách bị từ chối; hai danh tính dùng chung khóa bị từ chối; sửa chữ ký bị từ chối; không sửa được bản sao chữ ký đã ghi nhận qua Buffer của người gọi; khóa riêng PKCS#8 có mật khẩu xuất/đọc được và mật khẩu sai bị chặn.

`KET_QUA_DEMO.txt` và `KET_QUA_KIEM_THU.txt` là kết quả thực chạy trong môi trường chuẩn bị Node.js v24.22.1. Bạn cần chạy lại trên máy mình để có bằng chứng của nhóm; không coi các file này là ảnh chụp trên máy bạn.

## 4. File bàn giao

| File | Vai trò |
|---|---|
| crypto_engine.js | Mã hóa phong bì, giải mã, SHA-256 và manifest xác định |
| multisig_service.js | Sinh khóa, xuất/đọc khóa riêng được mã hóa, ký/xác minh và chính sách 2-of-2 |
| demo.js | Chạy ba tình huống, ghi bằng chứng đầu ra |
| test_tv2.js | 10 kiểm thử tự động |
| BAO_CAO_TV2.md | Nội dung để ghép phần đặc tả kỹ thuật trong báo cáo |

Hai chữ ký ECDSA là chữ ký rời do ứng dụng kiểm tra; chưa phải chữ ký nhúng PAdES và không phải một chữ ký ngưỡng tổng hợp từ giao thức mật mã phân tán.

## 5. Ghép code với nhóm

TV1 import CommonJS:

```js
const { newKek, encryptDocument, decryptDocument } = require('./crypto_engine');
const { MultiSigService, signManifest } = require('./multisig_service');
```

Luồng tích hợp:

1. Nhận PDF và xác thực người tải lên; kiểm tra dung lượng, định dạng, mã độc ở backend.
2. Cấp mã/phiên bản tài liệu, gọi `encryptDocument(pdfBuffer, docId, version, kek)`; lưu package và manifest vào vùng lưu trữ tin cậy.
3. Đăng ký hai khóa công khai gắn với hai danh tính đã xác minh. Không cho người gọi tự đổi khóa công khai, danh sách người ký hoặc ngưỡng duyệt.
4. Mỗi người giữ khóa riêng độc lập để ký đúng manifest, gửi chữ ký về backend; gọi `submitSignature(actor, signatureBuffer)` sau khi xác thực/kiểm tra quyền actor.
5. Gọi `requireIssued()` trước khi phát hành/cấp link. Ghi các sự kiện tải lên, ký, từ chối, phát hành bằng module audit của TV3.
6. Khi thay nội dung/phiên bản, mở đợt duyệt mới; chữ ký cũ không áp dụng cho phiên bản mới.

Manifest ký gồm docId, version, SHA-256 của bản rõ, thuật toán và schema. Hàm `canonicalManifest` áp đặt định dạng cố định; nhóm phải giữ cùng định dạng giữa các bên ký/xác minh.

`MultiSigService` chỉ giữ trạng thái trong RAM. Backend thật cần lưu chữ ký bền vững, transaction/kiểm soát đồng thời, ràng buộc duy nhất theo tài liệu + phiên bản + người ký và phục hồi/xác minh lại các chữ ký bằng khóa công khai tin cậy khi đọc DB. Không chỉ tin vào cột trạng thái `ISSUED`.

FIM của TV3 quét `document.enc` phải đối chiếu với `cipherSha256` có nguồn tin cậy; không so hash ciphertext với hash PDF gốc. Nếu FIM quét toàn bộ package thì phải tạo thêm baseline cho toàn bộ file package. TV4 kiểm tra đủ chữ ký cùng trạng thái thu hồi/cách ly và toàn vẹn trước khi cấp/trả tài liệu.

## 6. Quản lý khóa và giới hạn của prototype

- KEK chỉ tồn tại trong RAM và được sinh mới mỗi lần demo. Package cũ không giải mã lại được sau khi chương trình kết thúc; PDF phục hồi được tạo trong cùng lần chạy. Hệ thống thật cần KEK bền vững trong kho bí mật/KMS riêng, mã phiên bản khóa và quy trình sao lưu/luân chuyển.
- Khóa riêng hai Admin trong demo được sinh trong cùng tiến trình để trình diễn. Triển khai thật phải để từng người kiểm soát khóa, có xác thực và phân quyền; demo chưa có đăng nhập/MFA.
- Có hàm `encryptedPrivatePem` và `loadPrivatePem` cho khóa PKCS#8 có mật khẩu nếu nhóm cần lưu khóa. Cấp mật khẩu qua cơ chế riêng, không đặt khóa hoặc mật khẩu thật trong Git.
- DEK/KEK Buffer được ghi đè khi kết thúc phạm vi sử dụng, nhưng JavaScript/OpenSSL có thể giữ bản sao; không tuyên bố đảm bảo xóa sạch mọi khóa khỏi RAM.
- Nonce phải không lặp dưới cùng khóa; bản demo sinh ngẫu nhiên 96 bit. Khi triển khai cần chính sách giới hạn số lần sử dụng/luân chuyển khóa.
- Bản rõ được ghi ra đĩa để đối chiếu demo; hệ thống thật cần kiểm soát quyền truy cập và thời gian lưu bản rõ.
- Bảo vệ được tình huống một người/khóa bị chiếm trong khi người thứ hai và bộ xác minh còn tin cậy. Không bảo đảm chống giả mạo nếu cả hai khóa hoặc gốc tin cậy/bộ xác minh bị kiểm soát.

## 7. Câu trả lời ngắn khi bảo vệ

- **DEK và KEK khác nhau thế nào?** DEK mã hóa từng tài liệu; KEK bảo vệ các DEK.
- **AES-GCM có tác dụng gì?** Giữ bí mật và phát hiện sửa đổi qua tag xác thực.
- **SHA-256 dùng làm gì?** Đại diện nội dung để đối chiếu; chữ ký ràng buộc người ký với manifest chứa hash đó.
- **Một Admin ký hai lần được không?** Không, ngưỡng yêu cầu hai danh tính với hai khóa độc lập.
- **Có phải chữ ký số trong PDF không?** Bộ này dùng chữ ký rời của ứng dụng, chưa nhúng chữ ký PAdES.

Thứ tự thực hiện: chạy demo → chạy kiểm thử → chụp 5 ảnh → đọc hai module → cập nhật báo cáo theo kết quả thực tế → ghép backend với nhóm.

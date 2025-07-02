
README - Chương trình Mã hóa và Giải mã Email
=============================================

🔐 MỤC TIÊU
-----------
Chương trình thực hiện:
- Mã hóa nội dung email bằng AES-CBC.
- Mã hóa khóa phiên AES bằng RSA.
- Ký số nội dung bằng RSA + SHA-512.
- Ghi gói tin vào encrypted.json.
- Giải mã nếu gói tin còn hạn và chữ ký hợp lệ.


📁 CẤU TRÚC THƯ MỤC
-------------------
.
├── email.txt                  # Nội dung email gốc
├── email_decrypted.txt       # Email sau khi giải mã
├── encrypted.json            # Gói tin mã hóa
├── sender.py                 # Chương trình mã hóa và ký
├── receiver.py               # Chương trình giải mã và xác thực
├── gen_keys.py               # Tạo cặp khóa RSA
└── rsa_keys/
    ├── sender_private.pem
    ├── sender_public.pem
    ├── receiver_private.pem
    └── receiver_public.pem


▶️ CÁCH CHẠY CHƯƠNG TRÌNH
-------------------------

1. Cài đặt thư viện cần thiết
    pip install pycryptodome

2. Tạo khóa RSA
    python gen_keys.py
    ✅ Tạo các cặp khóa RSA 2048-bit cho sender và receiver trong thư mục rsa_keys.

3. Tạo file mã hóa
    python sender.py
    ✅ Đọc nội dung từ email.txt, mã hóa bằng AES-CBC, ký SHA-512, mã hóa khóa AES bằng RSA → xuất encrypted.json.

4. Giải mã và xác minh
    python receiver.py
    ✅ Kiểm tra hạn sử dụng (exp) và chữ ký. Nếu hợp lệ → giải mã AES và lưu vào email_decrypted.txt.


⏰ QUẢN LÝ HẠN SỬ DỤNG
---------------------
- Gói tin có trường "exp" (thời gian hết hạn, định dạng UTC ISO).
- Nếu quá hạn → từ chối giải mã.


🛡️ BẢO MẬT
----------
- AES-CBC (256-bit) dùng để mã hóa nội dung.
- RSA (2048-bit) dùng để mã hóa khóa phiên.
- Chữ ký số đảm bảo toàn vẹn dữ liệu và xác thực người gửi.
- SHA-512 để tạo hash cho nội dung cần ký.


📌 LƯU Ý
--------
- Nội dung email.txt nên là dạng văn bản thuần (.txt).
- File encrypted.json có thể chia sẻ công khai.
- Chỉ người có khóa riêng receiver_private.pem mới giải mã được.


# **BMC Cryptographic - Flutter Plugin**

Một plugin Flutter đa nền tảng, hiệu năng cao, cung cấp các chức năng mật mã tiêu chuẩn bằng cách sử dụng `dart:ffi` để giao tiếp với một lõi thư viện C đã được kiểm chứng.

## Giới thiệu

`bmc_cryptographic_flutter` mang đến một giải pháp đơn giản và an toàn để thực hiện các tác vụ mã hóa và băm phổ biến trực tiếp trong ứng dụng Flutter của bạn. Bằng cách thực thi các thuật toán phức tạp trên mã C gốc, plugin đảm bảo hiệu năng vượt trội so với các triển khai bằng Dart thuần, đồng thời cung cấp một API Dart đơn giản và dễ sử dụng.

## Done
Thêm Isolate riêng biệt để không làm ảnh hưởng đến luồng giao diện người dùng (UI thread). Xem `example/lib/main.dart` hàm `funcAliceBobTestAsync`

## Tính năng

* **Trao đổi khóa & Mã hóa End-to-End (E2EE):**
    * **Trao đổi khóa:** Sử dụng **Elliptic Curve Diffie-Hellman (ECDH)** trên đường cong Curve25519 để thiết lập khóa bí mật chung.
* **Mã hóa AES:**
    * **Kích thước khóa:** Hỗ trợ 128, 192, và 256-bit.
    * **Chế độ hoạt động:** Hỗ trợ CBC, ECB, và CTR.
    * **Đệm (Padding):** Tự động xử lý đệm PKCS\#7 cho chế độ CBC.
* **Hàm băm (Hashing):**
    * **SHA-2:** Triển khai SHA-256.
    * **SHA-3:** Triển khai SHA3-256, SHA3-384, và SHA3-512.
* **Hiệu năng cao:** Toàn bộ logic mật mã được xử lý bởi mã C gốc đã được tối ưu.
* **Đa nền tảng:** Hỗ trợ đầy đủ cho Android, iOS, Windows, Linux, và macOS.

## Hỗ trợ Nền tảng

| Android | iOS | Linux | macOS | Windows |
| :---: |:---:|:---:|:---:|:---:|
|   ✅   |  ✅  |   ✅   |   ✅   |    ✅    |

## Cài đặt

Thêm dependency sau vào file `pubspec.yaml` của dự án Flutter của bạn:

```yaml
dependencies:
  flutter:
    sdk: flutter
  
  # Sử dụng path nếu bạn đang phát triển cục bộ
  bmc_cryptographic_flutter:
    path: ../path/to/your/plugin/bmc_cryptographic_flutter

  # Hoặc sử dụng git
  # bmc_cryptographic_flutter:
  #   git:
  #     url: https://github.com/phamhungdg96/bmc_crypto_flutter.git
```

Sau đó, chạy lệnh sau trong terminal:

```bash
flutter pub get
```

## Hướng dẫn sử dụng

Vui lòng xem file `example/lib/main.dart`

## Tham chiếu API

Vui lòng xem file `lib/bmc_cryptographic_flutter.dart`, `lib/bmc_protocol.dart` để có danh sách đầy đủ các hàm được hỗ trợ.

## Giấy phép

Dự án này được phát triển của BMC T\&S JSC
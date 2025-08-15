
# **BMC Cryptographic - Flutter Plugin**

Một plugin Flutter đa nền tảng, hiệu năng cao, cung cấp các chức năng mật mã tiêu chuẩn bằng cách sử dụng `dart:ffi` để giao tiếp với một lõi thư viện C đã được kiểm chứng.

## Giới thiệu

`bmc_cryptographic_flutter` mang đến một giải pháp đơn giản và an toàn để thực hiện các tác vụ mã hóa và băm phổ biến trực tiếp trong ứng dụng Flutter của bạn. Bằng cách thực thi các thuật toán phức tạp trên mã C gốc, plugin đảm bảo hiệu năng vượt trội so với các triển khai bằng Dart thuần, đồng thời cung cấp một API Dart đơn giản và dễ sử dụng.

Toàn bộ các tác vụ nặng sẽ được thực thi trên một Isolate riêng biệt để không làm ảnh hưởng đến luồng giao diện người dùng (UI thread).

## Tính năng

* **Trao đổi khóa & Mã hóa End-to-End (E2EE):**
    * **Trao đổi khóa:** Sử dụng **Elliptic Curve Diffie-Hellman (ECDH)** trên đường cong Curve25519 để thiết lập khóa bí mật chung.
    * **Mã hóa phiên:** Sử dụng **ChaCha20-Poly1305**, một thuật toán mã hóa đã xác thực (AEAD) hiện đại và hiệu quả.
* **Mã hóa AES:**
    * **Kích thước khóa:** Hỗ trợ 128, 192, và 256-bit.
    * **Chế độ hoạt động:** Hỗ trợ CBC, ECB, và CTR.
    * **Đệm (Padding):** Tự động xử lý đệm PKCS\#7 cho chế độ CBC và ECB.
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
  #     url: https://github.com/bmctechvn/bmc_crypto_flutter.git
```

Sau đó, chạy lệnh sau trong terminal:

```bash
flutter pub get
```

## Hướng dẫn sử dụng

Import package và sử dụng đối tượng singleton `BmcCrypto` để truy cập tất cả các hàm.

```dart
import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart';
import 'dart:convert';
import 'dart:typed_data';
```

### Ví dụ 1: Trao đổi khóa và Mã hóa End-to-End

Đây là một luồng hoàn chỉnh để thiết lập một kênh liên lạc an toàn giữa hai bên (Alice và Bob).

```dart
Future<void> testSecureSession() async {
  final crypto = BmcCrypto();

  print('--- Secure Session E2EE Test ---');

  // 1. Khởi tạo thư viện (nên gọi một lần khi ứng dụng bắt đầu)
  crypto.sessionInit();
  print('Init OK');

  // 2. Mỗi bên tạo cặp khóa định danh của riêng mình
  final aliceKeyPair = await crypto.sessionGenerateKeyPair();
  final bobKeyPair = await crypto.sessionGenerateKeyPair();
  if (aliceKeyPair == null || bobKeyPair == null) {
    print('Lỗi: Không thể tạo cặp khóa!');
    return;
  }
  print('Tạo khóa cho Alice và Bob thành công.');

  // 3. Bắt đầu phiên làm việc an toàn
  // Alice là người gọi (isInitiator: true)
  final aliceSession = await crypto.sessionStart(
    myPk: aliceKeyPair.pk,
    mySk: aliceKeyPair.sk,
    theirPk: bobKeyPair.pk,
    isInitiator: true,
  );
  // Bob là người nhận cuộc gọi
  final bobSession = await crypto.sessionStart(
    myPk: bobKeyPair.pk,
    mySk: bobKeyPair.sk,
    theirPk: aliceKeyPair.pk,
    isInitiator: false,
  );

  if (aliceSession == 0 || bobSession == 0) {
    print('Lỗi: Không thể bắt đầu phiên!');
    return;
  }
  print('Bắt đầu phiên thành công.');

  // 4. Alice mã hóa và gửi tin nhắn
  final message = "Flutter E2EE is working!";
  final plaintext = Uint8List.fromList(utf8.encode(message));
  print('Tin nhắn gốc: "$message"');

  final ciphertext = await crypto.sessionEncrypt(sessionHandle: aliceSession, plaintext: plaintext);
  if (ciphertext == null) {
    print('Lỗi: Mã hóa thất bại!');
    return;
  }
  print('Mã hóa thành công.');

  // 5. Bob nhận và giải mã tin nhắn
  final decrypted = await crypto.sessionDecrypt(sessionHandle: bobSession, ciphertext: ciphertext);
  if (decrypted == null) {
    print('Lỗi: Giải mã thất bại!');
    return;
  }
  final decryptedMessage = utf8.decode(decrypted);
  print('Tin nhắn đã giải mã: "$decryptedMessage"');

  // 6. Xác minh kết quả
  assert(message == decryptedMessage);
  print('✅ Secure Session Test PASSED!');

  // 7. Hủy phiên làm việc để giải phóng bộ nhớ
  await crypto.sessionDestroy(sessionHandle: aliceSession);
  await crypto.sessionDestroy(sessionHandle: bobSession);
  print('Đã hủy phiên.');
}
```

### Ví dụ 2: Mã hóa & Giải mã AES-256-CBC

```dart
Future<void> testAes256Cbc() async {
  final crypto = BmcCrypto();
  final plaintext = Uint8List.fromList(utf8.encode("Đây là một tin nhắn bí mật!"));
  final key = Uint8List.fromList(utf8.encode("my-super-secret-key-for-aes256")); // 32 bytes
  final iv = Uint8List.fromList(utf8.encode("my-unique-iv-001")); // 16 bytes

  print('\n--- AES-256-CBC Test ---');
  print('Plaintext: ${utf8.decode(plaintext)}');

  // Mã hóa
  final ciphertext = await crypto.aes256CbcEncrypt(plaintext: plaintext, key: key, iv: iv);
  if (ciphertext == null) {
    print('Encryption failed!');
    return;
  }

  // Giải mã
  final decrypted = await crypto.aes256CbcDecrypt(ciphertext: ciphertext, key: key, iv: iv);
  if (decrypted == null) {
    print('Decryption failed!');
    return;
  }
  print('Decrypted: ${utf8.decode(decrypted)}');

  assert(listEquals(plaintext, decrypted));
  print('✅ AES-256-CBC Test PASSED!');
}
```

### Ví dụ 3: Băm SHA3-512

```dart
Future<void> testSha3_512() async {
  final crypto = BmcCrypto();
  final dataToHash = Uint8List.fromList(utf8.encode("")); // Chuỗi rỗng
  final expectedHash = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";

  print('\n--- SHA3-512 Test ---');
  print("Input: '' (empty string)");

  final hash = await crypto.sha3_512(dataToHash);
  if (hash != null) {
      final hexHash = hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      print('Actual hash:   $hexHash');
      print('Expected hash: $expectedHash');
      assert(hexHash == expectedHash);
      print('✅ SHA3-512 Test PASSED!');
  }
}
```

## Tham chiếu API

Vui lòng xem file `lib/bmc_cryptographic_flutter.dart` để có danh sách đầy đủ các hàm được hỗ trợ.

## Giấy phép

Dự án này được phát triển của BMC T\&S JSC
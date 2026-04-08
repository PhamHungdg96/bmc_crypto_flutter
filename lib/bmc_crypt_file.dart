import 'dart:io';
import 'dart:typed_data';
import 'package:path/path.dart' as p;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;
final crypto = libcrypt.BmcCrypto();

/// Trả về đường dẫn đầu ra trong thư mục tạm, giữ nguyên tên file gốc.
String tempPathFor(String sourcePath) =>
    p.join(Directory.systemTemp.path, p.basename(sourcePath));

/// Đọc file tại [path] theo từng chunk có kích thước [chunkSize] byte.
/// [startOffset] cho phép bỏ qua một số byte đầu (ví dụ: phần header).
Stream<Uint8List> readFileChunks(String path, int chunkSize, {int startOffset = 0}) async* {
  final raf = await File(path).open(mode: FileMode.read);
  if (startOffset > 0) await raf.setPosition(startOffset);
  var i=0;
  try {
    while (true) {
      final chunk = await raf.read(chunkSize);
      // print('break ${path} ${i} ${chunk.length}');
      if (chunk.isEmpty){
        break;
      }
      i+=1;
      yield chunk;
    }
  // }catch(e){
  //   print('e: ${e}');
  }
  finally {
    await raf.close();
  }
}

/// Ghi (nối) [bytes] vào file tại [destPath].
Future<void> appendBytes(String destPath, Uint8List bytes) async {
  final raf = await File(destPath).open(mode: FileMode.writeOnlyAppend);
  try {
    await raf.writeFrom(bytes);
  } finally {
    await raf.close();
  }
}

// Số byte dùng để lưu độ dài header (uint32 big-endian).
const int _kHeaderLenBytes = 4;

/// Khởi tạo file đích (xoá cũ nếu có).
/// Nếu [header] được cung cấp, ghi tiền tố độ dài rồi đến bytes header.
/// Format: [4 bytes BE uint32: headerLen][header bytes]
Future<void> initFile(String destPath, Uint8List? header) async {
  final f = File(destPath);
  if (header != null && header.isNotEmpty) {
    final lenBuf = ByteData(_kHeaderLenBytes)
      ..setUint32(0, header.length, Endian.big);
    await f.writeAsBytes(
      [...lenBuf.buffer.asUint8List(), ...header],
      flush: true,
    );
  } else {
    await f.writeAsBytes(const [], flush: true);
  }
}

/// Đọc phần header từ file (trả về rỗng nếu file không có header hợp lệ).
Future<Uint8List> readHeader(String path) async {
  final f = File(path);
  final size = await f.length();
  if (size < _kHeaderLenBytes) return Uint8List(0);
  final raf = await f.open();
  try {
    final lenBuf = await raf.read(_kHeaderLenBytes);
    final headerLen = ByteData.sublistView(lenBuf).getUint32(0, Endian.big);
    if (headerLen == 0 || _kHeaderLenBytes + headerLen > size) return Uint8List(0);
    return await raf.read(headerLen);
  } finally {
    await raf.close();
  }
}

/// Đọc phần thân (body) sau header.
/// Nếu file không có header hợp lệ, trả về toàn bộ nội dung.
Future<Uint8List> readBody(String path) async {
  final f = File(path);
  final size = await f.length();
  if (size < _kHeaderLenBytes) return f.readAsBytes();
  final raf = await f.open();
  try {
    final lenBuf = await raf.read(_kHeaderLenBytes);
    final headerLen = ByteData.sublistView(lenBuf).getUint32(0, Endian.big);
    final bodyStart = _kHeaderLenBytes + headerLen;
    if (bodyStart >= size) return Uint8List(0);
    await raf.setPosition(bodyStart);
    return await raf.read(size - bodyStart);
  } finally {
    await raf.close();
  }
}

/// Đọc toàn bộ nội dung file tại [path] (raw bytes, bao gồm cả header prefix).
Future<Uint8List> readAllBytes(String path) => File(path).readAsBytes();

/// Xoá file tạm.
Future<void> deleteTempFile(String path) async {
  final f = File(path);
  if (await f.exists()) await f.delete();
}


class BmcTempFile {
  final String path;

  const BmcTempFile._(this.path);

  /// Đọc toàn bộ nội dung raw (bao gồm cả header prefix nếu có).
  Future<Uint8List> readAll() => readAllBytes(path);

  /// Đọc phần header (trả về rỗng nếu file không có header).
  Future<Uint8List> getHeader() => readHeader(path);

  /// Đọc phần thân (body) sau header.
  Future<Uint8List> getBody() => readBody(path);

  /// Xoá / giải phóng dữ liệu tạm.
  Future<void> delete() => deleteTempFile(path);
}

// ---------------------------------------------------------------------------
// BmcChunkFileProcessor
// ---------------------------------------------------------------------------
class BmcChunkFileProcessor {
  final int chunkSize;

  const BmcChunkFileProcessor({this.chunkSize = 16384});

  Future<BmcTempFile> processFile(
    String sourcePath, {
    Uint8List? header,
    int bodyStartOffset = 0,
    Future<Uint8List> Function(Uint8List chunk)? transform,
  }) async {
    assert(!kIsWeb, 'processFile không hỗ trợ trên web. Dùng processBytes().');

    // Nếu sourcePath đã nằm trong thư mục tạm (destPath == sourcePath),
    // thêm suffix để tránh ghi đè lên file nguồn trước khi đọc xong.
    final rawDest = tempPathFor(sourcePath);
    final destPath = File(rawDest).absolute.path == File(sourcePath).absolute.path
        ? '$rawDest.out'
        : rawDest;

    // Khởi tạo file đích; ghi header (có length-prefix) nếu được cung cấp.
    await initFile(destPath, header);

    await for (final chunk in readFileChunks(sourcePath, chunkSize, startOffset: bodyStartOffset)) {
      final out = transform != null ? await transform(chunk) : chunk;
      await appendBytes(destPath, out);
    }

    return BmcTempFile._(destPath);
  }
}



// ---------------------------------------------------------------------------
// BmcFileEncryptor – mã hoá file theo chunk, bọc content key trong header
// ---------------------------------------------------------------------------
//
// Cấu trúc file đầu ra:
//   [4B BE: headerLen]
//   [headerLen bytes]:
//       [12B : bodyNonce   – nonce AES-GCM dùng mã hoá từng chunk]
//       [16B : wrapNonce   – nonce AES-GCM dùng bọc content key]
//       [48B : wrappedKey  – content key (32B) + GCM tag (16B)]
//   [body : các chunk đã mã hoá, nối tiếp nhau]
//
// Khoá bọc (wrapKey) được dẫn xuất ngoài lớp này (ví dụ: PBKDF / HKDF),
// người dùng truyền vào dưới dạng Uint8List 32 bytes.
// ---------------------------------------------------------------------------

class BmcFileEncryptor {
  final libcrypt.BmcCrypto _crypto;
  final int chunkSize;

  BmcFileEncryptor({
    libcrypt.BmcCrypto? crypto,
    this.chunkSize = 16384,
  }) : _crypto = crypto ?? libcrypt.BmcCrypto();

  // ── Hằng số kích thước ──────────────────────────────────────────────────
  static const int _kGcmNonceLen  = libcrypt.BMC_PROTOCOL_GCM_NONCE_LEN; // 12
  static const int _kAesNonceLen  = libcrypt.BMC_PROTOCOL_GCM_NONCE_LEN;      // 12
  static const int _kKeyLen       = libcrypt.BMC_PROTOCOL_KEY_LEN;        // 32
  static const int _kGcmTagLen    = libcrypt.BMC_PROTOCOL_GCM_TAG_LEN;    // 16
  // wrappedKey = encrypt(contentKey[32]) via AEAD → ciphertext 32B + tag 16B = 48B
  static const int _kWrappedKeyLen = _kKeyLen + _kGcmTagLen;              // 48
  // header payload = bodyNonce(12) + wrapNonce(16) + wrappedKey(48) = 76B
  static const int _kHeaderPayloadLen = _kGcmNonceLen + _kAesNonceLen + _kWrappedKeyLen; // 76

  // ── Mã hoá ──────────────────────────────────────────────────────────────

  /// Mã hoá file tại [sourcePath], bọc content key bằng [wrapKey] (32 bytes),
  /// ghi kết quả vào thư mục tạm giữ nguyên tên file, trả về [BmcTempFile].
  Future<BmcTempFile> encryptFile(
    String sourcePath,
    Uint8List wrapKey,
  ) async {
    assert(wrapKey.length == _kKeyLen, 'wrapKey phải đúng 32 bytes');
    assert(!kIsWeb, 'encryptFile không hỗ trợ web. Dùng encryptBytes().');

    final header = _buildHeader(wrapKey);
    final contentKey = header.$1;
    final bodyNonce  = header.$2;
    final headerBytes = header.$3;
    // print('contentKey: ${contentKey}');
    
    Uint8List prevTag = Uint8List(0);
    final processor = BmcChunkFileProcessor(chunkSize: chunkSize);
    return processor.processFile(
      sourcePath,
      header: headerBytes,
      transform: (chunk) async {
        final out = _encryptChunk(chunk, contentKey, bodyNonce, prevTag);
        prevTag = out.sublist(out.length - _kGcmTagLen);
        return out;
      },
    );
  }

  // ── Giải mã ─────────────────────────────────────────────────────────────

  /// Giải mã file tại [sourcePath] (đã được mã hoá bởi [encryptFile]),
  /// dùng [wrapKey] để mở khoá content key trong header.
  /// Ghi plaintext vào thư mục tạm với cùng tên file, trả về [BmcTempFile].
  Future<BmcTempFile> decryptFile(
    String sourcePath,
    Uint8List wrapKey,
  ) async {
    assert(wrapKey.length == _kKeyLen, 'wrapKey phải đúng 32 bytes');
    assert(!kIsWeb, 'decryptFile không hỗ trợ web. Dùng decryptBytes().');

    final headerBytes = await readHeader(sourcePath);
    final keys = _parseHeader(headerBytes, wrapKey);
    final contentKey = keys.$1;
    final bodyNonce  = keys.$2;
    // print('contentKey: ${contentKey} \n ${sourcePath}');

    // Tính offset bắt đầu phần body: bỏ qua [4B headerLen] + [headerPayload]
    final bodyStartOffset = _kHeaderLenBytes + headerBytes.length;

    Uint8List prevTag = Uint8List(0);
    final processor = BmcChunkFileProcessor(chunkSize: chunkSize + _kGcmTagLen);
    return processor.processFile(
      sourcePath,
      bodyStartOffset: bodyStartOffset,
      // Không ghi header vào file giải mã
      transform: (chunk) async {
        final tag = chunk.sublist(chunk.length - _kGcmTagLen);
        final out = _decryptChunk(chunk, contentKey, bodyNonce, prevTag);
        prevTag = tag;
        return out;
      },
    );
  }

  // ── Helpers nội bộ ──────────────────────────────────────────────────────
  /// Tạo content key và nonce ngẫu nhiên, bọc content key bằng wrapKey.
  /// Trả về (contentKey, bodyNonce, headerPayloadBytes).
  (Uint8List, Uint8List, Uint8List) _buildHeader(Uint8List wrapKey) {
    final contentKey = _crypto.rand(_kKeyLen);        // 32B
    final bodyNonce  = _crypto.rand(_kGcmNonceLen);   // 12B – nonce GCM cho body
    final wrapNonce  = _crypto.rand(_kAesNonceLen);   // 12B – nonce AES-GCM wrap

    // Bọc content key: encryptAEAD(contentKey, aad=[], wrapKey, wrapNonce)
    // Kết quả: 32B ciphertext + 16B tag = 48B nhờ AEAD appends tag
    final wrappedKey = _crypto.encryptAEAD(
      contentKey,
      Uint8List(0),   // aad rỗng
      wrapKey,
      wrapNonce,
    );

    // header = bodyNonce(12) || wrapNonce(16) || wrappedKey(48)
    final header = BytesBuilder()
      ..add(bodyNonce)
      ..add(wrapNonce)
      ..add(wrappedKey);

    return (contentKey, bodyNonce, header.toBytes());
  }

  /// Giải mã header, khôi phục content key và body nonce.
  (Uint8List, Uint8List) _parseHeader(Uint8List headerBytes, Uint8List wrapKey) {
    assert(
      headerBytes.length == _kHeaderPayloadLen,
      'Header không hợp lệ: cần $_kHeaderPayloadLen bytes, nhận ${headerBytes.length}.',
    );

    int off = 0;
    final bodyNonce  = headerBytes.sublist(off, off += _kGcmNonceLen);   // 12B
    final wrapNonce  = headerBytes.sublist(off, off += _kAesNonceLen);   // 16B
    final wrappedKey = headerBytes.sublist(off, off += _kWrappedKeyLen); // 48B

    final contentKey = _crypto.decryptAEAD(
      wrappedKey,
      Uint8List(0),   // aad rỗng
      wrapKey,
      wrapNonce,
    );

    return (contentKey, bodyNonce);
  }

  /// Mã hoá một chunk bằng AES-256-GCM. [aad] là tag của chunk trước (empty cho chunk đầu).
  Uint8List _encryptChunk(Uint8List chunk, Uint8List key, Uint8List nonce, Uint8List aad) {
    return _crypto.encryptAEAD(chunk, aad, key, nonce);
  }
      

  /// Giải mã một chunk bằng AES-256-GCM. [aad] là tag của chunk trước (empty cho chunk đầu).
  Uint8List _decryptChunk(Uint8List chunk, Uint8List key, Uint8List nonce, Uint8List aad) {
    return _crypto.decryptAEAD(chunk, aad, key, nonce);
  }
      

  // ── Đổi mật khẩu (re-wrap) ──────────────────────────────────────────────

  /// Đổi wrapKey cho file đã mã hoá tại [sourcePath]:
  /// - Dùng [oldWrapKey] để mở content key từ header cũ.
  /// - Bọc lại content key bằng [newWrapKey] với wrapNonce mới.
  /// - Ghi file mới vào thư mục tạm (cùng tên), KHÔNG giải/mã lại body.
  /// Trả về [BmcTempFile] trỏ đến file với header mới + body cũ nguyên vẹn.
  Future<BmcTempFile> changePassword(
    String sourcePath,
    Uint8List oldWrapKey,
    Uint8List newWrapKey,
  ) async {
    assert(oldWrapKey.length == _kKeyLen, 'oldWrapKey phải đúng 32 bytes');
    assert(newWrapKey.length == _kKeyLen, 'newWrapKey phải đúng 32 bytes');
    assert(!kIsWeb, 'changePassword không hỗ trợ web.');

    // 1. Đọc header cũ → lấy contentKey và bodyNonce
    final oldHeader = await readHeader(sourcePath);
    final keys = _parseHeader(oldHeader, oldWrapKey);
    final contentKey = keys.$1;
    final bodyNonce  = keys.$2;

    // 2. Bọc lại contentKey bằng newWrapKey với wrapNonce mới
    final newWrapNonce  = _crypto.rand(_kAesNonceLen);
    final newWrappedKey = _crypto.encryptAEAD(
      contentKey, Uint8List(0), newWrapKey, newWrapNonce,
    );
    final newHeaderBytes = (BytesBuilder()
          ..add(bodyNonce)
          ..add(newWrapNonce)
          ..add(newWrappedKey))
        .toBytes();

    // 3. Đọc phần body cũ (raw encrypted chunks)
    final bodyBytes = await readBody(sourcePath);

    // 4. Ghi file mới: header mới + body cũ nguyên xi
    final destPath = tempPathFor(sourcePath);
    await initFile(destPath, newHeaderBytes);
    await appendBytes(destPath, bodyBytes);

    return BmcTempFile._(destPath);
  }
}

// ---------------------------------------------------------------------------
// BmcWrapKeyHelper – dẫn xuất wrapKey từ mật khẩu
// ---------------------------------------------------------------------------
//
// Dùng HMAC-SHA256 lặp [iterations] lần để dẫn xuất 32-byte wrapKey từ
// chuỗi mật khẩu + salt ngẫu nhiên (hoặc salt do người dùng cung cấp).
//
// Salt nên được lưu cùng file để có thể dẫn xuất lại khi giải mã.
// ---------------------------------------------------------------------------

class BmcWrapKeyHelper {
  final libcrypt.BmcCrypto _crypto;

  /// Số vòng lặp HMAC mặc định (~tương đương PBKDF2 nhẹ).
  static const int defaultIterations = 10000;

  BmcWrapKeyHelper({libcrypt.BmcCrypto? crypto})
      : _crypto = crypto ?? libcrypt.BmcCrypto();

  /// Tạo salt ngẫu nhiên 32 bytes. Lưu salt này cùng file để dẫn xuất lại.
  Uint8List generateSalt() => _crypto.rand(32);

  /// Dẫn xuất wrapKey (32 bytes) từ [password] + [salt] dùng HMAC-SHA256
  /// lặp [iterations] lần (PBKDF2-like, PRF = HMAC-SHA256).
  ///
  /// Trả về 32-byte wrapKey.
  Uint8List deriveWrapKey(
    String password,
    Uint8List salt, {
    int iterations = defaultIterations,
  }) {
    assert(salt.isNotEmpty, 'salt không được rỗng');

    // Bước khởi tạo: key0 = HMAC-SHA256(salt, password_bytes)
    final pwBytes = Uint8List.fromList(password.codeUnits);

    Uint8List current = _hmac(pwBytes, salt);

    // PBKDF2 single-block T(1): XOR liên tiếp các U_i
    Uint8List result = Uint8List.fromList(current);
    for (int i = 1; i < iterations; i++) {
      current = _hmac(pwBytes, current);
      for (int j = 0; j < result.length; j++) {
        result[j] ^= current[j];
      }
    }

    return result;
  }

  /// Tính HMAC-SHA256(key, data).
  Uint8List _hmac(Uint8List key, Uint8List data) {
    final ctx = _crypto.initHmacSha256(key);
    _crypto.updateHmacSha256(ctx, data);
    final out = Uint8List(32);
    _crypto.finishHmacSha256(ctx, out);
    _crypto.clearHmacSha256(ctx);
    return out;
  }
}



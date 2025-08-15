import 'dart:ffi';
import 'dart:io' show Platform;
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart'; // Để sử dụng compute

final class CryptoAesCtx extends Opaque {}

const int AES_MODE_ECB = 0;
const int AES_MODE_CBC = 1;
const int AES_MODE_CTR = 2;
const int AES_MODE_GCM = 3;

// --- khởi tạo thư viện và random
typedef _BmcCryptInitFunc = Void Function();
typedef _BmcCryptInitDartFunc = void Function();

// for crypto_core_aes_init(key, key_length, mode, is_enc, iv, iv_len)
typedef _BmcCryptAesInitFunc = Int32 Function(Pointer<Pointer<CryptoAesCtx>>, Pointer<Uint8>, Size, Int32, Int32, Pointer<Uint8>, Size);
typedef _BmcCryptAesInitDartFunc = int Function(Pointer<Pointer<CryptoAesCtx>>, Pointer<Uint8>, int, int, int, Pointer<Uint8>, int);

//for crypto_core_aes_update(ctx, out, in, in_len)
typedef _BmcCryptAesUpdateFunc = Int32 Function(Pointer<CryptoAesCtx>, Pointer<Uint8>, Pointer<Uint8>, Size);
typedef _BmcCryptAesUpdateDartFunc = int Function(Pointer<CryptoAesCtx>, Pointer<Uint8>, Pointer<Uint8>, int);

//for crypto_core_aes_finish(ctx, out, *out_len)
typedef _BmcCryptAesFinishFunc = Int32 Function(Pointer<CryptoAesCtx>, Pointer<Uint8>, Pointer<Size>);
typedef _BmcCryptAesFinishDartFunc = int Function(Pointer<CryptoAesCtx>, Pointer<Uint8>, Pointer<Size>);

//for crypto_core_aes_clear(ctx)
typedef _BmcCryptAesClearFunc = Int32 Function(Pointer<CryptoAesCtx>);
typedef _BmcCryptAesClearDartFunc = int Function(Pointer<CryptoAesCtx>);

/// Lớp API chính để tương tác với thư viện mật mã native.
class BmcCrypto {
  /// Singleton pattern để đảm bảo chỉ có một instance của FFI bridge.
  static final BmcCrypto _instance = BmcCrypto._internal();
  factory BmcCrypto() => _instance;
  late final DynamicLibrary _dylib;

  late final _BmcCryptInitDartFunc _bmcCryptInit;
  late final _BmcCryptAesInitDartFunc _bmcCryptAesInit;
  late final _BmcCryptAesUpdateDartFunc _bmcCryptAesUpdate;
  late final _BmcCryptAesFinishDartFunc _bmcCryptAesFinish;
  late final _BmcCryptAesClearDartFunc _bmcCryptAesClear;



  BmcCrypto._internal() {
    _dylib = _loadDylib();
    _bmcCryptInit = _dylib.lookup<NativeFunction<_BmcCryptInitFunc>>('bmc_crypt_init').asFunction<_BmcCryptInitDartFunc>();
    _bmcCryptAesInit = _dylib.lookup<NativeFunction<_BmcCryptAesInitFunc>>('crypto_core_aes_init').asFunction<_BmcCryptAesInitDartFunc>();
    _bmcCryptAesUpdate = _dylib.lookup<NativeFunction<_BmcCryptAesUpdateFunc>>('crypto_core_aes_update').asFunction<_BmcCryptAesUpdateDartFunc>();
    _bmcCryptAesFinish = _dylib.lookup<NativeFunction<_BmcCryptAesFinishFunc>>('crypto_core_aes_finish').asFunction<_BmcCryptAesFinishDartFunc>();
    _bmcCryptAesClear = _dylib.lookup<NativeFunction<_BmcCryptAesClearFunc>>('crypto_core_aes_cleanup').asFunction<_BmcCryptAesClearDartFunc>();
    
    _bmcCryptInit();
  }



  DynamicLibrary _loadDylib() {
    if (Platform.isAndroid) return DynamicLibrary.open('bmc_crypt.so');
    if (Platform.isWindows) return DynamicLibrary.open('bmc_crypt.dll');
    if (Platform.isLinux) return DynamicLibrary.open('bmc_crypt.so');
    if (Platform.isIOS || Platform.isMacOS) return DynamicLibrary.process();
    throw UnsupportedError('Unsupported platform');
  }

  Pointer<CryptoAesCtx> initAesCtx(Uint8List key, int mode, int isEnc, Uint8List iv) {
    final keyPtr = malloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = malloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final ctxPtr = malloc<Pointer<CryptoAesCtx>>();

    final ret = _bmcCryptAesInit(ctxPtr, keyPtr, key.length, mode, isEnc, ivPtr, iv.length);

    malloc.free(keyPtr);
    malloc.free(ivPtr);

    if (ret != 0) {
      throw Exception('AES init failed: $ret');
    }
    return ctxPtr.value;
  }

  int updateAes(Pointer<CryptoAesCtx> ctx, Uint8List out, Uint8List inData) {
    final outPtr = malloc<Uint8>(out.length);
    final inPtr = malloc<Uint8>(inData.length);
    inPtr.asTypedList(inData.length).setAll(0, inData);

    final ret = _bmcCryptAesUpdate(ctx, outPtr, inPtr, inData.length);
    // print(outPtr.asTypedList(out.length));
    out.setAll(0, outPtr.asTypedList(out.length));

    malloc.free(outPtr);
    malloc.free(inPtr);
    return ret;
  }

  int finishAes(Pointer<CryptoAesCtx> ctx, Uint8List out) {
    final outPtr = malloc<Uint8>(out.length);
    final outLenPtr = malloc<Size>();

    final ret = _bmcCryptAesFinish(ctx, outPtr, outLenPtr);
    final actualLen = outLenPtr.value;
    // Đảm bảo không copy quá giới hạn mảng Dart
    final copyLen = actualLen <= out.length ? actualLen : out.length;
    out.setAll(0, outPtr.asTypedList(copyLen));
    malloc.free(outPtr);
    malloc.free(outLenPtr);
    return ret;
  }

  int clearAes(Pointer<CryptoAesCtx> ctx) {
    return _bmcCryptAesClear(ctx);
  }
}


// Extension helper để quản lý bộ nhớ dễ dàng hơn
extension Uint8ListBlobConversion on Uint8List {
  Pointer<Uint8> allocatePointer() {
    final ptr = calloc<Uint8>(length);
    ptr.asTypedList(length).setAll(0, this);
    return ptr;
  }
}
import 'dart:ffi';
import 'dart:io' show Platform;
import 'dart:isolate';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart'; // Để sử dụng compute

final class CryptoAesCtx extends Opaque {}
final class CryptoHmacSha256Ctx extends Opaque {}

const int AES_MODE_ECB = 0;
const int AES_MODE_CBC = 1;
const int AES_MODE_CTR = 2;
const int AES_MODE_GCM = 3;

const int BMC_PROTOCOL_KEY_LEN = 32;
const int BMC_PROTOCOL_NONCE_LEN = 16;
const int BMC_PROTOCOL_CHAIN_KEY_LEN = 32;
const int BMC_PROTOCOL_MESSAGE_KEY_LEN = 32;
const int BMC_PROTOCOL_HMAC_KEY_LEN = 32;

const int BMC_PROTOCOL_PKLEN = 32;
const int BMC_PROTOCOL_SKLEN = 64;
const int BMC_PROTOCOL_x25519_KEYLEN = 32;
const int BMC_PROTOCOL_SIGLEN = 64;

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

//for bmc_protocol
typedef _BmcProtocolDeriveSessionKeysFunc = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolDeriveSessionKeysDartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

typedef _BmcProtocolDeriveMessageKeysFunc = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolDeriveMessageKeysDartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

typedef _BmcProtocolConvertEd25519ToX25519Func = Int32  Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolConvertEd25519ToX25519DartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

typedef _BmcProtocolGenerateEd25519KeypairFunc = Int32  Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolGenerateEd25519KeypairDartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>);

typedef _BmcProtocolGenerateX25519KeypairFunc = Int32  Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolGenerateX25519KeypairDartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>);

typedef _BmcProtocolCaculateSecretFunc = Int32  Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolCaculateSecretDartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

typedef _BmcProtocolSignFunc = Int32  Function(Pointer<Uint8>, Pointer<Uint64>, Pointer<Uint8>, Uint64, Pointer<Uint8>);
typedef _BmcProtocolSignDartFunc = int Function(Pointer<Uint8>, Pointer<Uint64>, Pointer<Uint8>, int, Pointer<Uint8>);

typedef _BmcProtocolVerifyFunc = Int32  Function(Pointer<Uint8>, Pointer<Uint8>, Uint64, Pointer<Uint8>);
typedef _BmcProtocolVerifyDartFunc = int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>);

//for hmacsha256
typedef _BmcProtocolHmacSha256InitFunc = Int32  Function(Pointer<Pointer<CryptoHmacSha256Ctx>>, Pointer<Uint8>, Size);
typedef _BmcProtocolHmacSha256InitDartFunc = int Function(Pointer<Pointer<CryptoHmacSha256Ctx>>, Pointer<Uint8>, int);

typedef _BmcProtocolHmacSha256UpdateFunc = Int32  Function(Pointer<CryptoHmacSha256Ctx>, Pointer<Uint8>, Size);
typedef _BmcProtocolHmacSha256UpdateDartFunc = int Function(Pointer<CryptoHmacSha256Ctx>, Pointer<Uint8>, int);

typedef _BmcProtocolHmacSha256FinishFunc = Int32  Function(Pointer<CryptoHmacSha256Ctx>, Pointer<Uint8>);
typedef _BmcProtocolHmacSha256FinishDartFunc = int Function(Pointer<CryptoHmacSha256Ctx>, Pointer<Uint8>);

typedef _BmcProtocolHmacSha256ClearFunc = Int32  Function(Pointer<CryptoHmacSha256Ctx>);
typedef _BmcProtocolHmacSha256ClearDartFunc = int Function(Pointer<CryptoHmacSha256Ctx>);

//for bmc_protocol_encrypt
typedef _BmcProtocolEncryptFunc = Int32  Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Pointer<Uint8>, Size, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolEncryptDartFunc = int Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Pointer<Uint8>,int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

//for bmc_protocol_decrypt
typedef _BmcProtocolDecryptFunc = Int32  Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Pointer<Uint8>, Size, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _BmcProtocolDecryptDartFunc = int Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

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

  late final _BmcProtocolDeriveSessionKeysDartFunc _bmcProtocolDeriveSessionKeys;
  late final _BmcProtocolDeriveMessageKeysDartFunc _bmcProtocolDeriveMessageKeys;
  late final _BmcProtocolConvertEd25519ToX25519DartFunc _bmcProtocolConvertEd25519ToX25519;
  late final _BmcProtocolGenerateEd25519KeypairDartFunc _bmcProtocolGenerateEd25519Keypair;
  late final _BmcProtocolGenerateX25519KeypairDartFunc _bmcProtocolGenerateX25519Keypair;
  late final _BmcProtocolCaculateSecretDartFunc _bmcProtocolCaculateSecret;
  late final _BmcProtocolSignDartFunc _bmcProtocolSign;
  late final _BmcProtocolVerifyDartFunc _bmcProtocolVerify;
  late final _BmcProtocolHmacSha256InitDartFunc _bmcProtocolHmacSha256Init;
  late final _BmcProtocolHmacSha256UpdateDartFunc _bmcProtocolHmacSha256Update;
  late final _BmcProtocolHmacSha256FinishDartFunc _bmcProtocolHmacSha256Finish;
  late final _BmcProtocolHmacSha256ClearDartFunc _bmcProtocolHmacSha256Clear;

  late final _BmcProtocolEncryptDartFunc _bmcProtocolEncrypt;
  late final _BmcProtocolDecryptDartFunc _bmcProtocolDecrypt;


  BmcCrypto._internal() {
    _dylib = _loadDylib();
    _bmcCryptInit = _dylib.lookup<NativeFunction<_BmcCryptInitFunc>>('bmc_crypt_init').asFunction<_BmcCryptInitDartFunc>();
    _bmcCryptAesInit = _dylib.lookup<NativeFunction<_BmcCryptAesInitFunc>>('crypto_core_aes_init').asFunction<_BmcCryptAesInitDartFunc>();
    _bmcCryptAesUpdate = _dylib.lookup<NativeFunction<_BmcCryptAesUpdateFunc>>('crypto_core_aes_update').asFunction<_BmcCryptAesUpdateDartFunc>();
    _bmcCryptAesFinish = _dylib.lookup<NativeFunction<_BmcCryptAesFinishFunc>>('crypto_core_aes_finish').asFunction<_BmcCryptAesFinishDartFunc>();
    _bmcCryptAesClear = _dylib.lookup<NativeFunction<_BmcCryptAesClearFunc>>('crypto_core_aes_cleanup').asFunction<_BmcCryptAesClearDartFunc>();

    _bmcProtocolDeriveSessionKeys = _dylib.lookup<NativeFunction<_BmcProtocolDeriveSessionKeysFunc>>('bmc_protocol_derive_session_keys').asFunction<_BmcProtocolDeriveSessionKeysDartFunc>();
    _bmcProtocolDeriveMessageKeys = _dylib.lookup<NativeFunction<_BmcProtocolDeriveMessageKeysFunc>>('bmc_protocol_derive_message_keys').asFunction<_BmcProtocolDeriveMessageKeysDartFunc>();
    _bmcProtocolConvertEd25519ToX25519 = _dylib.lookup<NativeFunction<_BmcProtocolConvertEd25519ToX25519Func>>('bmc_protocol_convert_ed25519_to_x25519').asFunction<_BmcProtocolConvertEd25519ToX25519DartFunc>();
    _bmcProtocolGenerateEd25519Keypair = _dylib.lookup<NativeFunction<_BmcProtocolGenerateEd25519KeypairFunc>>('bmc_protocol_generate_ed25519_keypair').asFunction<_BmcProtocolGenerateEd25519KeypairDartFunc>();
    _bmcProtocolGenerateX25519Keypair = _dylib.lookup<NativeFunction<_BmcProtocolGenerateX25519KeypairFunc>>('bmc_protocol_generate_x25519_keypair').asFunction<_BmcProtocolGenerateX25519KeypairDartFunc>();
    _bmcProtocolCaculateSecret = _dylib.lookup<NativeFunction<_BmcProtocolCaculateSecretFunc>>('bmc_protocol_caculate_secret').asFunction<_BmcProtocolCaculateSecretDartFunc>();
    _bmcProtocolSign = _dylib.lookup<NativeFunction<_BmcProtocolSignFunc>>('bmc_protocol_sign').asFunction<_BmcProtocolSignDartFunc>();
    _bmcProtocolVerify = _dylib.lookup<NativeFunction<_BmcProtocolVerifyFunc>>('bmc_protocol_verify').asFunction<_BmcProtocolVerifyDartFunc>();
    _bmcProtocolHmacSha256Init = _dylib.lookup<NativeFunction<_BmcProtocolHmacSha256InitFunc>>('bmc_protocol_hmac_sha256_init').asFunction<_BmcProtocolHmacSha256InitDartFunc>();
    _bmcProtocolHmacSha256Update = _dylib.lookup<NativeFunction<_BmcProtocolHmacSha256UpdateFunc>>('bmc_protocol_hmac_sha256_update').asFunction<_BmcProtocolHmacSha256UpdateDartFunc>();
    _bmcProtocolHmacSha256Finish = _dylib.lookup<NativeFunction<_BmcProtocolHmacSha256FinishFunc>>('bmc_protocol_hmac_sha256_finish').asFunction<_BmcProtocolHmacSha256FinishDartFunc>();
    _bmcProtocolHmacSha256Clear = _dylib.lookup<NativeFunction<_BmcProtocolHmacSha256ClearFunc>>('bmc_protocol_hmac_sha256_cleanup').asFunction<_BmcProtocolHmacSha256ClearDartFunc>();
    _bmcProtocolEncrypt = _dylib.lookup<NativeFunction<_BmcProtocolEncryptFunc>>('bmc_protocol_encrypt').asFunction<_BmcProtocolEncryptDartFunc>();
    _bmcProtocolDecrypt = _dylib.lookup<NativeFunction<_BmcProtocolDecryptFunc>>('bmc_protocol_decrypt').asFunction<_BmcProtocolDecryptDartFunc>();
    _bmcCryptInit();
  }


  DynamicLibrary _loadDylib() {
    if (Platform.isAndroid) return DynamicLibrary.open('libbmc_crypt.so');
    if (Platform.isWindows) return DynamicLibrary.open('bmc_crypt.dll');
    if (Platform.isLinux) return DynamicLibrary.open('libbmc_crypt.so');
    if (Platform.isIOS || Platform.isMacOS) return DynamicLibrary.process();
    throw UnsupportedError('Unsupported platform');
  }

  Uint8List encrypt(Uint8List plaintext, Uint8List messageKey, Uint8List iv, Uint8List macKey) {
    assert(plaintext.isNotEmpty);
    assert(messageKey.length == BMC_PROTOCOL_MESSAGE_KEY_LEN);
    assert(iv.length == BMC_PROTOCOL_NONCE_LEN);
    assert(macKey.length == BMC_PROTOCOL_HMAC_KEY_LEN);

    final plaintextPtr = plaintext.allocatePointer();
    final messageKeyPtr = messageKey.allocatePointer();
    final ivPtr = iv.allocatePointer();
    final macKeyPtr = macKey.allocatePointer();
    final ciphertextPtr = calloc<Pointer<Uint8>>();
    final ciphertextLenPtr = calloc<Size>();
    final ret = _bmcProtocolEncrypt(ciphertextPtr, ciphertextLenPtr, plaintextPtr, plaintext.length, messageKeyPtr, ivPtr, macKeyPtr);
    if (ret > -1) {
      final ciphertext = ciphertextPtr.value.asTypedList(ciphertextLenPtr.value);
      calloc.free(plaintextPtr);
      calloc.free(messageKeyPtr);
      calloc.free(ivPtr);
      calloc.free(macKeyPtr);
      calloc.free(ciphertextPtr);
      calloc.free(ciphertextLenPtr);
      return ciphertext;
    } else {
      calloc.free(plaintextPtr);
      calloc.free(messageKeyPtr);
      calloc.free(ivPtr);
      calloc.free(macKeyPtr);
      calloc.free(ciphertextPtr);
      calloc.free(ciphertextLenPtr);
      throw Exception('Encrypt failed: $ret');
    }
  }

  Uint8List decrypt(Uint8List ciphertext, Uint8List messageKey, Uint8List iv, Uint8List macKey) {
    assert(ciphertext.isNotEmpty);
    assert(messageKey.length == BMC_PROTOCOL_MESSAGE_KEY_LEN);
    assert(iv.length == BMC_PROTOCOL_NONCE_LEN);
    assert(macKey.length == BMC_PROTOCOL_HMAC_KEY_LEN);

    final ciphertextPtr = ciphertext.allocatePointer();
    final messageKeyPtr = messageKey.allocatePointer();
    final ivPtr = iv.allocatePointer();
    final macKeyPtr = macKey.allocatePointer();
    final plaintextPtr = calloc<Pointer<Uint8>>();
    final plaintextLenPtr = calloc<Size>();
    final ret = _bmcProtocolDecrypt(plaintextPtr, plaintextLenPtr, ciphertextPtr, ciphertext.length, messageKeyPtr, ivPtr, macKeyPtr);
    if (ret > -1) {
      final plaintext = plaintextPtr.value.asTypedList(plaintextLenPtr.value);
      calloc.free(ciphertextPtr);
      calloc.free(messageKeyPtr);
      calloc.free(ivPtr);
      calloc.free(macKeyPtr);
      calloc.free(plaintextPtr);
      calloc.free(plaintextLenPtr);
      return plaintext;
    } else {
      calloc.free(ciphertextPtr);
      calloc.free(messageKeyPtr);
      calloc.free(ivPtr);
      calloc.free(macKeyPtr);
      calloc.free(plaintextPtr);
      calloc.free(plaintextLenPtr);
      throw Exception('Decrypt failed: $ret');
    }
  }

  Pointer<CryptoAesCtx> initAesCtx(Uint8List key, int mode, int isEnc, Uint8List iv) {
    final keyPtr = key.allocatePointer();
    final ivPtr = iv.allocatePointer();

    final ctxPtr = calloc<Pointer<CryptoAesCtx>>();

    final ret = _bmcCryptAesInit(ctxPtr, keyPtr, key.length, mode, isEnc, ivPtr, iv.length);

    calloc.free(keyPtr);
    calloc.free(ivPtr);

    if (ret != 0) {
      throw Exception('AES init failed: $ret');
    }
    return ctxPtr.value;
  }

  int updateAes(Pointer<CryptoAesCtx> ctx, Uint8List out, Uint8List inData) {
    final outPtr = out.allocatePointer();
    final inPtr = inData.allocatePointer();

    final ret = _bmcCryptAesUpdate(ctx, outPtr, inPtr, inData.length);;
    if (ret > 0) {
      out.setAll(0, outPtr.asTypedList(ret));
    }
    if (ret == -1){
      throw Exception('AES update failed: $ret');
    }

    calloc.free(outPtr);
    calloc.free(inPtr);
    return ret;
  }

  int finishAes(Pointer<CryptoAesCtx> ctx, Uint8List out) { 
    final outPtr = out.allocatePointer();
    final outLenPtr = calloc<Size>();

    var ret = _bmcCryptAesFinish(ctx, outPtr, outLenPtr);
    if (ret > -1) {
      final actualLen = outLenPtr.value;
      // Đảm bảo không copy quá giới hạn mảng Dart
      final copyLen = actualLen <= out.length ? actualLen : out.length;
      out.setAll(0, outPtr.asTypedList(copyLen));
      print("out: ${out}");
      ret = copyLen;
    }else{
      throw Exception('AES finish failed: $ret');
    }
    calloc.free(outPtr);
    calloc.free(outLenPtr);
    return ret;
  }

  int clearAes(Pointer<CryptoAesCtx> ctx) {
    return _bmcCryptAesClear(ctx);
  }

  int deriveSessionKeys(Uint8List sharedSecret, Uint8List ephemeralPk, Uint8List xPkPeer, Uint8List rootKey, Uint8List sendChainKey,Uint8List recvChainKey) {
    final sharedSecretPtr = sharedSecret.allocatePointer();
    final ephemeralPkPtr = ephemeralPk.allocatePointer();
    final xPkPeerPtr = xPkPeer.allocatePointer();

    final rootKeyPtr = rootKey.allocatePointer();
    final sendChainKeyPtr = sendChainKey.allocatePointer();
    final recvChainKeyPtr = recvChainKey.allocatePointer();

    final ret = _bmcProtocolDeriveSessionKeys(sharedSecretPtr, ephemeralPkPtr, xPkPeerPtr, rootKeyPtr, sendChainKeyPtr, recvChainKeyPtr);
    if (ret > -1) {
      rootKey.setAll(0, rootKeyPtr.asTypedList(rootKey.length));
      sendChainKey.setAll(0, sendChainKeyPtr.asTypedList(sendChainKey.length));
      recvChainKey.setAll(0, recvChainKeyPtr.asTypedList(recvChainKey.length));
    } else {
      throw Exception('Derive session keys failed: $ret');
    }
    calloc.free(sharedSecretPtr);
    calloc.free(ephemeralPkPtr);
    calloc.free(xPkPeerPtr);
    calloc.free(rootKeyPtr);
    calloc.free(sendChainKeyPtr);
    calloc.free(recvChainKeyPtr);
    return ret;
  }

  int deriveMessageKeys(Uint8List chainKey, Uint8List messageKey, Uint8List nextChainKey, Uint8List macKey, Uint8List iv) {
    final chainKeyPtr = chainKey.allocatePointer();
    final messageKeyPtr = messageKey.allocatePointer();
    final nextChainKeyPtr = nextChainKey.allocatePointer();
    final macKeyPtr = macKey.allocatePointer();
    final ivPtr = iv.allocatePointer();

    final ret = _bmcProtocolDeriveMessageKeys(chainKeyPtr, messageKeyPtr, nextChainKeyPtr, macKeyPtr, ivPtr);
    if (ret > -1) {
      chainKey.setAll(0, chainKeyPtr.asTypedList(chainKey.length));
      messageKey.setAll(0, messageKeyPtr.asTypedList(messageKey.length));
      nextChainKey.setAll(0, nextChainKeyPtr.asTypedList(nextChainKey.length));
      macKey.setAll(0, macKeyPtr.asTypedList(macKey.length));
      iv.setAll(0, ivPtr.asTypedList(iv.length));
    } else {
      throw Exception('Derive message keys failed: $ret');
    }
    calloc.free(chainKeyPtr);
    calloc.free(messageKeyPtr);
    calloc.free(nextChainKeyPtr);
    calloc.free(macKeyPtr);
    calloc.free(ivPtr);

    return ret;
  }

  int convertEd25519ToX25519(Uint8List ed25519PublicKey, Uint8List ed25519PrivateKey, Uint8List x25519PublicKey, Uint8List x25519PrivateKey) {
    final ed25519PublicKeyPtr = ed25519PublicKey.allocatePointer();
    final ed25519PrivateKeyPtr = ed25519PrivateKey.allocatePointer();
    final x25519PublicKeyPtr = x25519PublicKey.allocatePointer();
    final x25519PrivateKeyPtr = x25519PrivateKey.allocatePointer();

    final ret = _bmcProtocolConvertEd25519ToX25519(x25519PrivateKeyPtr, x25519PublicKeyPtr, ed25519PrivateKeyPtr, ed25519PublicKeyPtr);
    if (ret > -1) {
      x25519PublicKey.setAll(0, x25519PublicKeyPtr.asTypedList(x25519PublicKey.length));
      x25519PrivateKey.setAll(0, x25519PrivateKeyPtr.asTypedList(x25519PrivateKey.length));
    } else {
      throw Exception('Convert Ed25519 to X25519 failed: $ret');
    }
    calloc.free(ed25519PublicKeyPtr);
    calloc.free(ed25519PrivateKeyPtr);
    calloc.free(x25519PublicKeyPtr);
    calloc.free(x25519PrivateKeyPtr);

    return ret;
  }

  int generateEd25519Keypair(Uint8List publicKey, Uint8List privateKey) {
    final publicKeyPtr = publicKey.allocatePointer();
    final privateKeyPtr = privateKey.allocatePointer();

    final ret = _bmcProtocolGenerateEd25519Keypair(privateKeyPtr, publicKeyPtr);
    if (ret > -1) {
      publicKey.setAll(0, publicKeyPtr.asTypedList(publicKey.length));
      privateKey.setAll(0, privateKeyPtr.asTypedList(privateKey.length));
    } else {
      throw Exception('Generate Ed25519 keypair failed: $ret');
    }
    calloc.free(publicKeyPtr);
    calloc.free(privateKeyPtr);
    return ret;
  }

  int generateX25519Keypair(Uint8List publicKey, Uint8List privateKey) {
    final publicKeyPtr = publicKey.allocatePointer();
    final privateKeyPtr = privateKey.allocatePointer();

    final ret = _bmcProtocolGenerateX25519Keypair(privateKeyPtr, publicKeyPtr);
    if (ret > -1) {
      publicKey.setAll(0, publicKeyPtr.asTypedList(publicKey.length));
      privateKey.setAll(0, privateKeyPtr.asTypedList(privateKey.length));
    } else {
      throw Exception('Generate X25519 keypair failed: $ret');
    }
    calloc.free(publicKeyPtr);
    calloc.free(privateKeyPtr);
    return ret;
  }

  int caculateSecret(Uint8List secret, Uint8List privateKey, Uint8List publicKey) {
    final secretPtr = secret.allocatePointer();
    final privateKeyPtr = privateKey.allocatePointer();
    final publicKeyPtr = publicKey.allocatePointer();

    final ret = _bmcProtocolCaculateSecret(secretPtr, privateKeyPtr, publicKeyPtr);
    if (ret > -1) {
      secret.setAll(0, secretPtr.asTypedList(secret.length));
    } else {
      throw Exception('Caculate secret failed: $ret');
    }
    calloc.free(publicKeyPtr);
    calloc.free(privateKeyPtr);
    calloc.free(secretPtr);
    return ret;
  }

  int sign(Uint8List message, Uint8List privateKey, Uint8List signature) {
    final messagePtr = message.allocatePointer();
    final privateKeyPtr = privateKey.allocatePointer();
    final signaturePtr = signature.allocatePointer();
    final signatureLenPtr = calloc<Uint64>();

    final ret = _bmcProtocolSign(signaturePtr, signatureLenPtr, messagePtr, message.length, privateKeyPtr);
    if (ret > -1) {
      final actualLen = signatureLenPtr.value;
      final copyLen = actualLen <= signature.length ? actualLen : signature.length;
      signature.setAll(0, signaturePtr.asTypedList(copyLen));
    } else {
      throw Exception('Sign failed: $ret');
    }
    calloc.free(messagePtr);
    calloc.free(privateKeyPtr);
    calloc.free(signaturePtr);
    calloc.free(signatureLenPtr);
    return ret;
  }

  int verify(Uint8List publicKey, Uint8List message, Uint8List signature) {
    final publicKeyPtr = publicKey.allocatePointer();
    final messagePtr = message.allocatePointer();
    final signaturePtr = signature.allocatePointer();

    final ret = _bmcProtocolVerify(signaturePtr, messagePtr, message.length, publicKeyPtr);
    if (ret == -1){
      throw Exception('Verify failed: $ret');
    }
    calloc.free(publicKeyPtr);
    calloc.free(messagePtr);
    calloc.free(signaturePtr);
    return ret;
  }

  Pointer<CryptoHmacSha256Ctx> initHmacSha256(Uint8List key) {
    final keyPtr = key.allocatePointer();
    final ctxPtr = calloc<Pointer<CryptoHmacSha256Ctx>>();
    final ret = _bmcProtocolHmacSha256Init(ctxPtr, keyPtr, key.length);
    calloc.free(keyPtr);
    if (ret > -1) {
      return ctxPtr.value;
    } else {
      throw Exception('HMAC SHA256 init failed: $ret');
    }
  }

  int updateHmacSha256(Pointer<CryptoHmacSha256Ctx> ctx, Uint8List data) {
    final dataPtr = data.allocatePointer();
    final ret = _bmcProtocolHmacSha256Update(ctx, dataPtr, data.length);
    calloc.free(dataPtr);
    if (ret > -1) {
      return ret;
    } else {
      throw Exception('HMAC SHA256 update failed: $ret');
    }
  }

  int finishHmacSha256(Pointer<CryptoHmacSha256Ctx> ctx, Uint8List out) {
    final outPtr = out.allocatePointer();
    final ret = _bmcProtocolHmacSha256Finish(ctx, outPtr);
    if (ret > -1) {
      out.setAll(0, outPtr.asTypedList(out.length));
    } else {
      throw Exception('HMAC SHA256 finish failed: $ret');
    }
    calloc.free(outPtr);
    return ret;
  }

  int clearHmacSha256(Pointer<CryptoHmacSha256Ctx> ctx) {
    return _bmcProtocolHmacSha256Clear(ctx);
  }

  // ==================== ISOLATE FUNCTIONS ====================
  
  /// Encrypt data in isolate to avoid blocking UI thread
  Future<Uint8List> encryptAsync(Uint8List plaintext, Uint8List messageKey, Uint8List iv, Uint8List macKey) async {
    final params = _EncryptParams(plaintext, messageKey, iv, macKey);
    return await compute(_encryptIsolate, params);
  }

  /// Decrypt data in isolate to avoid blocking UI thread  
  Future<Uint8List> decryptAsync(Uint8List ciphertext, Uint8List messageKey, Uint8List iv, Uint8List macKey) async {
    final params = _DecryptParams(ciphertext, messageKey, iv, macKey);
    return await compute(_decryptIsolate, params);
  }

  /// Generate Ed25519 keypair in isolate
  Future<_KeypairResult> generateEd25519KeypairAsync() async {
    return await compute(_generateEd25519KeypairIsolate, null);
  }

  /// Generate X25519 keypair in isolate
  Future<_KeypairResult> generateX25519KeypairAsync() async {
    return await compute(_generateX25519KeypairIsolate, null);
  }

  /// Convert Ed25519 to X25519 in isolate
  Future<_KeypairResult> convertEd25519ToX25519Async(Uint8List ed25519PublicKey, Uint8List ed25519PrivateKey) async {
    final params = _ConvertKeyParams(ed25519PublicKey, ed25519PrivateKey);
    return await compute(_convertEd25519ToX25519Isolate, params);
  }

  /// Calculate secret in isolate
  Future<Uint8List> calculateSecretAsync(Uint8List privateKey, Uint8List publicKey) async {
    final params = _CalculateSecretParams(privateKey, publicKey);
    return await compute(_calculateSecretIsolate, params);
  }

  /// Sign message in isolate
  Future<Uint8List> signAsync(Uint8List message, Uint8List privateKey) async {
    final params = _SignParams(message, privateKey);
    return await compute(_signIsolate, params);
  }

  /// Verify signature in isolate
  Future<bool> verifyAsync(Uint8List publicKey, Uint8List message, Uint8List signature) async {
    final params = _VerifyParams(publicKey, message, signature);
    return await compute(_verifyIsolate, params);
  }

  /// Derive session keys in isolate
  Future<_SessionKeysResult> deriveSessionKeysAsync(Uint8List sharedSecret, Uint8List ephemeralPk, Uint8List xPkPeer) async {
    final params = _DeriveSessionKeysParams(sharedSecret, ephemeralPk, xPkPeer);
    return await compute(_deriveSessionKeysIsolate, params);
  }

  /// Derive message keys in isolate  
  Future<_MessageKeysResult> deriveMessageKeysAsync(Uint8List chainKey) async {
    return await compute(_deriveMessageKeysIsolate, chainKey);
  }
}

// ==================== ISOLATE PARAMETER CLASSES ====================

class _EncryptParams {
  final Uint8List plaintext;
  final Uint8List messageKey;
  final Uint8List iv;
  final Uint8List macKey;
  
  _EncryptParams(this.plaintext, this.messageKey, this.iv, this.macKey);
}

class _DecryptParams {
  final Uint8List ciphertext;
  final Uint8List messageKey;
  final Uint8List iv;
  final Uint8List macKey;
  
  _DecryptParams(this.ciphertext, this.messageKey, this.iv, this.macKey);
}

class _ConvertKeyParams {
  final Uint8List ed25519PublicKey;
  final Uint8List ed25519PrivateKey;
  
  _ConvertKeyParams(this.ed25519PublicKey, this.ed25519PrivateKey);
}

class _CalculateSecretParams {
  final Uint8List privateKey;
  final Uint8List publicKey;
  
  _CalculateSecretParams(this.privateKey, this.publicKey);
}

class _SignParams {
  final Uint8List message;
  final Uint8List privateKey;
  
  _SignParams(this.message, this.privateKey);
}

class _VerifyParams {
  final Uint8List publicKey;
  final Uint8List message;
  final Uint8List signature;
  
  _VerifyParams(this.publicKey, this.message, this.signature);
}

class _DeriveSessionKeysParams {
  final Uint8List sharedSecret;
  final Uint8List ephemeralPk;
  final Uint8List xPkPeer;
  
  _DeriveSessionKeysParams(this.sharedSecret, this.ephemeralPk, this.xPkPeer);
}

// ==================== ISOLATE RESULT CLASSES ====================

class _KeypairResult {
  final Uint8List publicKey;
  final Uint8List privateKey;
  
  _KeypairResult(this.publicKey, this.privateKey);
}

class _SessionKeysResult {
  final Uint8List rootKey;
  final Uint8List sendChainKey;
  final Uint8List recvChainKey;
  
  _SessionKeysResult(this.rootKey, this.sendChainKey, this.recvChainKey);
}

class _MessageKeysResult {
  final Uint8List chainKey;
  final Uint8List messageKey;
  final Uint8List nextChainKey;
  final Uint8List macKey;
  final Uint8List iv;
  
  _MessageKeysResult(this.chainKey, this.messageKey, this.nextChainKey, this.macKey, this.iv);
}

// ==================== ISOLATE WORKER FUNCTIONS ====================

/// Isolate worker function for encryption
Uint8List _encryptIsolate(_EncryptParams params) {
  final crypto = BmcCrypto();
  return crypto.encrypt(params.plaintext, params.messageKey, params.iv, params.macKey);
}

/// Isolate worker function for decryption
Uint8List _decryptIsolate(_DecryptParams params) {
  final crypto = BmcCrypto();
  return crypto.decrypt(params.ciphertext, params.messageKey, params.iv, params.macKey);
}

/// Isolate worker function for Ed25519 keypair generation
_KeypairResult _generateEd25519KeypairIsolate(void _) {
  final crypto = BmcCrypto();
  final publicKey = Uint8List(BMC_PROTOCOL_PKLEN);
  final privateKey = Uint8List(BMC_PROTOCOL_SKLEN);
  
  crypto.generateEd25519Keypair(publicKey, privateKey);
  return _KeypairResult(publicKey, privateKey);
}

/// Isolate worker function for X25519 keypair generation
_KeypairResult _generateX25519KeypairIsolate(void _) {
  final crypto = BmcCrypto();
  final publicKey = Uint8List(BMC_PROTOCOL_x25519_KEYLEN);
  final privateKey = Uint8List(BMC_PROTOCOL_x25519_KEYLEN);
  
  crypto.generateX25519Keypair(publicKey, privateKey);
  return _KeypairResult(publicKey, privateKey);
}

/// Isolate worker function for Ed25519 to X25519 conversion
_KeypairResult _convertEd25519ToX25519Isolate(_ConvertKeyParams params) {
  final crypto = BmcCrypto();
  final x25519PublicKey = Uint8List(BMC_PROTOCOL_x25519_KEYLEN);
  final x25519PrivateKey = Uint8List(BMC_PROTOCOL_x25519_KEYLEN);
  
  crypto.convertEd25519ToX25519(params.ed25519PublicKey, params.ed25519PrivateKey, x25519PublicKey, x25519PrivateKey);
  return _KeypairResult(x25519PublicKey, x25519PrivateKey);
}

/// Isolate worker function for secret calculation
Uint8List _calculateSecretIsolate(_CalculateSecretParams params) {
  final crypto = BmcCrypto();
  final secret = Uint8List(BMC_PROTOCOL_x25519_KEYLEN);
  
  crypto.caculateSecret(secret, params.privateKey, params.publicKey);
  return secret;
}

/// Isolate worker function for signing
Uint8List _signIsolate(_SignParams params) {
  final crypto = BmcCrypto();
  final signature = Uint8List(BMC_PROTOCOL_SIGLEN);
  
  crypto.sign(params.message, params.privateKey, signature);
  return signature;
}

/// Isolate worker function for verification
bool _verifyIsolate(_VerifyParams params) {
  final crypto = BmcCrypto();
  try {
    final result = crypto.verify(params.publicKey, params.message, params.signature);
    return result == 0; // 0 means success in verification
  } catch (e) {
    return false;
  }
}

/// Isolate worker function for session key derivation
_SessionKeysResult _deriveSessionKeysIsolate(_DeriveSessionKeysParams params) {
  final crypto = BmcCrypto();
  final rootKey = Uint8List(BMC_PROTOCOL_CHAIN_KEY_LEN);
  final sendChainKey = Uint8List(BMC_PROTOCOL_CHAIN_KEY_LEN);
  final recvChainKey = Uint8List(BMC_PROTOCOL_CHAIN_KEY_LEN);
  
  crypto.deriveSessionKeys(params.sharedSecret, params.ephemeralPk, params.xPkPeer, rootKey, sendChainKey, recvChainKey);
  return _SessionKeysResult(rootKey, sendChainKey, recvChainKey);
}

/// Isolate worker function for message key derivation
_MessageKeysResult _deriveMessageKeysIsolate(Uint8List chainKey) {
  final crypto = BmcCrypto();
  final messageKey = Uint8List(BMC_PROTOCOL_MESSAGE_KEY_LEN);
  final nextChainKey = Uint8List(BMC_PROTOCOL_CHAIN_KEY_LEN);
  final macKey = Uint8List(BMC_PROTOCOL_HMAC_KEY_LEN);
  final iv = Uint8List(BMC_PROTOCOL_NONCE_LEN);
  
  crypto.deriveMessageKeys(chainKey, messageKey, nextChainKey, macKey, iv);
  return _MessageKeysResult(chainKey, messageKey, nextChainKey, macKey, iv);
}

// Extension helper để quản lý bộ nhớ dễ dàng hơn
extension Uint8ListBlobConversion on Uint8List {
  Pointer<Uint8> allocatePointer() {
    final ptr = calloc<Uint8>(length);
    ptr.asTypedList(length).setAll(0, this);
    return ptr;
  }
}
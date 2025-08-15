import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;

final crypto = libcrypt.BmcCrypto();

void main() {
  funAES256CTRTest();
  //funAES256ECBTest();
}

void funAES256CTRTest(){
  // Key 128-bit (16 bytes)
    final key = Uint8List.fromList([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ]);

    // Nonce / Counter block
    final iv = Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    ]);
    final message = Uint8List.fromList(utf8.encode('hello'));

    // Allocate output buffer
    final outEnc = Uint8List(message.length + 16);
    // Init AES Encrypt
    final ctxEnc = crypto.initAesCtx(key, libcrypt.AES_MODE_CTR, 1, iv); // 1 = encrypt  , 0 = decrypt
    final ctxDec = crypto.initAesCtx(key, libcrypt.AES_MODE_CTR, 0, iv); // 1 = encrypt  , 0 = decrypt
    // Update
    final updated = crypto.updateAes(ctxEnc, outEnc, message);
    if(updated == -1){
      print("AES encrypt updateAes failed");
      return;
    }else{
      print("AES encrypt updateAes success");
    }

    // Finish
    final finished = crypto.finishAes(ctxEnc, outEnc.sublist(updated));
    final cipherText = outEnc.sublist(0, updated + finished);
    print("cipherText: ${cipherText}");

    // Decrypt
    final outDec = Uint8List(cipherText.length);
    final updatedDec = crypto.updateAes(ctxDec, outDec, cipherText);
    if(updatedDec == -1){
      print("AES decrypt updateAes failed");
      return;
    }else{
      print("AES decrypt updateAes success");
    }
    // Finish
    final finishedDec = crypto.finishAes(ctxDec, outDec.sublist(updatedDec));
    final plainText = outDec.sublist(0, updatedDec + finishedDec);
    print("plainText: ${plainText}");
    print("plainText: ${utf8.decode(plainText)}");

    // Clear
    final cleared = crypto.clearAes(ctxEnc);
    if(cleared != 0){
      print("AES encrypt clearAes failed");
      return;
    }else{
      print("AES encrypt clearAes success");
    }
    final clearedDec = crypto.clearAes(ctxDec);
    if(clearedDec != 0){
      print("AES decrypt clearAes failed");
      return;
    }else{
      print("AES decrypt clearAes success");
    }
}

void funAES256ECBTest(){
  // Test vector
  final keyBytes = Uint8List.fromList([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ]);

  final plaintextBytes = Uint8List.fromList([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  ]);

  final expectedCipherBytes = Uint8List.fromList([
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
  ]);

  final iv = Uint8List(16);
  // Allocate output buffer
  final outEnc = Uint8List(plaintextBytes.length + 16);
  // Init AES Encrypt
  final ctxEnc = crypto.initAesCtx(keyBytes, libcrypt.AES_MODE_ECB, 1, iv); // 1 = encrypt  , 0 = decrypt
  // Update
  final updated = crypto.updateAes(ctxEnc, outEnc, plaintextBytes);
  if(updated == -1){
    print("AES encrypt updateAes failed");
    return;
  }else{
    print("AES encrypt updateAes success");
  }

  // Finish
  final finished = crypto.finishAes(ctxEnc, outEnc.sublist(updated));
  final cipherText = outEnc.sublist(0, updated + finished);
  if (cipherText.length == expectedCipherBytes.length &&
      ListEquality().equals(cipherText, expectedCipherBytes)) {
    print("✅ AES-256 ECB encryption matches expected output");
  } else {
    print("❌ AES-256 ECB encryption does NOT match expected output");
  }

  // Clear
  final cleared = crypto.clearAes(ctxEnc);
  if(cleared != 0){
    print("AES encrypt clearAes failed");
    return;
  }else{
    print("AES encrypt clearAes success");
  }
}
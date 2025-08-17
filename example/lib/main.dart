import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;

final crypto = libcrypt.BmcCrypto();



class BmcProtocolMessageCtx{
  final Uint8List chainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final Uint8List messageKey = Uint8List(libcrypt.BMC_PROTOCOL_MESSAGE_KEY_LEN);
  final Uint8List hmacKey = Uint8List(libcrypt.BMC_PROTOCOL_HMAC_KEY_LEN);
  final Uint8List nonce = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);

}

class BmcProtocolContext{
  //long term key
  final Uint8List ed25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_SKLEN);
  final Uint8List ed25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);
  final Uint8List x25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  final Uint8List x25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  //peer key
  final Uint8List ed25519PublicKeyPeer = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);
  final Uint8List x25519PublicKeyPeer = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  //ephemeral key
  final Uint8List x25519PrivateKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  final Uint8List x25519PublicKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  //secret_shared
  final Uint8List secretShared = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  //session_key
  BmcProtocolMessageCtx messageCtx = BmcProtocolMessageCtx();

  //init long term key
  int initLongTermKey(){
    var ret = crypto.generateEd25519Keypair(ed25519PublicKey, ed25519PrivateKey);
    if(ret != 0){
      return -1;
    }else{
      ret = crypto.convertEd25519ToX25519(ed25519PublicKey, ed25519PrivateKey, x25519PublicKey, x25519PrivateKey);
      if(ret != 0){
        return -1;
      }
    }
    return 0;
  }

  //set peer key
  int setPeerKey(Uint8List ed25519PublicKeyPeer, Uint8List x25519PublicKeyPeer){
    ed25519PublicKeyPeer.setAll(0, ed25519PublicKeyPeer);
    x25519PublicKeyPeer.setAll(0, x25519PublicKeyPeer);
    return 0;
  }

  //generate ephemeral key
  int generateEphemeralKey(){
    var ret = crypto.generateX25519Keypair(x25519PublicKeyEphemeral, x25519PrivateKeyEphemeral);
    if(ret != 0){
      return -1;
    }
    return ret;
  }
  //sign ephemeral public key
  Uint8List signEphemeralPublicKey(){
    final signature = Uint8List(libcrypt.BMC_PROTOCOL_SIGLEN);
    var ret = crypto.sign(x25519PublicKeyEphemeral, ed25519PrivateKey, signature);
    if(ret != 0){
      return Uint8List(0);
    }
    return signature;
  }
  //verify ephemeral public key
  int verifyEphemeralPublicKey(Uint8List signature, Uint8List x25519PublicKeyEphemeralPeer){
    var ret = crypto.verify(ed25519PublicKeyPeer, x25519PublicKeyEphemeralPeer, signature);
    if(ret != 0){
      return -1;
    }
    return ret;
  }

  //caculate secret shared
  int caculateSelfSecretShared(){
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKeyEphemeral, x25519PublicKeyPeer);
    if(ret != 0){
      return -1;
    }
    return ret;
  }

  //caculate peer secret shared
  int caculatePeerSecretShared(Uint8List x25519PublicKeyEphemeralPeer){
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKey, x25519PublicKeyEphemeralPeer);
    if(ret != 0){
      return -1;
    }
    return ret;
  }
}

void main() {

  funcAliceBobTest();
  
  // funAES256CBCTest();
  // funAES256CTRTest();
  // funAES256ECBTest();
}

void funcAliceBobTest(){
  // Khai báo context cho Alice và Bob để lưu khóa dài hạn
  final alice = BmcProtocolContext();
  final bob = BmcProtocolContext();
  //init long term key
  alice.initLongTermKey();
  bob.initLongTermKey();
  //print long term key
  print("alice ed25519 public key: ${alice.ed25519PublicKey}");
  print("alice ed25519 private key: ${alice.ed25519PrivateKey}");
  print("alice x25519 public key: ${alice.x25519PublicKey}");
  print("alice x25519 private key: ${alice.x25519PrivateKey}");
  print("bob ed25519 public key: ${bob.ed25519PublicKey}");
  print("bob ed25519 private key: ${bob.ed25519PrivateKey}");
  print("bob x25519 public key: ${bob.x25519PublicKey}");
  print("bob x25519 private key: ${bob.x25519PrivateKey}");
  //set peer key
  alice.setPeerKey(bob.ed25519PublicKey, bob.x25519PublicKey);
  bob.setPeerKey(alice.ed25519PublicKey, alice.x25519PublicKey);

  //Alice send to Bob
  //generate ephemeral key
  alice.generateEphemeralKey();
  //print ephemeral key
  print("alice ephemeral public key: ${alice.x25519PublicKeyEphemeral}");
  print("alice ephemeral private key: ${alice.x25519PrivateKeyEphemeral}");
  //sign ephemeral public key
  final signature = alice.signEphemeralPublicKey();
  print("alice signature: ${signature}");
  //caculate self secret shared
  alice.caculateSelfSecretShared();
  print("alice secret shared: ${alice.secretShared}");
  
  //derive session key
  
  //sign ephemeral public key
 
}


void funAES256CBCTest(){
  final key = Uint8List.fromList([
      0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  ]);
  // Nonce / Counter block
  final iv = Uint8List.fromList([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ]);
  final message = Uint8List.fromList(utf8.encode('Hello, Bob!'));
  // Allocate output buffer
  final outEnc = Uint8List(message.length + 16);
  // Init AES Encrypt
  final ctxEnc = crypto.initAesCtx(key, libcrypt.AES_MODE_CBC, 1, iv); // 1 = encrypt  , 0 = decrypt
  final ctxDec = crypto.initAesCtx(key, libcrypt.AES_MODE_CBC, 0, iv); // 1 = encrypt  , 0 = decrypt
  // Update
  final updated = crypto.updateAes(ctxEnc, outEnc, message);
  if(updated == -1){
    print("AES encrypt updateAes failed");
    return;
  }else{
    print("AES encrypt updateAes success");
  }

  // Finish
  final slice = outEnc.buffer.asUint8List(updated, outEnc.length - updated);
  final finished = crypto.finishAes(ctxEnc, slice);
  print("finished: $outEnc");
  final cipherText = outEnc.sublist(0, updated + finished);
  print("cipherText: ${cipherText}");

  // // Decrypt
  final outDec = Uint8List(cipherText.length);
  final updatedDec = crypto.updateAes(ctxDec, outDec, cipherText);
  if(updatedDec == -1){
    print("AES decrypt updateAes failed");
    return;
  }else{
    print("AES decrypt updateAes success");
  }
  // Finish
  final slicedec = outDec.buffer.asUint8List(updatedDec, outDec.length - updatedDec);
  final finishedDec = crypto.finishAes(ctxDec, slicedec);
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
    final sliceenc = outEnc.buffer.asUint8List(updated, outEnc.length - updated);
    final finished = crypto.finishAes(ctxEnc, sliceenc);
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
    final slicedec = outDec.buffer.asUint8List(updatedDec, outDec.length - updatedDec);
    final finishedDec = crypto.finishAes(ctxDec, slicedec);
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
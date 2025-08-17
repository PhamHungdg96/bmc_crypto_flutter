import 'dart:typed_data';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;

class BmcProtocolMessageCtx{
  final Uint8List chainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final Uint8List messageKey = Uint8List(libcrypt.BMC_PROTOCOL_MESSAGE_KEY_LEN);
  final Uint8List hmacKey = Uint8List(libcrypt.BMC_PROTOCOL_HMAC_KEY_LEN);
  final Uint8List nonce = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);

}

class BmcProtocolContext{
  //long term key
  final Uint8List ed25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_SKLEN);//private key ed25519 of long term key
  final Uint8List ed25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);//public key ed25519 of long term key
  final Uint8List x25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);//private key x25519 of long term key
  final Uint8List x25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN); //public key x25519 of long term key
  //peer long term key
  final Uint8List ed25519PublicKeyPeer = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);//public key ed25519 of peer
  final Uint8List x25519PublicKeyPeer = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);//public key x25519 of peer
  //ephemeral key
  final Uint8List x25519PrivateKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);//private key x25519 of ephemeral key
  final Uint8List x25519PublicKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);//public key x25519 of ephemeral key
  //secret_shared
  final Uint8List secretShared = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);//secret shared
  //session_key
  BmcProtocolMessageCtx messageCtx = BmcProtocolMessageCtx();//message context
  final libcrypt.BmcCrypto crypto;
  //constructor
  BmcProtocolContext({required this.crypto});
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
    assert(ed25519PublicKeyPeer.length == libcrypt.BMC_PROTOCOL_PKLEN);
    assert(x25519PublicKeyPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);

    this.ed25519PublicKeyPeer.setAll(0, ed25519PublicKeyPeer);
    this.x25519PublicKeyPeer.setAll(0, x25519PublicKeyPeer);
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
    assert(signature.length == libcrypt.BMC_PROTOCOL_SIGLEN);
    assert(x25519PublicKeyEphemeralPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    
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
    assert(x25519PublicKeyEphemeralPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKey, x25519PublicKeyEphemeralPeer);
    if(ret != 0){
      return -1;
    }
    return ret;
  }

  //derive session key
  int deriveSessionSelfKey(){
    final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    var ret = crypto.deriveSessionKeys(secretShared, x25519PublicKeyEphemeral, x25519PublicKey, rootKey, sendChainKey, recvChainKey);
    if(ret != 0){
      return -1;
    }
    messageCtx.chainKey.setAll(0, rootKey);
    return ret;
  }

  //derive session key
  int deriveSessionPeerKey(Uint8List x25519PublicKeyEphemeralPeer){
    assert(x25519PublicKeyEphemeralPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    
    final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    var ret = crypto.deriveSessionKeys(secretShared, x25519PublicKeyEphemeralPeer, x25519PublicKeyPeer, rootKey, sendChainKey, recvChainKey);
    if(ret != 0){
      return -1;
    }
    messageCtx.chainKey.setAll(0, rootKey);
    return ret;
  }

  //derive message key
  int deriveMessageKey(){
    final nextChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final macKey = Uint8List(libcrypt.BMC_PROTOCOL_HMAC_KEY_LEN);
    final iv = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
    var ret = crypto.deriveMessageKeys(messageCtx.chainKey, messageCtx.messageKey, nextChainKey, macKey, iv);
    if(ret != 0){
      return -1;
    }
    messageCtx.chainKey.setAll(0, nextChainKey);
    messageCtx.hmacKey.setAll(0, macKey);
    messageCtx.nonce.setAll(0, iv);
    return ret;
  }

  //encrypt message
  Uint8List encryptMessage(Uint8List message){
    assert(message.isNotEmpty);
    
    final ciphertext = crypto.encrypt(message, messageCtx.messageKey, messageCtx.nonce, messageCtx.hmacKey);
    return ciphertext;
  }

  //decrypt message
  Uint8List decryptMessage(Uint8List ciphertext){
    assert(ciphertext.isNotEmpty);
    
    final plaintext = crypto.decrypt(ciphertext, messageCtx.messageKey, messageCtx.nonce, messageCtx.hmacKey);
    return plaintext;
  }
}
import 'dart:typed_data';
import 'package:flutter/foundation.dart';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;

class BmcProtocolMessageCtx{
  final Uint8List chainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final Uint8List messageKey = Uint8List(libcrypt.BMC_PROTOCOL_MESSAGE_KEY_LEN);
  final Uint8List hmacKey = Uint8List(libcrypt.BMC_PROTOCOL_HMAC_KEY_LEN);
  final Uint8List nonce = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
}

// ==================== SESSION ====================
/// Per-session state (ephemeral, peer key, message context)
class BmcProtocolSession {
  final String sessionId;
  final libcrypt.BmcCrypto crypto;
  
  // Peer long-term key
  final Uint8List ed25519PublicKeyPeer = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);
  final Uint8List x25519PublicKeyPeer = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  // Ephemeral key
  final Uint8List x25519PrivateKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  final Uint8List x25519PublicKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  // Secret shared
  final Uint8List secretShared = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  // Message context
  BmcProtocolMessageCtx messageCtx = BmcProtocolMessageCtx();

  // Reference to long-term keys from context
  final Uint8List ed25519PrivateKey;
  final Uint8List ed25519PublicKey;
  final Uint8List x25519PrivateKey;
  final Uint8List x25519PublicKey;

  BmcProtocolSession({
    required this.sessionId,
    required this.crypto,
    required this.ed25519PrivateKey,
    required this.ed25519PublicKey,
    required this.x25519PrivateKey,
    required this.x25519PublicKey,
  });

  // Set peer key
  int setPeerKey(Uint8List ed25519PublicKeyPeer, Uint8List x25519PublicKeyPeer){
    assert(ed25519PublicKeyPeer.length == libcrypt.BMC_PROTOCOL_PKLEN);
    assert(x25519PublicKeyPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    this.ed25519PublicKeyPeer.setAll(0, ed25519PublicKeyPeer);
    this.x25519PublicKeyPeer.setAll(0, x25519PublicKeyPeer);
    return 0;
  }

  // Generate ephemeral key
  int generateEphemeralKey(){
    var ret = crypto.generateX25519Keypair(x25519PublicKeyEphemeral, x25519PrivateKeyEphemeral);
    if(ret != 0) return -1;
    return ret;
  }

  // Sign ephemeral public key
  Uint8List signEphemeralPublicKey(){
    final signature = Uint8List(libcrypt.BMC_PROTOCOL_SIGLEN);
    var ret = crypto.sign(x25519PublicKeyEphemeral, ed25519PrivateKey, signature);
    if(ret != 0) return Uint8List(0);
    return signature;
  }

  // Verify ephemeral public key
  int verifyEphemeralPublicKey(Uint8List signature, Uint8List x25519PublicKeyEphemeralPeer){
    assert(signature.length == libcrypt.BMC_PROTOCOL_SIGLEN);
    assert(x25519PublicKeyEphemeralPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    var ret = crypto.verify(ed25519PublicKeyPeer, x25519PublicKeyEphemeralPeer, signature);
    if(ret != 0) return -1;
    return ret;
  }

  // Calculate self secret shared
  int caculateSelfSecretShared(){
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKeyEphemeral, x25519PublicKeyPeer);
    if(ret != 0) return -1;
    return ret;
  }

  // Calculate peer secret shared
  int caculatePeerSecretShared(Uint8List x25519PublicKeyEphemeralPeer){
    assert(x25519PublicKeyEphemeralPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKey, x25519PublicKeyEphemeralPeer);
    if(ret != 0) return -1;
    return ret;
  }

  // Derive session self key
  int deriveSessionSelfKey(){
    final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    var ret = crypto.deriveSessionKeys(secretShared, x25519PublicKeyEphemeral, x25519PublicKey, rootKey, sendChainKey, recvChainKey);
    if(ret != 0) return -1;
    messageCtx.chainKey.setAll(0, rootKey);
    return ret;
  }

  // Derive session peer key
  int deriveSessionPeerKey(Uint8List x25519PublicKeyEphemeralPeer){
    assert(x25519PublicKeyEphemeralPeer.length == libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
    final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    var ret = crypto.deriveSessionKeys(secretShared, x25519PublicKeyEphemeralPeer, x25519PublicKeyPeer, rootKey, sendChainKey, recvChainKey);
    if(ret != 0) return -1;
    messageCtx.chainKey.setAll(0, rootKey);
    return ret;
  }

  // Derive message key
  int deriveMessageKey(Uint8List salt){
    final iv = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
    var ret = crypto.deriveMessageKeys(messageCtx.chainKey, salt, messageCtx.messageKey, null, null, iv);
    if(ret != 0) return -1;
    messageCtx.nonce.setAll(0, iv);
    return ret;
  }

  // Encrypt message
  Uint8List encryptMessage(Uint8List message, Uint8List aad){
    assert(message.isNotEmpty);
    final ciphertext = crypto.encryptAEAD(message, aad, messageCtx.messageKey, messageCtx.nonce);
    return ciphertext;
  }

  // Decrypt message
  Uint8List decryptMessage(Uint8List ciphertext, Uint8List aad){
    assert(ciphertext.isNotEmpty);
    final plaintext = crypto.decryptAEAD(ciphertext, aad, messageCtx.messageKey, messageCtx.nonce);
    return plaintext;
  }

  // ==================== ASYNC FUNCTIONS ====================
  Future<Uint8List> signEphemeralPublicKeyAsync() async {
    final params = _SignEphemeralParams(x25519PublicKeyEphemeral, ed25519PrivateKey);
    return await compute(_signEphemeralPublicKeyIsolate, params);
  }

  Future<bool> verifyEphemeralPublicKeyAsync(Uint8List signature, Uint8List x25519PublicKeyEphemeralPeer) async {
    final params = _VerifyEphemeralParams(signature, x25519PublicKeyEphemeralPeer, ed25519PublicKeyPeer);
    return await compute(_verifyEphemeralPublicKeyIsolate, params);
  }

  Future<Uint8List> calculateSelfSecretSharedAsync() async {
    final params = _CalculateSecretParams(x25519PrivateKeyEphemeral, x25519PublicKeyPeer);
    return await compute(_calculateSecretSharedIsolate, params);
  }

  Future<Uint8List> calculatePeerSecretSharedAsync(Uint8List x25519PublicKeyEphemeralPeer) async {
    final params = _CalculateSecretParams(x25519PrivateKey, x25519PublicKeyEphemeralPeer);
    return await compute(_calculateSecretSharedIsolate, params);
  }

  Future<Uint8List> deriveSessionSelfKeyAsync() async {
    final params = _DeriveSessionKeyParams(secretShared, x25519PublicKeyEphemeral, x25519PublicKey);
    return await compute(_deriveSessionSelfKeyIsolate, params);
  }

  Future<Uint8List> deriveSessionPeerKeyAsync(Uint8List x25519PublicKeyEphemeralPeer) async {
    final params = _DeriveSessionKeyParams(secretShared, x25519PublicKeyEphemeralPeer, x25519PublicKeyPeer);
    return await compute(_deriveSessionPeerKeyIsolate, params);
  }

  Future<_MessageKeyResult> deriveMessageKeyAsync(Uint8List salt) async {
    final params = _DeriveMessageKeyParams(messageCtx.chainKey, salt);
    return await compute(_deriveMessageKeyIsolate, params);
  }

  Future<Uint8List> encryptMessageAsync(Uint8List message, Uint8List aad) async {
    final params = _EncryptMessageParams(message, aad, messageCtx.messageKey, messageCtx.nonce);
    return await compute(_encryptMessageIsolate, params);
  }

  Future<Uint8List> decryptMessageAsync(Uint8List ciphertext, Uint8List aad) async {
    final params = _EncryptMessageParams(ciphertext, aad, messageCtx.messageKey, messageCtx.nonce);
    return await compute(_decryptMessageIsolate, params);
  }
}

// ==================== CONTEXT (Long-term key + session manager) ====================
class BmcProtocolContext {
  //long term key
  final Uint8List ed25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_SKLEN);
  final Uint8List ed25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);
  final Uint8List x25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  final Uint8List x25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  final libcrypt.BmcCrypto crypto;
  
  // Session management
  final Map<String, BmcProtocolSession> _sessions = {};

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

  // ==================== SESSION MANAGEMENT ====================
  
  /// Create a new session
  BmcProtocolSession createSession(String sessionId) {
    if (_sessions.containsKey(sessionId)) {
      throw Exception('Session $sessionId already exists');
    }
    final session = BmcProtocolSession(
      sessionId: sessionId,
      crypto: crypto,
      ed25519PrivateKey: ed25519PrivateKey,
      ed25519PublicKey: ed25519PublicKey,
      x25519PrivateKey: x25519PrivateKey,
      x25519PublicKey: x25519PublicKey,
    );
    _sessions[sessionId] = session;
    return session;
  }

  /// Get session by ID
  BmcProtocolSession? getSession(String sessionId) {
    return _sessions[sessionId];
  }

  /// Get session by ID, throw if not found
  BmcProtocolSession getSessionOrThrow(String sessionId) {
    final session = _sessions[sessionId];
    if (session == null) {
      throw Exception('Session $sessionId not found');
    }
    return session;
  }

  /// Close session by ID
  void closeSession(String sessionId) {
    _sessions.remove(sessionId);
  }

  /// Get all active sessions
  List<BmcProtocolSession> getAllSessions() {
    return _sessions.values.toList();
  }

  /// Get number of active sessions
  int getSessionCount() {
    return _sessions.length;
  }

  /// Close all sessions
  void closeAllSessions() {
    _sessions.clear();
  }
}

// ==================== ISOLATE PARAMETER CLASSES ====================

class _SignEphemeralParams {
  final Uint8List x25519PublicKeyEphemeral;
  final Uint8List ed25519PrivateKey;
  
  _SignEphemeralParams(this.x25519PublicKeyEphemeral, this.ed25519PrivateKey);
}

class _VerifyEphemeralParams {
  final Uint8List signature;
  final Uint8List x25519PublicKeyEphemeralPeer;
  final Uint8List ed25519PublicKeyPeer;
  
  _VerifyEphemeralParams(this.signature, this.x25519PublicKeyEphemeralPeer, this.ed25519PublicKeyPeer);
}

class _CalculateSecretParams {
  final Uint8List privateKey;
  final Uint8List publicKey;
  
  _CalculateSecretParams(this.privateKey, this.publicKey);
}

class _DeriveSessionKeyParams {
  final Uint8List secretShared;
  final Uint8List ephemeralPk;
  final Uint8List peerPk;
  
  _DeriveSessionKeyParams(this.secretShared, this.ephemeralPk, this.peerPk);
}

class _DeriveMessageKeyParams {
  final Uint8List chainKey;
  final Uint8List salt;
  
  _DeriveMessageKeyParams(this.chainKey, this.salt);
}

class _EncryptMessageParams {
  final Uint8List message;
  final Uint8List aad;
  final Uint8List messageKey;
  final Uint8List nonce;
  
  _EncryptMessageParams(this.message,this.aad,this.messageKey, this.nonce);
}

// ==================== ISOLATE RESULT CLASSES ====================

class _MessageKeyResult {
  final Uint8List chainKey;
  final Uint8List messageKey;
  final Uint8List hmacKey;
  final Uint8List nonce;
  
  _MessageKeyResult(this.chainKey, this.messageKey, this.hmacKey, this.nonce);
}

// ==================== ISOLATE WORKER FUNCTIONS ====================

/// Isolate worker function for long term key initialization
bool _initLongTermKeyIsolate(void _) {
  final crypto = libcrypt.BmcCrypto();
  final ed25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);
  final ed25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_SKLEN);
  final x25519PublicKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  final x25519PrivateKey = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  try {
    crypto.generateEd25519Keypair(ed25519PublicKey, ed25519PrivateKey);
    crypto.convertEd25519ToX25519(ed25519PublicKey, ed25519PrivateKey, x25519PublicKey, x25519PrivateKey);
    return true;
  } catch (e) {
    return false;
  }
}

/// Isolate worker function for ephemeral key generation
bool _generateEphemeralKeyIsolate(void _) {
  final crypto = libcrypt.BmcCrypto();
  final x25519PublicKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  final x25519PrivateKeyEphemeral = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  try {
    crypto.generateX25519Keypair(x25519PublicKeyEphemeral, x25519PrivateKeyEphemeral);
    return true;
  } catch (e) {
    return false;
  }
}

/// Isolate worker function for signing ephemeral public key
Uint8List _signEphemeralPublicKeyIsolate(_SignEphemeralParams params) {
  final crypto = libcrypt.BmcCrypto();
  final signature = Uint8List(libcrypt.BMC_PROTOCOL_SIGLEN);
  
  crypto.sign(params.x25519PublicKeyEphemeral, params.ed25519PrivateKey, signature);
  return signature;
}

/// Isolate worker function for verifying ephemeral public key
bool _verifyEphemeralPublicKeyIsolate(_VerifyEphemeralParams params) {
  final crypto = libcrypt.BmcCrypto();
  
  try {
    final result = crypto.verify(params.ed25519PublicKeyPeer, params.x25519PublicKeyEphemeralPeer, params.signature);
    return result == 0;
  } catch (e) {
    return false;
  }
}

/// Isolate worker function for calculating secret shared
Uint8List _calculateSecretSharedIsolate(_CalculateSecretParams params) {
  final crypto = libcrypt.BmcCrypto();
  final secret = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
  
  crypto.caculateSecret(secret, params.privateKey, params.publicKey);
  return secret;
}

/// Isolate worker function for deriving session self key
Uint8List _deriveSessionSelfKeyIsolate(_DeriveSessionKeyParams params) {
  final crypto = libcrypt.BmcCrypto();
  final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  
  crypto.deriveSessionKeys(params.secretShared, params.ephemeralPk, params.peerPk, rootKey, sendChainKey, recvChainKey);
  return rootKey;
}

/// Isolate worker function for deriving session peer key
Uint8List _deriveSessionPeerKeyIsolate(_DeriveSessionKeyParams params) {
  final crypto = libcrypt.BmcCrypto();
  final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  
  crypto.deriveSessionKeys(params.secretShared, params.ephemeralPk, params.peerPk, rootKey, sendChainKey, recvChainKey);
  return rootKey;
}

/// Isolate worker function for deriving message key
_MessageKeyResult _deriveMessageKeyIsolate(_DeriveMessageKeyParams params) {
  final crypto = libcrypt.BmcCrypto();
  final messageKey = Uint8List(libcrypt.BMC_PROTOCOL_MESSAGE_KEY_LEN);
  final iv = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
  
  crypto.deriveMessageKeys(params.chainKey, params.salt, messageKey, null, null, iv);
  return _MessageKeyResult(params.chainKey, messageKey, Uint8List(0), iv);
}

/// Isolate worker function for message encryption
Uint8List _encryptMessageIsolate(_EncryptMessageParams params) {
  final crypto = libcrypt.BmcCrypto();
  return crypto.encryptAEAD(params.message, params.aad, params.messageKey, params.nonce);
}

/// Isolate worker function for message decryption
Uint8List _decryptMessageIsolate(_EncryptMessageParams params) {
  final crypto = libcrypt.BmcCrypto();
  return crypto.decryptAEAD(params.message, params.aad, params.messageKey, params.nonce);
}
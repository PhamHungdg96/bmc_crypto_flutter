import 'dart:typed_data';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;
import 'package:bmc_cryptographic_flutter/bmc_crypto_worker.dart';

class BmcProtocolMessageCtx{
  final Uint8List chainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
  final Uint8List messageKey = Uint8List(libcrypt.BMC_PROTOCOL_MESSAGE_KEY_LEN);
  final Uint8List hmacKey = Uint8List(libcrypt.BMC_PROTOCOL_HMAC_KEY_LEN);
  final Uint8List nonce = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
}

// ==================== SESSION ====================
/// Per-session state (ephemeral, peer key, message context)
class BmcProtocolSession {
  bool _isClosed = false;

  bool get isClosed => _isClosed;

  void _clearBytes(Uint8List bytes) {
    bytes.fillRange(0, bytes.length, 0);
  }

  void close() {
    if (_isClosed) return;

    _clearBytes(ed25519PublicKeyPeer);
    _clearBytes(x25519PublicKeyPeer);
    _clearBytes(x25519PrivateKeyEphemeral);
    _clearBytes(x25519PublicKeyEphemeral);
    _clearBytes(secretShared);

    _clearBytes(messageCtx.chainKey);
    _clearBytes(messageCtx.messageKey);
    _clearBytes(messageCtx.hmacKey);
    _clearBytes(messageCtx.nonce);

    _isClosed = true;
  }

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

  // Persistent isolate worker for async operations
  final BmcCryptoWorker worker;

  BmcProtocolSession({
    required this.sessionId,
    required this.crypto,
    required this.worker,
    required this.ed25519PrivateKey,
    required this.ed25519PublicKey,
    required this.x25519PrivateKey,
    required this.x25519PublicKey,
  });

  // Set peer key
  int setPeerKey(Uint8List ed25519PublicKeyPeer, Uint8List x25519PublicKeyPeer){
    if (_isClosed) throw StateError('Session is closed');
    if (ed25519PublicKeyPeer.length != libcrypt.BMC_PROTOCOL_PKLEN) {
      throw ArgumentError('ed25519PublicKeyPeer length must be ${libcrypt.BMC_PROTOCOL_PKLEN}');
    }
    if (x25519PublicKeyPeer.length != libcrypt.BMC_PROTOCOL_x25519_KEYLEN) {
      throw ArgumentError('x25519PublicKeyPeer length must be ${libcrypt.BMC_PROTOCOL_x25519_KEYLEN}');
    }
    this.ed25519PublicKeyPeer.setAll(0, ed25519PublicKeyPeer);
    this.x25519PublicKeyPeer.setAll(0, x25519PublicKeyPeer);
    return 0;
  }

  // Generate ephemeral key
  int generateEphemeralKey(){
    if (_isClosed) throw StateError('Session is closed');
    var ret = crypto.generateX25519Keypair(x25519PublicKeyEphemeral, x25519PrivateKeyEphemeral);
    if(ret != 0) return -1;
    return ret;
  }

  // Sign ephemeral public key
  Uint8List signEphemeralPublicKey(){
    if (_isClosed) throw StateError('Session is closed');
    final signature = Uint8List(libcrypt.BMC_PROTOCOL_SIGLEN);
    var ret = crypto.sign(x25519PublicKeyEphemeral, ed25519PrivateKey, signature);
    if(ret != 0) throw Exception('Failed to sign ephemeral public key: error code $ret');
    return signature;
  }

  // Verify ephemeral public key
  int verifyEphemeralPublicKey(Uint8List signature, Uint8List x25519PublicKeyEphemeralPeer){
    if (_isClosed) throw StateError('Session is closed');
    if (signature.length != libcrypt.BMC_PROTOCOL_SIGLEN) {
      throw ArgumentError('signature length must be ${libcrypt.BMC_PROTOCOL_SIGLEN}');
    }
    if (x25519PublicKeyEphemeralPeer.length != libcrypt.BMC_PROTOCOL_x25519_KEYLEN) {
      throw ArgumentError('x25519PublicKeyEphemeralPeer length must be ${libcrypt.BMC_PROTOCOL_x25519_KEYLEN}');
    }
    var ret = crypto.verify(ed25519PublicKeyPeer, x25519PublicKeyEphemeralPeer, signature);
    if(ret != 0) return -1;
    return ret;
  }

  // Calculate self secret shared
  int calculateSelfSecretShared(){
    if (_isClosed) throw StateError('Session is closed');
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKeyEphemeral, x25519PublicKeyPeer);
    if(ret != 0) return -1;
    return ret;
  }

  // Calculate peer secret shared
  int calculatePeerSecretShared(Uint8List x25519PublicKeyEphemeralPeer){
    if (_isClosed) throw StateError('Session is closed');
    if (x25519PublicKeyEphemeralPeer.length != libcrypt.BMC_PROTOCOL_x25519_KEYLEN) {
      throw ArgumentError('x25519PublicKeyEphemeralPeer length must be ${libcrypt.BMC_PROTOCOL_x25519_KEYLEN}');
    }
    var ret = crypto.caculateSecret(secretShared, x25519PrivateKey, x25519PublicKeyEphemeralPeer);
    if(ret != 0) return -1;
    return ret;
  }

  // Deprecated: use calculateSelfSecretShared
  @deprecated
  int caculateSelfSecretShared() => calculateSelfSecretShared();

  // Deprecated: use calculatePeerSecretShared
  @deprecated
  int caculatePeerSecretShared(Uint8List x25519PublicKeyEphemeralPeer) =>
      calculatePeerSecretShared(x25519PublicKeyEphemeralPeer);

  // Derive session self key
  int deriveSessionSelfKey(){
    if (_isClosed) throw StateError('Session is closed');
    final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    try {
      var ret = crypto.deriveSessionKeys(secretShared, x25519PublicKeyEphemeral, x25519PublicKey, rootKey, sendChainKey, recvChainKey);
      if(ret != 0) return -1;
      messageCtx.chainKey.setAll(0, rootKey);
      return ret;
    } finally {
      // Clear temporary sensitive data
      _clearBytes(rootKey);
      _clearBytes(sendChainKey);
      _clearBytes(recvChainKey);
    }
  }

  // Derive session peer key
  int deriveSessionPeerKey(Uint8List x25519PublicKeyEphemeralPeer){
    if (_isClosed) throw StateError('Session is closed');
    if (x25519PublicKeyEphemeralPeer.length != libcrypt.BMC_PROTOCOL_x25519_KEYLEN) {
      throw ArgumentError('x25519PublicKeyEphemeralPeer length must be ${libcrypt.BMC_PROTOCOL_x25519_KEYLEN}');
    }
    final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final sendChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    final recvChainKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
    try {
      var ret = crypto.deriveSessionKeys(secretShared, x25519PublicKeyEphemeralPeer, x25519PublicKeyPeer, rootKey, sendChainKey, recvChainKey);
      if(ret != 0) return -1;
      messageCtx.chainKey.setAll(0, rootKey);
      return ret;
    } finally {
      // Clear temporary sensitive data
      _clearBytes(rootKey);
      _clearBytes(sendChainKey);
      _clearBytes(recvChainKey);
    }
  }

  int setChainKey(Uint8List value) {
    if (_isClosed) throw StateError('Session is closed');
    if (value.length != libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN) {
      throw ArgumentError('value length must be ${libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN}');
    }
    messageCtx.chainKey.setAll(0, value);
    return 0;
  }

  // Derive message key
  int deriveMessageKey(Uint8List salt){
    if (_isClosed) throw StateError('Session is closed');
    final iv = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
    try {
      var ret = crypto.deriveMessageKeys(messageCtx.chainKey, salt, messageCtx.messageKey, null, null, iv);
      if(ret != 0) return -1;
      messageCtx.nonce.setAll(0, iv);
      return ret;
    } finally {
      // Clear temporary IV from stack
      _clearBytes(iv);
    }
  }

  // Encrypt message
  Uint8List encryptMessage(Uint8List message, Uint8List aad){
    if (_isClosed) throw StateError('Session is closed');
    if (message.isEmpty) throw ArgumentError('message cannot be empty');
    final ciphertext = crypto.encryptAEAD(message, aad, messageCtx.messageKey, messageCtx.nonce.sublist(0,libcrypt.BMC_PROTOCOL_GCM_NONCE_LEN));
    return ciphertext;
  }

  // Decrypt message
  Uint8List decryptMessage(Uint8List ciphertext, Uint8List aad){
    if (_isClosed) throw StateError('Session is closed');
    if (ciphertext.isEmpty) throw ArgumentError('ciphertext cannot be empty');
    final plaintext = crypto.decryptAEAD(ciphertext, aad, messageCtx.messageKey, messageCtx.nonce.sublist(0,libcrypt.BMC_PROTOCOL_GCM_NONCE_LEN));
    return plaintext;
  }

  // ==================== ASYNC FUNCTIONS ====================
  Future<Uint8List> signEphemeralPublicKeyAsync() =>
      worker.signEphemeralPublicKey(x25519PublicKeyEphemeral, ed25519PrivateKey);

  Future<bool> verifyEphemeralPublicKeyAsync(
    Uint8List signature,
    Uint8List x25519PublicKeyEphemeralPeer,
  ) =>
      worker.verifyEphemeralPublicKey(
          signature, x25519PublicKeyEphemeralPeer, ed25519PublicKeyPeer);

  Future<int> calculateSelfSecretSharedAsync() async {
    if (_isClosed) throw StateError('Session is closed');
    final secret =
        await worker.calculateSecret(x25519PrivateKeyEphemeral, x25519PublicKeyPeer);
    secretShared.setAll(0, secret);
    return 0;
  }

  Future<int> calculatePeerSecretSharedAsync(
    Uint8List x25519PublicKeyEphemeralPeer,
  ) async {
    if (_isClosed) throw StateError('Session is closed');
    final secret =
        await worker.calculateSecret(x25519PrivateKey, x25519PublicKeyEphemeralPeer);
    secretShared.setAll(0, secret);
    return 0;
  }

  Future<int> deriveSessionSelfKeyAsync() async {
    if (_isClosed) throw StateError('Session is closed');
    final rootKey = await worker.deriveSessionKey(
        secretShared, x25519PublicKeyEphemeral, x25519PublicKey);
    if (_isClosed) throw StateError('Session is closed');
    messageCtx.chainKey.setAll(0, rootKey);
    return 0;
  }

  Future<int> deriveSessionPeerKeyAsync(
    Uint8List x25519PublicKeyEphemeralPeer,
  ) async {
    if (_isClosed) throw StateError('Session is closed');
    final rootKey = await worker.deriveSessionKey(
        secretShared, x25519PublicKeyEphemeralPeer, x25519PublicKeyPeer);
    if (_isClosed) throw StateError('Session is closed');
    messageCtx.chainKey.setAll(0, rootKey);
    return 0;
  }

  Future<int> deriveMessageKeyAsync(Uint8List salt) async {
    if (_isClosed) throw StateError('Session is closed');
    final result = await worker.deriveMessageKey(messageCtx.chainKey, salt);
    if (_isClosed) throw StateError('Session is closed');
    messageCtx.messageKey.setAll(0, result.messageKey);
    messageCtx.nonce.setAll(0, result.nonce);
    return 0;
  }

  Future<Uint8List> encryptMessageAsync(Uint8List message, Uint8List aad) async {
    if (_isClosed) throw StateError('Session is closed');
    return await worker.encryptAEAD(message, aad, messageCtx.messageKey,
        messageCtx.nonce.sublist(0, libcrypt.BMC_PROTOCOL_GCM_NONCE_LEN));
  }

  Future<Uint8List> decryptMessageAsync(
    Uint8List ciphertext,
    Uint8List aad,
  ) async {
    if (_isClosed) throw StateError('Session is closed');
    return await worker.decryptAEAD(ciphertext, aad, messageCtx.messageKey,
        messageCtx.nonce.sublist(0, libcrypt.BMC_PROTOCOL_GCM_NONCE_LEN));
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

  /// Persistent isolate worker shared across all sessions in this context.
  final BmcCryptoWorker worker;

  // Session management
  final Map<String, BmcProtocolSession> _sessions = {};

  //constructor
  BmcProtocolContext({required this.crypto, required this.worker});
  
  //init long term key - must be called once before creating sessions
  int initLongTermKey(){
    // Validate keys are not already initialized
    final isEd25519Initialized = ed25519PublicKey.any((b) => b != 0) || ed25519PrivateKey.any((b) => b != 0);
    if (isEd25519Initialized) {
      throw StateError('Long-term keys are already initialized. Create a new context to reinitialize.');
    }

    var ret = crypto.generateEd25519Keypair(ed25519PublicKey, ed25519PrivateKey);
    if(ret != 0){
      // Rollback: clear any partial state
      _clearBytes(ed25519PublicKey);
      _clearBytes(ed25519PrivateKey);
      return -1;
    }
    
    ret = crypto.convertEd25519ToX25519(ed25519PublicKey, ed25519PrivateKey, x25519PublicKey, x25519PrivateKey);
    if(ret != 0){
      // Rollback: clear all keys
      _clearBytes(ed25519PublicKey);
      _clearBytes(ed25519PrivateKey);
      _clearBytes(x25519PublicKey);
      _clearBytes(x25519PrivateKey);
      return -1;
    }
    return 0;
  }

  // ==================== SESSION MANAGEMENT ====================
  
  /// Create a new session
  BmcProtocolSession createSession(String sessionId) {
    if (sessionId.isEmpty) {
      throw ArgumentError('sessionId cannot be empty');
    }
    if (_sessions.containsKey(sessionId)) {
      throw Exception('Session $sessionId already exists');
    }
    // Validate that long-term keys have been initialized
    final isKeysInitialized = ed25519PublicKey.any((b) => b != 0) || x25519PublicKey.any((b) => b != 0);
    if (!isKeysInitialized) {
      throw StateError('Long-term keys not initialized. Call initLongTermKey() first.');
    }
    final session = BmcProtocolSession(
      sessionId: sessionId,
      crypto: crypto,
      worker: worker,
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
    if (sessionId.isEmpty) {
      throw ArgumentError('sessionId cannot be empty');
    }
    final session = _sessions.remove(sessionId);
    if (session == null) {
      throw Exception('Session $sessionId not found');
    }
    session.close();
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
    for (final session in _sessions.values) {
      session.close();
    }
    _sessions.clear();
  }

  /// Close all sessions and stop the worker isolate.
  /// After calling this, the context should not be used.
  void close() {
    closeAllSessions();
    // Clear long-term keys before stopping worker
    _clearBytes(ed25519PrivateKey);
    _clearBytes(ed25519PublicKey);
    _clearBytes(x25519PrivateKey);
    _clearBytes(x25519PublicKey);
    // Stop worker isolate
    // worker.stop();
  }

  void _clearBytes(Uint8List bytes) {
    bytes.fillRange(0, bytes.length, 0);
  }
}
import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;

// ==================== PUBLIC RESULT CLASSES ====================

class DeriveMessageKeyResult {
  final Uint8List messageKey;
  final Uint8List nonce;

  DeriveMessageKeyResult(this.messageKey, this.nonce);
}

class KeypairResult {
  final Uint8List publicKey;
  final Uint8List privateKey;

  KeypairResult(this.publicKey, this.privateKey);
}

// ==================== INTERNAL MESSAGE CLASSES ====================

enum _Op {
  sign,
  verify,
  calcSecret,
  deriveSession,
  deriveMessage,
  encrypt,
  decrypt,
  genEd25519,
  genX25519,
  convertEd25519ToX25519,
}

class _Request {
  final int id;
  final _Op op;
  final Object params;

  _Request(this.id, this.op, this.params);
}

class _Response {
  final int id;
  final Object? result;
  final String? error;

  _Response(this.id, {this.result, this.error});
}

// ==================== INTERNAL PARAM CLASSES ====================

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

class _CalcSecretParams {
  final Uint8List privateKey;
  final Uint8List publicKey;

  _CalcSecretParams(this.privateKey, this.publicKey);
}

class _DeriveSessionParams {
  final Uint8List secretShared;
  final Uint8List ephemeralPk;
  final Uint8List peerPk;

  _DeriveSessionParams(this.secretShared, this.ephemeralPk, this.peerPk);
}

class _DeriveMessageParams {
  final Uint8List chainKey;
  final Uint8List salt;

  _DeriveMessageParams(this.chainKey, this.salt);
}

class _CipherParams {
  final Uint8List data;
  final Uint8List aad;
  final Uint8List messageKey;
  final Uint8List nonce;

  _CipherParams(this.data, this.aad, this.messageKey, this.nonce);
}

class _ConvertKeyParams {
  final Uint8List ed25519PublicKey;
  final Uint8List ed25519PrivateKey;

  _ConvertKeyParams(this.ed25519PublicKey, this.ed25519PrivateKey);
}

// ==================== ISOLATE ENTRY (top-level required) ====================

void _workerEntry(SendPort mainPort) {
  final port = ReceivePort();
  mainPort.send(port.sendPort);

  final crypto = libcrypt.BmcCrypto();

  port.listen((dynamic msg) {
    if (msg is! _Request) return;
    try {
      Object? result;
      switch (msg.op) {
        case _Op.sign:
          final p = msg.params as _SignParams;
          final sig = Uint8List(libcrypt.BMC_PROTOCOL_SIGLEN);
          crypto.sign(p.message, p.privateKey, sig);
          result = sig;
        case _Op.verify:
          final p = msg.params as _VerifyParams;
          result = crypto.verify(p.publicKey, p.message, p.signature) == 0;
        case _Op.calcSecret:
          final p = msg.params as _CalcSecretParams;
          final secret = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
          crypto.caculateSecret(secret, p.privateKey, p.publicKey);
          result = secret;
        case _Op.deriveSession:
          final p = msg.params as _DeriveSessionParams;
          final rootKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
          final sendKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
          final recvKey = Uint8List(libcrypt.BMC_PROTOCOL_CHAIN_KEY_LEN);
          crypto.deriveSessionKeys(
              p.secretShared, p.ephemeralPk, p.peerPk, rootKey, sendKey, recvKey);
          result = rootKey;
        case _Op.deriveMessage:
          final p = msg.params as _DeriveMessageParams;
          final msgKey = Uint8List(libcrypt.BMC_PROTOCOL_MESSAGE_KEY_LEN);
          final iv = Uint8List(libcrypt.BMC_PROTOCOL_NONCE_LEN);
          crypto.deriveMessageKeys(p.chainKey, p.salt, msgKey, null, null, iv);
          result = DeriveMessageKeyResult(msgKey, iv);
        case _Op.encrypt:
          final p = msg.params as _CipherParams;
          result = crypto.encryptAEAD(p.data, p.aad, p.messageKey, p.nonce);
        case _Op.decrypt:
          final p = msg.params as _CipherParams;
          result = crypto.decryptAEAD(p.data, p.aad, p.messageKey, p.nonce);
        case _Op.genEd25519:
          final pk = Uint8List(libcrypt.BMC_PROTOCOL_PKLEN);
          final sk = Uint8List(libcrypt.BMC_PROTOCOL_SKLEN);
          crypto.generateEd25519Keypair(pk, sk);
          result = KeypairResult(pk, sk);
        case _Op.genX25519:
          final pk = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
          final sk = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
          crypto.generateX25519Keypair(pk, sk);
          result = KeypairResult(pk, sk);
        case _Op.convertEd25519ToX25519:
          final p = msg.params as _ConvertKeyParams;
          final xPk = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
          final xSk = Uint8List(libcrypt.BMC_PROTOCOL_x25519_KEYLEN);
          crypto.convertEd25519ToX25519(p.ed25519PublicKey, p.ed25519PrivateKey, xPk, xSk);
          result = KeypairResult(xPk, xSk);
      }
      mainPort.send(_Response(msg.id, result: result));
    } catch (e) {
      mainPort.send(_Response(msg.id, error: e.toString()));
    }
  });
}

// ==================== PUBLIC WORKER CLASS ====================

/// Persistent isolate worker for offloading crypto operations.
/// Reuses a single long-lived isolate to avoid per-call spawn overhead.
///
/// Usage:
/// ```dart
/// final worker = BmcCryptoWorker();
/// await worker.start();
/// // ... use worker methods ...
/// worker.stop();
/// ```
class BmcCryptoWorker {
  Isolate? _isolate;
  SendPort? _sendPort;
  ReceivePort? _receivePort;
  final _pending = <int, Completer<Object?>>{};
  int _nextId = 0;

  bool get isRunning => _sendPort != null;

  /// Spawns the background isolate and waits until it is ready.
  Future<void> start() async {
    if (_sendPort != null) return;

    _receivePort = ReceivePort();
    final ready = Completer<void>();

    _receivePort!.listen((dynamic msg) {
      if (msg is SendPort) {
        _sendPort = msg;
        if (!ready.isCompleted) ready.complete();
        return;
      }
      if (msg is _Response) {
        final c = _pending.remove(msg.id);
        if (msg.error != null) {
          c?.completeError(Exception(msg.error));
        } else {
          c?.complete(msg.result);
        }
      }
    });

    _isolate = await Isolate.spawn(_workerEntry, _receivePort!.sendPort);
    await ready.future;
  }

  /// Kills the background isolate and cleans up pending requests.
  void stop() {
    _isolate?.kill(priority: Isolate.immediate);
    _isolate = null;
    _receivePort?.close();
    _receivePort = null;
    _sendPort = null;
    for (final c in _pending.values) {
      c.completeError(Exception('BmcCryptoWorker stopped'));
    }
    _pending.clear();
  }

  Future<T> _dispatch<T>(_Op op, Object params) {
    assert(_sendPort != null, 'Worker not started — call start() first.');
    final id = _nextId++;
    final c = Completer<Object?>();
    _pending[id] = c;
    _sendPort!.send(_Request(id, op, params));
    return c.future.then((v) => v as T);
  }

  // -------------------- Public API --------------------

  Future<Uint8List> signEphemeralPublicKey(
    Uint8List x25519PublicKeyEphemeral,
    Uint8List ed25519PrivateKey,
  ) =>
      _dispatch<Uint8List>(
          _Op.sign, _SignParams(x25519PublicKeyEphemeral, ed25519PrivateKey));

  Future<bool> verifyEphemeralPublicKey(
    Uint8List signature,
    Uint8List x25519PublicKeyEphemeralPeer,
    Uint8List ed25519PublicKeyPeer,
  ) =>
      _dispatch<bool>(
          _Op.verify,
          _VerifyParams(
              ed25519PublicKeyPeer, x25519PublicKeyEphemeralPeer, signature));

  Future<Uint8List> calculateSecret(
    Uint8List privateKey,
    Uint8List publicKey,
  ) =>
      _dispatch<Uint8List>(
          _Op.calcSecret, _CalcSecretParams(privateKey, publicKey));

  Future<Uint8List> deriveSessionKey(
    Uint8List secretShared,
    Uint8List ephemeralPk,
    Uint8List peerPk,
  ) =>
      _dispatch<Uint8List>(
          _Op.deriveSession,
          _DeriveSessionParams(secretShared, ephemeralPk, peerPk));

  Future<DeriveMessageKeyResult> deriveMessageKey(
    Uint8List chainKey,
    Uint8List salt,
  ) =>
      _dispatch<DeriveMessageKeyResult>(
          _Op.deriveMessage, _DeriveMessageParams(chainKey, salt));

  Future<Uint8List> encryptAEAD(
    Uint8List message,
    Uint8List aad,
    Uint8List messageKey,
    Uint8List nonce,
  ) =>
      _dispatch<Uint8List>(
          _Op.encrypt, _CipherParams(message, aad, messageKey, nonce));

  Future<Uint8List> decryptAEAD(
    Uint8List ciphertext,
    Uint8List aad,
    Uint8List messageKey,
    Uint8List nonce,
  ) =>
      _dispatch<Uint8List>(
          _Op.decrypt, _CipherParams(ciphertext, aad, messageKey, nonce));

  Future<KeypairResult> generateEd25519KeypairAsync() =>
      _dispatch<KeypairResult>(_Op.genEd25519, Object());

  Future<KeypairResult> generateX25519KeypairAsync() =>
      _dispatch<KeypairResult>(_Op.genX25519, Object());

  Future<KeypairResult> convertEd25519ToX25519Async(
    Uint8List ed25519PublicKey,
    Uint8List ed25519PrivateKey,
  ) =>
      _dispatch<KeypairResult>(
          _Op.convertEd25519ToX25519,
          _ConvertKeyParams(ed25519PublicKey, ed25519PrivateKey));
}

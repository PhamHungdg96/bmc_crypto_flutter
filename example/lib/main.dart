import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;
import 'package:bmc_cryptographic_flutter/bmc_protocol.dart' as bmcprotocol;
import 'package:bmc_cryptographic_flutter/bmc_crypt_file.dart';

final crypto = libcrypt.BmcCrypto();

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'BMC Crypto Demo',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: DefaultTabController(
        length: 2,
        child: Scaffold(
          appBar: AppBar(
            title: const Text('BMC Crypto Demo'),
            bottom: const TabBar(
              tabs: [
                Tab(text: 'Protocol Tests'),
                Tab(text: 'File Encrypt'),
              ],
            ),
          ),
          body: const TabBarView(
            children: [
              _ProtocolTestPage(),
              _FileEncryptPage(),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Tab 1: Protocol Tests (giữ nguyên logic cũ)
// ---------------------------------------------------------------------------

class _ProtocolTestPage extends StatefulWidget {
  const _ProtocolTestPage();

  @override
  State<_ProtocolTestPage> createState() => _ProtocolTestPageState();
}

class _ProtocolTestPageState extends State<_ProtocolTestPage> {
  String _result = '';
  bool _isLoading = false;

  void _runTest() async {
    setState(() {
      _isLoading = true;
      _result = 'Running tests...\n';
    });

    await _testSyncFunctions();
    await _testAsyncFunctions();
    await _testGenerateKeyAsyncFunctions();

    setState(() => _isLoading = false);
  }

  Future<void> _testSyncFunctions() async {
    setState(() => _result += '\n=== TESTING SYNC FUNCTIONS ===\n');
    final start = DateTime.now();
    funcAliceBobTest();
    final end = DateTime.now();
    setState(() => _result +=
        'Sync functions completed in: ${end.difference(start).inMilliseconds}ms\n');
  }

  Future<void> _testAsyncFunctions() async {
    setState(() => _result += '\n=== TESTING ASYNC (ISOLATE) FUNCTIONS ===\n');
    final start = DateTime.now();
    await funcAliceBobTestAsync();
    final end = DateTime.now();
    setState(() => _result +=
        'Async functions completed in: ${end.difference(start).inMilliseconds}ms\n');
  }

  Future<void> _testGenerateKeyAsyncFunctions() async {
    setState(() =>
        _result += '\n=== TESTING GENERATE KEY ASYNC (ISOLATE) FUNCTIONS ===\n');
    final start = DateTime.now();
    await funcGenKeyTestAsync();
    final end = DateTime.now();
    setState(() => _result +=
        'Async gen key functions completed in: ${end.difference(start).inMilliseconds}ms\n');
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ElevatedButton(
            onPressed: _isLoading ? null : _runTest,
            child: _isLoading
                ? const CircularProgressIndicator(color: Colors.white)
                : const Text('Run Crypto Tests'),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: SingleChildScrollView(
              child: Text(_result,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Tab 2: File Encrypt / Decrypt / Change Password
// ---------------------------------------------------------------------------

class _FileEncryptPage extends StatefulWidget {
  const _FileEncryptPage();

  @override
  State<_FileEncryptPage> createState() => _FileEncryptPageState();
}

class _FileEncryptPageState extends State<_FileEncryptPage> {
  final _encryptor = BmcFileEncryptor();
  final _keyHelper = BmcWrapKeyHelper();

  String  _log          = '';
  bool    _busy         = false;
  String? _selectedPath;
  String? _encryptedPath;

  final _pwCtrl    = TextEditingController();
  final _newPwCtrl = TextEditingController();

  void _appendLog(String msg) =>
      setState(() => _log += '${DateTime.now().toIso8601String().substring(11, 23)}  $msg\n');

  // ── KDF ──────────────────────────────────────────────────────────────────

  (Uint8List, Uint8List) _deriveNewKey(String password) {
    final salt    = _keyHelper.generateSalt();
    final wrapKey = _keyHelper.deriveWrapKey(password, salt);
    return (wrapKey, salt);
  }

  Uint8List _rederiveKey(String password, Uint8List salt) =>
      _keyHelper.deriveWrapKey(password, salt);

  // ── Chọn file ─────────────────────────────────────────────────────────────

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles();
    if (result == null || result.files.single.path == null) return;
    setState(() {
      _selectedPath  = result.files.single.path!;
      _encryptedPath = null;
    });
    _appendLog('Đã chọn: $_selectedPath');
  }

  // ── Mã hoá ───────────────────────────────────────────────────────────────
  //
  // Cấu trúc file .bmc đầu ra:
  //   [32B: salt][4B BE: headerLen][76B header][body chunks mã hoá]

  Future<void> _encryptFile() async {
    if (_selectedPath == null) { _appendLog('⚠ Chưa chọn file'); return; }
    final password = _pwCtrl.text.trim();
    if (password.isEmpty) { _appendLog('⚠ Chưa nhập mật khẩu'); return; }

    setState(() => _busy = true);
    try {
      _appendLog('Bắt đầu mã hoá...');
      final sw = Stopwatch()..start();

      final (wrapKey, salt) = _deriveNewKey(password);
      _appendLog('wrapKey: ${wrapKey}');
      final tmp = await _encryptor.encryptFile(_selectedPath!, wrapKey);

      final outPath = '${tmp.path}.bmc';
      final raf     = await File(outPath).open(mode: FileMode.writeOnly);
      await raf.writeFrom(salt);
      _appendLog('salt: ${salt}');
      await raf.writeFrom(await tmp.readAll());
      await raf.close();
      await tmp.delete();

      sw.stop();
      setState(() => _encryptedPath = outPath);
      _appendLog('✅ Mã hoá xong (${sw.elapsedMilliseconds}ms)');
      _appendLog('   ↳ $outPath');
    } catch (e) {
      _appendLog('❌ Lỗi mã hoá: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  // ── Giải mã ──────────────────────────────────────────────────────────────

  Future<void> _decryptFile() async {
    final src = _encryptedPath ?? _selectedPath;
    if (src == null) { _appendLog('⚠ Chưa có file mã hoá'); return; }
    final password = _pwCtrl.text.trim();
    if (password.isEmpty) { _appendLog('⚠ Chưa nhập mật khẩu'); return; }

    setState(() => _busy = true);
    try {
      _appendLog('Bắt đầu giải mã file ${src}...');
      final sw = Stopwatch()..start();

      final raw     = await File(src).readAsBytes();
      final salt    = raw.sublist(0, 32);
      final payload = raw.sublist(32);
      _appendLog('salt: ${salt}');

      // Ghi payload vào file tạm để giải mã
      final tmpIn = await File(p.join(Directory.systemTemp.path,"_bmc_dec_in.tmp")).open(mode: FileMode.writeOnly);
      await tmpIn.writeFrom(payload);
      await tmpIn.close();
      
      _appendLog('file: ${tmpIn.path} with ${payload.length} bytes');
      final wrapKey = _rederiveKey(password, salt);
      _appendLog('wrapKey: ${wrapKey}');
      final tmp     = await _encryptor.decryptFile(tmpIn.path, wrapKey);

      // final decPath = '${tmp.path}.dec';
      // await File(tmp.path).copy(decPath);
      // await tmp.delete();
      // if (await tmpIn.exists()) await tmpIn.delete();

      sw.stop();
      _appendLog('✅ Giải mã xong (${sw.elapsedMilliseconds}ms)');
      // _appendLog('   ↳ $decPath');
    } catch (e) {
      _appendLog('❌ Lỗi giải mã: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  // ── Đổi mật khẩu ─────────────────────────────────────────────────────────

  Future<void> _changePassword() async {
    final src = _encryptedPath ?? _selectedPath;
    if (src == null) { _appendLog('⚠ Chưa có file mã hoá'); return; }
    final oldPw = _pwCtrl.text.trim();
    final newPw = _newPwCtrl.text.trim();
    if (oldPw.isEmpty || newPw.isEmpty) {
      _appendLog('⚠ Nhập đủ mật khẩu cũ và mới');
      return;
    }

    setState(() => _busy = true);
    try {
      _appendLog('Đang đổi mật khẩu...');
      final sw = Stopwatch()..start();

      final raw     = await File(src).readAsBytes();
      final oldSalt = raw.sublist(0, 32);
      final payload = raw.sublist(32);

      final tmpIn = File('${Directory.systemTemp.path}/_bmc_rk_in.tmp');
      await tmpIn.writeAsBytes(payload, flush: true,);

      final oldWrapKey         = _rederiveKey(oldPw, oldSalt);
      final (newWrapKey, newSalt) = _deriveNewKey(newPw);

      // Re-wrap: chỉ đổi header, body giữ nguyên
      final tmp = await _encryptor.changePassword(tmpIn.path, oldWrapKey, newWrapKey);

      // Ghi đè file gốc với salt mới
      final raf = await File(src).open(mode: FileMode.writeOnly);
      await raf.writeFrom(newSalt);
      await raf.writeFrom(await tmp.readAll());
      await raf.close();
      await tmp.delete();
      if (await tmpIn.exists()) await tmpIn.delete();

      sw.stop();
      _appendLog('✅ Đổi mật khẩu xong (${sw.elapsedMilliseconds}ms)');
    } catch (e) {
      _appendLog('❌ Lỗi đổi mật khẩu: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  // ── Build ─────────────────────────────────────────────────────────────────

  @override
  void dispose() {
    _pwCtrl.dispose();
    _newPwCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ElevatedButton.icon(
            onPressed: _busy ? null : _pickFile,
            icon: const Icon(Icons.folder_open),
            label: Text(_selectedPath != null
                ? 'File: ${_selectedPath!.split(Platform.pathSeparator).last}'
                : 'Chọn file'),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _pwCtrl,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Mật khẩu',
              border: OutlineInputBorder(),
              isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _newPwCtrl,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Mật khẩu mới (chỉ dùng khi đổi mật khẩu)',
              border: OutlineInputBorder(),
              isDense: true,
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _busy ? null : _encryptFile,
                  icon: const Icon(Icons.lock),
                  label: const Text('Mã hoá'),
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.green),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _busy ? null : _decryptFile,
                  icon: const Icon(Icons.lock_open),
                  label: const Text('Giải mã'),
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.blue),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _busy ? null : _changePassword,
                  icon: const Icon(Icons.key),
                  label: const Text('Đổi pass'),
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.orange),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (_busy) const LinearProgressIndicator(),
          const SizedBox(height: 8),
          Expanded(
            child: Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.black87,
                borderRadius: BorderRadius.circular(6),
              ),
              child: SingleChildScrollView(
                child: SelectableText(
                  _log.isEmpty ? 'Log sẽ hiển thị ở đây...' : _log,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: Colors.greenAccent),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}



Future<void> funcGenKeyTestAsync() async {
  print('\n--- ASYNC (ISOLATE) GenKey Test ---');
  
  int testCount = 0;
  int successCount = 0;
  int errorCount = 0;
  
  while (testCount < 10) {
    testCount++;
    print('\n=== Test iteration $testCount ===');
    
    try {
      // Create contexts for long-term keys
      final aliceCtx = bmcprotocol.BmcProtocolContext(crypto: crypto);
      final bobCtx = bmcprotocol.BmcProtocolContext(crypto: crypto);

      final aliceKeypair = await crypto.generateEd25519KeypairAsync();
      final bobKeypair = await crypto.generateEd25519KeypairAsync();
      
      aliceCtx.ed25519PublicKey.setAll(0, aliceKeypair.publicKey);
      aliceCtx.ed25519PrivateKey.setAll(0, aliceKeypair.privateKey);
      bobCtx.ed25519PublicKey.setAll(0, bobKeypair.publicKey);
      bobCtx.ed25519PrivateKey.setAll(0, bobKeypair.privateKey);
      
      // Convert Ed25519 to X25519 using async functions
      final aliceX25519 = await crypto.convertEd25519ToX25519Async(aliceCtx.ed25519PublicKey, aliceCtx.ed25519PrivateKey);
      final bobX25519 = await crypto.convertEd25519ToX25519Async(bobCtx.ed25519PublicKey, bobCtx.ed25519PrivateKey);
      
      aliceCtx.x25519PublicKey.setAll(0, aliceX25519.publicKey);
      aliceCtx.x25519PrivateKey.setAll(0, aliceX25519.privateKey);
      bobCtx.x25519PublicKey.setAll(0, bobX25519.publicKey);
      bobCtx.x25519PrivateKey.setAll(0, bobX25519.privateKey);
      
      // Create sessions for testing
      final alice = aliceCtx.createSession('test_session_$testCount');
      final bob = bobCtx.createSession('test_session_$testCount');
      
      // Set peer keys
      alice.setPeerKey(bobCtx.ed25519PublicKey, bobCtx.x25519PublicKey);
      bob.setPeerKey(aliceCtx.ed25519PublicKey, aliceCtx.x25519PublicKey);
      
      // Generate ephemeral keypair for Alice
      final aliceEphemeral = await crypto.generateX25519KeypairAsync();
      alice.x25519PublicKeyEphemeral.setAll(0, aliceEphemeral.publicKey);
      alice.x25519PrivateKeyEphemeral.setAll(0, aliceEphemeral.privateKey);
      
      // Test random generation
      final randomBytes = crypto.rand(32);
      print_hex("Random bytes", randomBytes);
      
      //print_hex("alice ephemeral public key (async)", alice.x25519PublicKeyEphemeral);
      
      successCount++;
      print('✅ Test $testCount completed successfully');
      
    } catch (e, stackTrace) {
      errorCount++;
      print('❌ Error in test $testCount: $e');
      print('Stack trace: $stackTrace');
    }
  }
  
  print('\n=== Test Summary ===');
  print('Total tests: $testCount');
  print('Successful: $successCount');
  print('Errors: $errorCount');
  print('Success rate: ${(successCount / testCount * 100).toStringAsFixed(1)}%');
}

// Async version of Alice-Bob test using Isolate functions
Future<void> funcAliceBobTestAsync() async {
  print('\n--- ASYNC (ISOLATE) Alice-Bob Test ---');

  final aliceCtx = bmcprotocol.BmcProtocolContext(crypto: crypto);
  final bobCtx = bmcprotocol.BmcProtocolContext(crypto: crypto);

  final aliceKeypair = await crypto.generateEd25519KeypairAsync();
  final bobKeypair = await crypto.generateEd25519KeypairAsync();

  aliceCtx.ed25519PublicKey.setAll(0, aliceKeypair.publicKey);
  aliceCtx.ed25519PrivateKey.setAll(0, aliceKeypair.privateKey);
  bobCtx.ed25519PublicKey.setAll(0, bobKeypair.publicKey);
  bobCtx.ed25519PrivateKey.setAll(0, bobKeypair.privateKey);

  final aliceX25519 = await crypto.convertEd25519ToX25519Async(
    aliceCtx.ed25519PublicKey,
    aliceCtx.ed25519PrivateKey,
  );
  final bobX25519 = await crypto.convertEd25519ToX25519Async(
    bobCtx.ed25519PublicKey,
    bobCtx.ed25519PrivateKey,
  );

  aliceCtx.x25519PublicKey.setAll(0, aliceX25519.publicKey);
  aliceCtx.x25519PrivateKey.setAll(0, aliceX25519.privateKey);
  bobCtx.x25519PublicKey.setAll(0, bobX25519.publicKey);
  bobCtx.x25519PrivateKey.setAll(0, bobX25519.privateKey);

  print_hex("alice ed25519 public key (async)", aliceCtx.ed25519PublicKey);
  print_hex("bob ed25519 public key (async)", bobCtx.ed25519PublicKey);

  final alice = aliceCtx.createSession('alice_session_to_bob');
  final bob = bobCtx.createSession('bob_session_to_alice');

  alice.setPeerKey(bobCtx.ed25519PublicKey, bobCtx.x25519PublicKey);
  bob.setPeerKey(aliceCtx.ed25519PublicKey, aliceCtx.x25519PublicKey);

  final aliceEphemeral = await crypto.generateX25519KeypairAsync();
  alice.x25519PublicKeyEphemeral.setAll(0, aliceEphemeral.publicKey);
  alice.x25519PrivateKeyEphemeral.setAll(0, aliceEphemeral.privateKey);

  print_hex("alice ephemeral public key (async)", alice.x25519PublicKeyEphemeral);

  final signature = await alice.signEphemeralPublicKeyAsync();
  print_hex("alice signature (async)", signature);

  await alice.calculateSelfSecretSharedAsync();
  print_hex("alice secret shared (async)", alice.secretShared);

  await alice.deriveSessionSelfKeyAsync();
  print_hex("alice session key (async)", alice.messageCtx.chainKey);

  final Uint8List aad = crypto.rand(32);

  await alice.deriveMessageKeyAsync(aad);
  print_hex("alice message key (async)", alice.messageCtx.messageKey);

  final firstMessage =
      Uint8List.fromList(utf8.encode('Hello, Bob! (from Isolate)'));
  final firstCipherText = await alice.encryptMessageAsync(firstMessage, aad);
  print_hex("alice first cipher text (async)", firstCipherText);

  final verifyResult = await bob.verifyEphemeralPublicKeyAsync(
    signature,
    alice.x25519PublicKeyEphemeral,
  );
  if (!verifyResult) {
    print("Bob verify ephemeral public key failed");
    return;
  }
  print("✅ Bob verify ephemeral public key success (async)");

  await bob.calculatePeerSecretSharedAsync(alice.x25519PublicKeyEphemeral);
  print_hex("bob secret shared (async)", bob.secretShared);

  await bob.deriveSessionPeerKeyAsync(alice.x25519PublicKeyEphemeral);
  print_hex("bob session key (async)", bob.messageCtx.chainKey);

  await bob.deriveMessageKeyAsync(aad);
  print_hex("bob message key (async)", bob.messageCtx.messageKey);

  final firstPlainText = await bob.decryptMessageAsync(firstCipherText, aad);
  print_hex("bob first plain text (async)", firstPlainText);
  print("✅ bob first plain text (async): ${utf8.decode(firstPlainText)}");
}

void print_hex(String title, Uint8List data) {
  final buffer = StringBuffer();
  for (int i = 0; i < data.length; i++) {
    buffer.write(data[i].toRadixString(16).padLeft(2, '0'));
  }
  print("$title: ${buffer.toString()}");
}

void funcAliceBobTest(){
  // Create contexts for Alice and Bob (hold long-term keys)
  final aliceCtx = bmcprotocol.BmcProtocolContext(crypto: crypto);
  final bobCtx = bmcprotocol.BmcProtocolContext(crypto: crypto);
  
  // Initialize long-term keys
  aliceCtx.initLongTermKey();
  bobCtx.initLongTermKey();
  
  // Print long-term keys
  print_hex("alice ed25519 public key", aliceCtx.ed25519PublicKey);
  print_hex("bob ed25519 public key", bobCtx.ed25519PublicKey);
  
  // Create a session for Alice-Bob communication
  final alice = aliceCtx.createSession('alice_to_bob');
  final bob = bobCtx.createSession('bob_from_alice');
  
  // Set peer keys
  alice.setPeerKey(bobCtx.ed25519PublicKey, bobCtx.x25519PublicKey);
  bob.setPeerKey(aliceCtx.ed25519PublicKey, aliceCtx.x25519PublicKey);

  // Alice generates ephemeral key
  if(alice.generateEphemeralKey() != 0){
    print("Alice generate ephemeral key failed");
    return;
  }
  
  // Sign ephemeral public key
  final signature = alice.signEphemeralPublicKey();
  print_hex("alice signature", signature);
  
  // Calculate self secret shared
  alice.caculateSelfSecretShared();
  print_hex("alice secret shared", alice.secretShared);
  
  alice.deriveSessionSelfKey();
  print_hex("alice session key", alice.messageCtx.chainKey);

  final Uint8List aad = crypto.rand(32);

  alice.deriveMessageKey(aad);
  print_hex("alice message key", alice.messageCtx.messageKey);
  
  // Encrypt message
  final firstMessage = Uint8List.fromList(utf8.encode('Hello, Bob!'));
  final firstCipherText = alice.encryptMessage(firstMessage, aad);
  print_hex("alice first cipher text", firstCipherText);

  // Bob verify ephemeral public key
  if(bob.verifyEphemeralPublicKey(signature, alice.x25519PublicKeyEphemeral) != 0){
    print("Bob verify ephemeral public key failed");
    return;
  }
  print("Bob verify ephemeral public key success");
  
  // Calculate peer secret shared
  bob.caculatePeerSecretShared(alice.x25519PublicKeyEphemeral);
  print_hex("bob secret shared", bob.secretShared);
  
  bob.deriveSessionPeerKey(alice.x25519PublicKeyEphemeral);
  print_hex("bob session key", bob.messageCtx.chainKey);
  
  bob.deriveMessageKey(aad);
  print_hex("bob message key", bob.messageCtx.messageKey);
  
  // Decrypt message
  final firstPlainText = bob.decryptMessage(firstCipherText, aad);
  print_hex("bob first plain text", firstPlainText);
  print("bob first plain text: ${utf8.decode(firstPlainText)}");
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
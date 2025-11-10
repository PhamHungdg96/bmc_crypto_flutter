import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:flutter/material.dart';

import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart' as libcrypt;
import 'package:bmc_cryptographic_flutter/bmc_protocol.dart' as bmcprotocol;

final crypto = libcrypt.BmcCrypto();

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'BMC Crypto Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: MyHomePage(title: 'BMC Crypto with Isolate Demo'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  MyHomePage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String _result = '';
  bool _isLoading = false;

  void _runTest() async {
    setState(() {
      _isLoading = true;
      _result = 'Running tests...\n';
    });

    // Test sync functions
    await _testSyncFunctions();
    
    // Test async (isolate) functions
    await _testAsyncFunctions();

    setState(() {
      _isLoading = false;
    });
  }

  Future<void> _testSyncFunctions() async {
    setState(() {
      _result += '\n=== TESTING SYNC FUNCTIONS ===\n';
    });
    
    final start = DateTime.now();
    funcAliceBobTest();
    final end = DateTime.now();
    
    setState(() {
      _result += 'Sync functions completed in: ${end.difference(start).inMilliseconds}ms\n';
    });
  }

  Future<void> _testAsyncFunctions() async {
    setState(() {
      _result += '\n=== TESTING ASYNC (ISOLATE) FUNCTIONS ===\n';
    });
    
    final start = DateTime.now();
    await funcAliceBobTestAsync();
    final end = DateTime.now();
    
    setState(() {
      _result += 'Async functions completed in: ${end.difference(start).inMilliseconds}ms\n';
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ElevatedButton(
              onPressed: _isLoading ? null : _runTest,
              child: _isLoading 
                ? CircularProgressIndicator(color: Colors.white)
                : Text('Run Crypto Tests'),
            ),
            SizedBox(height: 16),
            Expanded(
              child: SingleChildScrollView(
                child: Text(
                  _result,
                  style: TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// Async version of Alice-Bob test using Isolate functions
Future<void> funcAliceBobTestAsync() async {
  print('\n--- ASYNC (ISOLATE) Alice-Bob Test ---');
  
  // Khai báo context cho Alice và Bob để lưu khóa dài hạn
  final alice = bmcprotocol.BmcProtocolContext(crypto: crypto);
  final bob = bmcprotocol.BmcProtocolContext(crypto: crypto);
  
  // Generate keypairs using async functions
  final aliceKeypair = await crypto.generateEd25519KeypairAsync();
  final bobKeypair = await crypto.generateEd25519KeypairAsync();
  
  alice.ed25519PublicKey.setAll(0, aliceKeypair.publicKey);
  alice.ed25519PrivateKey.setAll(0, aliceKeypair.privateKey);
  bob.ed25519PublicKey.setAll(0, bobKeypair.publicKey);
  bob.ed25519PrivateKey.setAll(0, bobKeypair.privateKey);
  
  // Convert Ed25519 to X25519 using async functions
  final aliceX25519 = await crypto.convertEd25519ToX25519Async(alice.ed25519PublicKey, alice.ed25519PrivateKey);
  final bobX25519 = await crypto.convertEd25519ToX25519Async(bob.ed25519PublicKey, bob.ed25519PrivateKey);
  
  alice.x25519PublicKey.setAll(0, aliceX25519.publicKey);
  alice.x25519PrivateKey.setAll(0, aliceX25519.privateKey);
  bob.x25519PublicKey.setAll(0, bobX25519.publicKey);
  bob.x25519PrivateKey.setAll(0, bobX25519.privateKey);
  
  print_hex("alice ed25519 public key (async)", alice.ed25519PublicKey);
  print_hex("bob ed25519 public key (async)", bob.ed25519PublicKey);
  
  // Set peer keys
  alice.setPeerKey(bob.ed25519PublicKey, bob.x25519PublicKey);
  bob.setPeerKey(alice.ed25519PublicKey, alice.x25519PublicKey);
  
  // Generate ephemeral keypair for Alice
  final aliceEphemeral = await crypto.generateX25519KeypairAsync();
  alice.x25519PublicKeyEphemeral.setAll(0, aliceEphemeral.publicKey);
  alice.x25519PrivateKeyEphemeral.setAll(0, aliceEphemeral.privateKey);
  
  print_hex("alice ephemeral public key (async)", alice.x25519PublicKeyEphemeral);
  
  // Sign ephemeral public key using async function
  final signature = await alice.signEphemeralPublicKeyAsync();
  print_hex("alice signature (async)", signature);
  
  // Calculate secret shared using async function
  final aliceSecret = await alice.calculateSelfSecretSharedAsync();
  alice.secretShared.setAll(0, aliceSecret);
  print_hex("alice secret shared (async)", alice.secretShared);
  
  // Derive session key using async function
  final aliceSessionKey = await alice.deriveSessionSelfKeyAsync();
  alice.messageCtx.chainKey.setAll(0, aliceSessionKey);
  print_hex("alice session key (async)", alice.messageCtx.chainKey);

  final Uint8List aad = await crypto.rand(32);
  
  // Derive message key using async function
  final aliceMessageKeyResult = await alice.deriveMessageKeyAsync(aad);
  alice.messageCtx.chainKey.setAll(0, aliceMessageKeyResult.chainKey);
  alice.messageCtx.messageKey.setAll(0, aliceMessageKeyResult.messageKey);
  alice.messageCtx.hmacKey.setAll(0, aliceMessageKeyResult.hmacKey);
  alice.messageCtx.nonce.setAll(0, aliceMessageKeyResult.nonce);
  print_hex("alice message key (async)", alice.messageCtx.messageKey);
  
  // Encrypt message using async function
  final firstMessage = Uint8List.fromList(utf8.encode('Hello, Bob! (from Isolate)'));
  final firstCipherText = await alice.encryptMessageAsync(firstMessage, aad);
  print_hex("alice first cipher text (async)", firstCipherText);
  
  // Bob verify ephemeral public key using async function
  final verifyResult = await bob.verifyEphemeralPublicKeyAsync(signature, alice.x25519PublicKeyEphemeral);
  if (!verifyResult) {
    print("Bob verify ephemeral public key failed");
    return;
  }
  print("✅ Bob verify ephemeral public key success (async)");
  
  // Calculate peer secret shared using async function
  final bobSecret = await bob.calculatePeerSecretSharedAsync(alice.x25519PublicKeyEphemeral);
  bob.secretShared.setAll(0, bobSecret);
  print_hex("bob secret shared (async)", bob.secretShared);
  
  // Derive session key using async function
  final bobSessionKey = await bob.deriveSessionPeerKeyAsync(alice.x25519PublicKeyEphemeral);
  bob.messageCtx.chainKey.setAll(0, bobSessionKey);
  print_hex("bob session key (async)", bob.messageCtx.chainKey);
  
  // Derive message key using async function
  final bobMessageKeyResult = await bob.deriveMessageKeyAsync(aad);
  bob.messageCtx.chainKey.setAll(0, bobMessageKeyResult.chainKey);
  bob.messageCtx.messageKey.setAll(0, bobMessageKeyResult.messageKey);
  bob.messageCtx.hmacKey.setAll(0, bobMessageKeyResult.hmacKey);
  bob.messageCtx.nonce.setAll(0, bobMessageKeyResult.nonce);
  print_hex("bob message key (async)", bob.messageCtx.messageKey);
  
  // Decrypt message using async function
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
  // Khai báo context cho Alice và Bob để lưu khóa dài hạn
  final alice = bmcprotocol.BmcProtocolContext(crypto: crypto);
  final bob = bmcprotocol.BmcProtocolContext(crypto: crypto);
  //init long term key and publist public key to server
  alice.initLongTermKey();
  bob.initLongTermKey();
  //print long term key
  print_hex("alice ed25519 public key", alice.ed25519PublicKey);
  print_hex("alice ed25519 private key", alice.ed25519PrivateKey);
  print_hex("alice x25519 public key", alice.x25519PublicKey);
  print_hex("alice x25519 private key", alice.x25519PrivateKey);
  print_hex("bob ed25519 public key", bob.ed25519PublicKey);
  print_hex("bob ed25519 private key", bob.ed25519PrivateKey);
  print_hex("bob x25519 public key", bob.x25519PublicKey);
  print_hex("bob x25519 private key", bob.x25519PrivateKey);
  //set peer key from server
  alice.setPeerKey(bob.ed25519PublicKey, bob.x25519PublicKey);
  bob.setPeerKey(alice.ed25519PublicKey, alice.x25519PublicKey);

  //Alice send to Bob
  //generate ephemeral key
  if(alice.generateEphemeralKey() != 0){
    print("Alice generate ephemeral key failed");
    return;
  }
  //print ephemeral key
  print_hex("alice ephemeral public key", alice.x25519PublicKeyEphemeral);
  print_hex("alice ephemeral private key", alice.x25519PrivateKeyEphemeral);
  //sign ephemeral public key
  final signature = alice.signEphemeralPublicKey();
  print_hex("alice signature", signature);
  //caculate self secret shared
  alice.caculateSelfSecretShared();
  print_hex("alice secret shared", alice.secretShared);
  alice.deriveSessionSelfKey();
  print_hex("alice session key", alice.messageCtx.chainKey);

  final Uint8List aad = crypto.rand(32);

  alice.deriveMessageKey(aad);
  print_hex("alice message key", alice.messageCtx.messageKey);
  //Alice send to Bob (first message include ephemeral public key;signature;first cipher text;hmacsha256 of first cipher text)
  final firstMessage = Uint8List.fromList(utf8.encode('Hello, Bob!'));
  final firstCipherText = alice.encryptMessage(firstMessage, aad);
  print_hex("alice first cipher text", firstCipherText);

  //Bob verify ephemeral public key
  if(bob.verifyEphemeralPublicKey(signature, alice.x25519PublicKeyEphemeral) != 0){
    print("Bob verify ephemeral public key failed");
    return;
  }
  print("Bob verify ephemeral public key success");
  //caculate peer secret shared
  bob.caculatePeerSecretShared(alice.x25519PublicKeyEphemeral);
  print_hex("bob secret shared", bob.secretShared);
  //derive session key
  
  bob.deriveSessionPeerKey(alice.x25519PublicKeyEphemeral);
  print_hex("bob session key", bob.messageCtx.chainKey);
  //derive message key
  
  bob.deriveMessageKey(aad);
  print_hex("bob message key", bob.messageCtx.messageKey);
  //decrypt first message
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
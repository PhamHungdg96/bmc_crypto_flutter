import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'bmc_cryptographic_flutter_platform_interface.dart';

/// An implementation of [BmcCryptographicFlutterPlatform] that uses method channels.
class MethodChannelBmcCryptographicFlutter extends BmcCryptographicFlutterPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('bmc_cryptographic_flutter');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}

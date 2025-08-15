import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'bmc_cryptographic_flutter_method_channel.dart';

abstract class BmcCryptographicFlutterPlatform extends PlatformInterface {
  /// Constructs a BmcCryptographicFlutterPlatform.
  BmcCryptographicFlutterPlatform() : super(token: _token);

  static final Object _token = Object();

  static BmcCryptographicFlutterPlatform _instance = MethodChannelBmcCryptographicFlutter();

  /// The default instance of [BmcCryptographicFlutterPlatform] to use.
  ///
  /// Defaults to [MethodChannelBmcCryptographicFlutter].
  static BmcCryptographicFlutterPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [BmcCryptographicFlutterPlatform] when
  /// they register themselves.
  static set instance(BmcCryptographicFlutterPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}

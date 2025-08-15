#ifndef FLUTTER_PLUGIN_BMC_CRYPTOGRAPHIC_FLUTTER_PLUGIN_H_
#define FLUTTER_PLUGIN_BMC_CRYPTOGRAPHIC_FLUTTER_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace bmc_cryptographic_flutter {

class BmcCryptographicFlutterPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  BmcCryptographicFlutterPlugin();

  virtual ~BmcCryptographicFlutterPlugin();

  // Disallow copy and assign.
  BmcCryptographicFlutterPlugin(const BmcCryptographicFlutterPlugin&) = delete;
  BmcCryptographicFlutterPlugin& operator=(const BmcCryptographicFlutterPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace bmc_cryptographic_flutter

#endif  // FLUTTER_PLUGIN_BMC_CRYPTOGRAPHIC_FLUTTER_PLUGIN_H_

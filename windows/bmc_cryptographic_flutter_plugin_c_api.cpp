#include "include/bmc_cryptographic_flutter/bmc_cryptographic_flutter_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "bmc_cryptographic_flutter_plugin.h"

void BmcCryptographicFlutterPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  bmc_cryptographic_flutter::BmcCryptographicFlutterPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}

# NimBLE(bt)を要求する。CONFIG_SM_ENABLE_BLE のときだけ ble.cpp が NimBLE を使い、
# 無効時(例: ESP32-S3、CONFIG_BT_ENABLED=n)は ble.cpp が #if で空 + bt はスタブに
# なるため、bt を常に要求しても S3 の BLE 無効ビルドは通る(コンポーネント要求は
# sdkconfig 展開前に評価されるため条件付き REQUIRES は使えない)。
idf_component_register(
    SRCS "main.cpp" "ble.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip driver esp_timer esp_system bt)

# C FFI シムのラッパは C++17。IDF v5.4 の既定 C++ 標準は C++17 だが明示する。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

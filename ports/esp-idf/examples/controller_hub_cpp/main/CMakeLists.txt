# `bt` は常時 REQUIRES(条件付き REQUIRES は sdkconfig 展開前に評価されるため不可。
# BLE 無効時は CONFIG_BT_ENABLED=n でスタブ化される。onoff_light_cpp と同方針)。
idf_component_register(
    SRCS "main.cpp" "ble_central.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip esp_timer esp_system esp_psram bt)

# C FFI シムヘッダの利用は C++17。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

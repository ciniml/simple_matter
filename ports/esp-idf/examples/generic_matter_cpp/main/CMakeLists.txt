# NimBLE(bt)・openthread は onoff_light_cpp と同じ方針で常時 REQUIRES する
# (条件付き REQUIRES は sdkconfig 展開前に評価されるため使えない。無効時は
#  ble.cpp / ot_thread.cpp が #if で空になり、コンポーネントはスタブになる)。
#
# generic_matter_cpp の追加要求:
#   console                      esp_console REPL(cfg-* コマンド、USB-Serial-JTAG)
#   esp_driver_usb_serial_jtag   REPL のバックエンド
#   driver                       gpio / ledc / i2c(HAL バインディング層)
#   esp_partition                smscript パーティションからのスクリプト読み出し(§9.3)
#   espressif__wasm-micro-runtime WAMR(ESP Registry の公式 component。idf_component.yml)
idf_component_register(
    SRCS "main.cpp" "ble.cpp" "ot_thread.cpp" "bindings.cpp" "cfg_store.cpp"
         "script_vm.cpp" "script_host.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip driver esp_timer
             esp_system bt openthread vfs console esp_driver_usb_serial_jtag
             esp_partition espressif__wasm-micro-runtime)

# C FFI シムのラッパは C++17。IDF v5.4 の既定 C++ 標準は C++17 だが明示する。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

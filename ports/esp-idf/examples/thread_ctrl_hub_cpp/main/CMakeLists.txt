# `openthread` / `vfs`(eventfd の提供元)は常時 REQUIRES(条件付き REQUIRES は
# sdkconfig 展開前に評価されるため不可。onoff_light_cpp と同方針)。
# `esp_wifi` は F8e(backbone)用に常時要求する(CONFIG_SM_THREAD_BR=n でも
# リンクは通る。P4 は radio 非搭載のため実体は esp_wifi_remote 側の話 = 足場のみ)。
idf_component_register(
    SRCS "main.cpp" "ot_hub.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_netif esp_event lwip esp_timer esp_system
             esp_psram driver openthread vfs)

# C FFI シムヘッダの利用は C++17。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

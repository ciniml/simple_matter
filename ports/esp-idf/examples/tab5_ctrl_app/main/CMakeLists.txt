# `openthread` / `vfs`(eventfd の提供元)は常時 REQUIRES(条件付き REQUIRES は
# sdkconfig 展開前に評価されるため不可。thread_ctrl_hub_cpp と同方針)。
# M5Unified/M5GFX と lvgl は managed component(main/idf_component.yml)。
idf_component_register(
    SRCS "main.cpp" "ot_hub.cpp" "app_state.cpp" "node_book.cpp" "ctrl_pump.cpp" "ui.cpp"
         "display_gfx.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_netif esp_event lwip esp_timer esp_system
             esp_psram driver openthread vfs)

# C FFI シムヘッダの利用と UI コードは C++17。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

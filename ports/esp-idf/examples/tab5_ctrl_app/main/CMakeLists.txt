# `openthread` / `vfs`(eventfd の提供元)は常時 REQUIRES(条件付き REQUIRES は
# sdkconfig 展開前に評価されるため不可。thread_ctrl_hub_cpp と同方針)。
# M5Unified/M5GFX と lvgl と esp_hosted / esp_wifi_remote は managed component
# (main/idf_component.yml)。
# `esp_wifi` は IDF 内蔵コンポーネントだが、P4 では中身が空で、
# esp_wifi_remote が `esp_wifi.h` の実体(injected ヘッダ)を差し込む。
# main が `#include "esp_wifi.h"` するには esp_wifi を REQUIRES に入れる必要がある。
idf_component_register(
    SRCS "main.cpp" "ot_hub.cpp" "app_state.cpp" "node_book.cpp" "ctrl_pump.cpp" "ui.cpp"
         "display_gfx.cpp" "wifi_sta.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_netif esp_event lwip esp_timer esp_system
             esp_psram driver openthread vfs esp_wifi)

# C FFI シムヘッダの利用と UI コードは C++17。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

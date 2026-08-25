# tab5_ctrl_app — M5Stack Tab5(ESP32-P4)+ Unit Gateway H2(ot_rcp over UART)の
# Thread ハブ兼 Matter コントローラに LVGL の GUI を載せたもの。
# docs/design/p4-thread-controller.md §9(T1)。
#
#   rm -f sdkconfig
#   idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults" set-target esp32p4
#   idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults" build
#
# (Rust 経路 (b): コンポーネントが cargo で riscv32imafc の .a をビルドする。
#  経路 (a) を使うなら -DSM_PREBUILT_A=<...>/riscv32imafc-unknown-none-elf/release/
#  libsimple_matter_cffi.a を set-target / build 両方に渡す。)
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tab5_ctrl_app)

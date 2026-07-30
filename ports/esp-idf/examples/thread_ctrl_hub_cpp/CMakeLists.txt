# thread_ctrl_hub_cpp — ESP32-P4(ホスト)+ ESP32-H2(ot_rcp over UART)の
# Thread ネットワーク主宰 兼 SRP サーバ 兼 Matter コントローラ。
# docs/design/p4-thread-controller.md(F8)。
#
#   idf.py set-target esp32p4
#   idf.py build
# (Rust 経路 (b): コンポーネントが cargo で riscv32imafc の .a をビルドする。
#  経路 (a) を使うなら -DSM_PREBUILT_A=<...>/riscv32imafc-unknown-none-elf/release/
#  libsimple_matter_cffi.a を set-target / build 両方に渡す。)
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(thread_ctrl_hub_cpp)

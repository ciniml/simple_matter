# controller_hub_cpp — simple-matter コントローラ C FFI(sm_ctrl_*)の ESP-IDF C++17
# 参照実装(ESP32-S3、供給メモリを PSRAM に確保。F7a、docs/design/c-ffi-shim.md §11)。
#
# ビルド検証用の最小 main: WiFi 接続 → PSRAM に供給メモリを確保 → sm_ctrl_init →
# 固定ノード 1 台を pairing → 30 秒毎に OnOff Toggle。実機フラッシュは対象外(ビルド green まで)。
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(controller_hub_cpp)

# onoff_light_cpp — simple-matter C FFI シムの ESP-IDF C++17 参照実装(ESP32-C6)。
# docs/design/c-ffi-shim.md §3。
cmake_minimum_required(VERSION 3.16)

# simple_matter コンポーネントは repo の ports/esp-idf/components/ に置く。
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(onoff_light_cpp)

# generic_matter_cpp — 設定駆動の汎用 Matter ファームウェア(Phase B = G1 + G2)。
# docs/design/generic-firmware.md §9.2。
cmake_minimum_required(VERSION 3.16)

# simple_matter コンポーネントは repo の ports/esp-idf/components/ に置く。
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(generic_matter_cpp)

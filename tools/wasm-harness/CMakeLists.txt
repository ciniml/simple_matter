# WASM スクリプトフックの Linux ホスト検証ハーネス(docs/design/generic-firmware.md §9.3)。
#
# ファームと**同一の script_vm.cpp** を Linux 用にビルドした WAMR へリンクし、モックの
# `sm` ホスト import(属性・GPIO・KVS をメモリ上でエミュレート)でフックのラウンドトリップを
# 検証する。WAMR のソースは fetch-wamr.sh が ESP Component Registry から取得したもの
# (ファームで使うのと同一版)を使う。
cmake_minimum_required(VERSION 3.14)
project(sm_wasm_harness C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT DEFINED WAMR_ROOT_DIR)
  set(WAMR_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/.wamr/wamr")
endif()
if(NOT EXISTS "${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake")
  message(FATAL_ERROR "WAMR sources not found at ${WAMR_ROOT_DIR}; run ./fetch-wamr.sh first")
endif()

# ファーム(sdkconfig.defaults の CONFIG_WAMR_*)と同じ機能セット:
# classic interpreter のみ + thread-manager(terminate で無限ループを打ち切るため)。
set(WAMR_BUILD_PLATFORM "linux")
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_FAST_INTERP 0)
set(WAMR_BUILD_AOT 0)
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_LIBC_BUILTIN 0)
set(WAMR_BUILD_LIBC_WASI 0)
set(WAMR_BUILD_LIB_PTHREAD 1)
set(WAMR_BUILD_MULTI_MODULE 0)
set(WAMR_BUILD_SIMD 0)
set(WAMR_BUILD_REF_TYPES 0)
include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

# ファーム側の共有ソース(ESP-IDF 非依存)。
set(FW_MAIN "${CMAKE_CURRENT_LIST_DIR}/../../ports/esp-idf/examples/generic_matter_cpp/main")

add_executable(sm_wasm_harness
  harness.cpp
  "${FW_MAIN}/script_vm.cpp"
  ${WAMR_RUNTIME_LIB_SOURCE})
target_include_directories(sm_wasm_harness PRIVATE "${FW_MAIN}")
target_link_libraries(sm_wasm_harness pthread m dl)

enable_testing()
add_test(NAME wasm_hooks
         COMMAND sm_wasm_harness "${CMAKE_CURRENT_LIST_DIR}/../../crates/sm-script-api/examples-wasm/momentary-toggle/target/wasm32-unknown-unknown/release/momentary_toggle.wasm")

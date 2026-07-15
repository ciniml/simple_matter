# ESP-IDF component that exposes the simple-matter device stack (C FFI shim,
# crates/simple-matter-cffi) to a C++17 ESP-IDF application.
#
# 二経路のリンクをサポートする(docs/design/c-ffi-shim.md §2 / §4 F2):
#   (a) SM_PREBUILT_A: ビルド済み .a のパスを渡す(Rust ツールチェーン不要)。
#         idf.py -DSM_PREBUILT_A=/abs/path/libsimple_matter_cffi.a build
#   (b) 未指定: cargo を custom command で叩いて .a を生成する
#         (ホストに rustup + riscv32imac-unknown-none-elf target が必要)。
#
# どちらも add_prebuilt_library で最終 ELF にリンクし、cbindgen ヘッダと
# C++17 RAII ラッパを INCLUDE_DIRS で公開する。

# repo ルートと crate の場所を解決する(このファイルは
# ports/esp-idf/components/simple_matter/ に居るので 4 つ上が repo ルート)。
get_filename_component(SM_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
set(SM_CRATE_DIR "${SM_REPO_ROOT}/crates/simple-matter-cffi")
set(SM_INCLUDE_DIR "${SM_CRATE_DIR}/include")

# IDF_TARGET から Rust ターゲットトリプルを対応付ける。
#   RISC-V(C6/C3) = riscv32imac-unknown-none-elf(stable rustc、経路 (a)/(b) 両対応)
#   Xtensa(S3)   = xtensa-esp32s3-none-elf(esp channel + -Zbuild-std=core が必須。
#                  経路 (b) の素朴な `cargo build` では通らないため S3 は経路 (a)
#                  = SM_PREBUILT_A のみサポート。F4a、docs/design/c-ffi-shim.md §4)
set(SM_TARGET_XTENSA FALSE)
if(IDF_TARGET STREQUAL "esp32c6" OR IDF_TARGET STREQUAL "esp32c3")
    set(SM_RUST_TARGET "riscv32imac-unknown-none-elf")
elseif(IDF_TARGET STREQUAL "esp32s3")
    set(SM_RUST_TARGET "xtensa-esp32s3-none-elf")
    set(SM_TARGET_XTENSA TRUE)
else()
    message(FATAL_ERROR
        "simple_matter: unsupported IDF_TARGET '${IDF_TARGET}'. "
        "Supported: esp32c6/esp32c3 (riscv32imac-unknown-none-elf), "
        "esp32s3 (xtensa-esp32s3-none-elf). See docs/design/c-ffi-shim.md §4.")
endif()

# ヘッダのみ公開するコンポーネント(実体は下で add_prebuilt_library でリンク)。
# stub ソースを 1 個持たせて COMPONENT_LIB を通常の STATIC library にする
# (INTERFACE library だと add_dependencies が使えず、経路 (b) の cargo 実行
#  順序を強制できないため)。
idf_component_register(
    SRCS "sm_component_stub.c"
    INCLUDE_DIRS "${SM_INCLUDE_DIR}")

if(DEFINED SM_PREBUILT_A AND NOT "${SM_PREBUILT_A}" STREQUAL "")
    # 経路 (a): ビルド済み .a。
    set(SM_STATICLIB "${SM_PREBUILT_A}")
    if(NOT EXISTS "${SM_STATICLIB}")
        message(FATAL_ERROR "simple_matter: SM_PREBUILT_A='${SM_STATICLIB}' does not exist")
    endif()
    message(STATUS "simple_matter: using prebuilt staticlib ${SM_STATICLIB}")
    add_prebuilt_library(simple_matter_rust "${SM_STATICLIB}")
    target_link_libraries(${COMPONENT_LIB} PUBLIC simple_matter_rust)
elseif(SM_TARGET_XTENSA)
    # S3/Xtensa は esp channel + `-Zbuild-std=core` が要るため、経路 (b) の素朴な
    # `cargo build` では通らない。SM_PREBUILT_A(経路 (a))を必須とする(F4a)。
    message(FATAL_ERROR
        "simple_matter: esp32s3 (Xtensa) requires a prebuilt staticlib. Build it with the "
        "esp toolchain:\n"
        "  . ~/export-esp.sh\n"
        "  cargo +esp build -p simple-matter-cffi --release "
        "--target xtensa-esp32s3-none-elf -Zbuild-std=core --features panic-abort\n"
        "then pass -DSM_PREBUILT_A=<repo>/target/xtensa-esp32s3-none-elf/release/"
        "libsimple_matter_cffi.a (also at set-target). See ports/esp-idf/components/simple_matter/README.md.")
else()
    # 経路 (b): cargo build で .a を生成する(RISC-V のみ)。
    set(SM_STATICLIB "${SM_REPO_ROOT}/target/${SM_RUST_TARGET}/release/libsimple_matter_cffi.a")
    find_program(CARGO_EXECUTABLE cargo)
    if(NOT CARGO_EXECUTABLE)
        message(FATAL_ERROR
            "simple_matter: neither SM_PREBUILT_A was given nor 'cargo' was found in PATH. "
            "Pass -DSM_PREBUILT_A=<abs path to libsimple_matter_cffi.a>, or install the Rust "
            "toolchain with the ${SM_RUST_TARGET} target.")
    endif()
    message(STATUS "simple_matter: building staticlib via cargo (${SM_RUST_TARGET})")
    add_custom_command(
        OUTPUT "${SM_STATICLIB}"
        COMMAND "${CARGO_EXECUTABLE}" build -p simple-matter-cffi --release
                --target "${SM_RUST_TARGET}" --features panic-abort
        WORKING_DIRECTORY "${SM_REPO_ROOT}"
        COMMENT "Building simple-matter-cffi staticlib (${SM_RUST_TARGET})"
        VERBATIM)
    add_custom_target(simple_matter_cargo DEPENDS "${SM_STATICLIB}")
    add_prebuilt_library(simple_matter_rust "${SM_STATICLIB}")
    # COMPONENT_LIB のリンク前に cargo を走らせる。
    add_dependencies(${COMPONENT_LIB} simple_matter_cargo)
    target_link_libraries(${COMPONENT_LIB} PUBLIC simple_matter_rust)
endif()

# Rust staticlib から「soft-float ABI」の .o を取り除く(ESP32-P4 = ilp32f 専用)。
#
# なぜ必要か(F8 の罠。docs/design/p4-thread-controller.md §6 R-P4-2):
#   rustup の riscv32imafc 向け `compiler_builtins` rlib には、cc でビルド済みの C 実装
#   (popcountsi2.o / bswapsi2.o / muldc3.o …)が **soft-float ABI(ilp32)** のまま
#   同梱されている。Rust が生成した .o は ilp32f なので普段は問題ないが、これらの
#   ビルトインが 1 つでも参照されると riscv ld が
#     "can't link soft-float modules with single-float modules"
#   で最終リンクを拒否する(参照が無ければ黙って通るため、症状が構成依存で出る)。
#   同名のルーチンは ESP-IDF が常にリンクする libgcc(ilp32f)が提供するため、
#   .a から soft-float の .o を削除すれば libgcc 側で解決される。
#
# 引数: IN_A(入力 .a)、OUT_A(出力 .a)、AR_TOOL(riscv32-esp-elf-ar)、
#       READELF_TOOL(riscv32-esp-elf-readelf)

if(NOT EXISTS "${IN_A}")
    message(FATAL_ERROR "strip_softfloat_objs: input archive '${IN_A}' not found")
endif()

get_filename_component(_out_dir "${OUT_A}" DIRECTORY)
set(_work "${_out_dir}/sm_softfloat_scan")
file(REMOVE_RECURSE "${_work}")
file(MAKE_DIRECTORY "${_work}")

configure_file("${IN_A}" "${OUT_A}" COPYONLY)

execute_process(COMMAND "${AR_TOOL}" t "${OUT_A}"
                OUTPUT_VARIABLE _members OUTPUT_STRIP_TRAILING_WHITESPACE
                COMMAND_ERROR_IS_FATAL ANY)
string(REPLACE "\n" ";" _members "${_members}")

set(_dropped "")
foreach(_m IN LISTS _members)
    if(_m STREQUAL "")
        continue()
    endif()
    execute_process(COMMAND "${AR_TOOL}" p "${OUT_A}" "${_m}"
                    OUTPUT_FILE "${_work}/obj.o" OUTPUT_QUIET ERROR_QUIET)
    execute_process(COMMAND "${READELF_TOOL}" -h "${_work}/obj.o"
                    OUTPUT_VARIABLE _hdr ERROR_QUIET)
    if(_hdr MATCHES "soft-float ABI")
        list(APPEND _dropped "${_m}")
    endif()
endforeach()

if(_dropped)
    list(LENGTH _dropped _n)
    message(STATUS "simple_matter: dropping ${_n} soft-float object(s) from the staticlib "
                   "(resolved by libgcc instead): ${_dropped}")
    execute_process(COMMAND "${AR_TOOL}" d "${OUT_A}" ${_dropped} COMMAND_ERROR_IS_FATAL ANY)
endif()
file(REMOVE_RECURSE "${_work}")

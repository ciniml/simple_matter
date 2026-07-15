/*
 * 空の翻訳単位。simple_matter コンポーネントの実体は Rust staticlib
 * (libsimple_matter_cffi.a)であり、CMakeLists.txt が add_prebuilt_library で
 * リンクする。このファイルは COMPONENT_LIB を(INTERFACE ではなく)通常の
 * STATIC library として生成させ、経路 (b) の cargo 実行順序を add_dependencies
 * で強制できるようにするためのプレースホルダである。
 */

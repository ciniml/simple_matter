idf_component_register(
    SRCS "main.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip driver esp_timer)

# C FFI シムのラッパは C++17。IDF v5.4 の既定 C++ 標準は C++17 だが明示する。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

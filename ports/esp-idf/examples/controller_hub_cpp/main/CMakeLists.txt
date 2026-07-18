idf_component_register(
    SRCS "main.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip esp_timer esp_system esp_psram)

# C FFI シムヘッダの利用は C++17。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

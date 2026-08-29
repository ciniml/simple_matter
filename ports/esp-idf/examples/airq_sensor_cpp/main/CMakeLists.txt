# AirQ センサ example。WiFi + BLE(NimBLE)構成 + SEN55/SCD40 I2C ドライバ。
#
# bt(NimBLE)は常時要求する。CONFIG_SM_ENABLE_BLE=n(将来の BLE 無効ビルド)でも
# ble.cpp は #if で空 + bt はスタブになるため通る(条件付き REQUIRES は sdkconfig
# 展開前に評価されるため使えない。onoff_light_cpp と同方針)。
# esp_driver_i2c / driver(gpio)はセンサドライバ(sensors.cpp)が使う。
idf_component_register(
    SRCS "main.cpp" "ble.cpp" "sensors.cpp"
    INCLUDE_DIRS "."
    REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip driver esp_driver_i2c esp_timer esp_system bt)

# C FFI シムのラッパは C++17。
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

# ホスト C++17 テストデバイスのビルド。
#
#   make            onoff_light をビルド(必要なら staticlib も cargo build)
#   make run ARGS=... 実行
#   make clean
#
# staticlib はホスト向けに --features std でビルドする(std のパニックハンドラ・
# eh_personality を使い C++ へリンクする。docs/design/c-ffi-shim.md §2)。
# ベアメタル(ESP-IDF/Zephyr)は --features panic-abort で no_std ビルドする。

INCDIR := ../include
ROOT   := $(abspath ../../..)
TARGET := x86_64-unknown-linux-gnu
LIBDIR := $(ROOT)/target/$(TARGET)/release
STATICLIB := $(LIBDIR)/libsimple_matter_cffi.a

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -I$(INCDIR)
LDLIBS   := -lpthread -ldl -lm

.PHONY: all lib run clean
all: onoff_light controller ble_loopback

lib:
	cargo build -p simple-matter-cffi --release --features std --target $(TARGET)

onoff_light: onoff_light.cpp lib
	$(CXX) $(CXXFLAGS) -o $@ onoff_light.cpp $(STATICLIB) $(LDLIBS)

# ホスト C++17 テストコントローラ(F7a、sm_ctrl_* を供給メモリ経路で駆動)。
controller: controller.cpp lib
	$(CXX) $(CXXFLAGS) -o $@ controller.cpp $(STATICLIB) $(LDLIBS)

# ホスト BLE ループバックハーネス(F7b、デバイスシム↔コントローラを 1 プロセスで直結)。
ble_loopback: ble_loopback.cpp lib
	$(CXX) $(CXXFLAGS) -o $@ ble_loopback.cpp $(STATICLIB) $(LDLIBS)

run: onoff_light
	./onoff_light $(ARGS)

clean:
	rm -f onoff_light controller ble_loopback

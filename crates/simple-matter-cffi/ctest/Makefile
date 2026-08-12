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

.PHONY: all lib run check check-generic check-wasm clean

# `make check` の作業ディレクトリ(状態ディレクトリを分離する)。
RUNDIR := ./run
all: onoff_light controller ble_loopback composed_loopback compose_check

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

# composition モード(Phase A)のループバックハーネス(合成デバイス ↔ コントローラ)。
composed_loopback: composed_loopback.cpp lib
	$(CXX) $(CXXFLAGS) -o $@ composed_loopback.cpp $(STATICLIB) $(LDLIBS)

# composition / binding blob のホスト検算(Phase B、generic_matter_cpp の README hex 例)。
# binding パーサはファームと同一ヘッダ(generic_matter_cpp/main/bind_tlv.hpp)を使う。
GENDIR := $(ROOT)/ports/esp-idf/examples/generic_matter_cpp/main
compose_check: compose_check.cpp lib $(GENDIR)/bind_tlv.hpp
	$(CXX) $(CXXFLAGS) -I$(GENDIR) -o $@ compose_check.cpp $(STATICLIB) $(LDLIBS)

run: onoff_light
	./onoff_light $(ARGS)

# 自己完結ハーネスの一括実行(ネットワーク・無線なしで green/red が決まる)。
#   make check
check: ble_loopback composed_loopback compose_check
	rm -rf $(RUNDIR) && mkdir -p $(RUNDIR)
	./ble_loopback wifi --dev-dir $(RUNDIR)/ble-wifi-dev --ctrl-dir $(RUNDIR)/ble-wifi-ctrl
	./ble_loopback thread --dev-dir $(RUNDIR)/ble-thr-dev --ctrl-dir $(RUNDIR)/ble-thr-ctrl
	./composed_loopback --dev-dir $(RUNDIR)/comp-dev --ctrl-dir $(RUNDIR)/comp-ctrl
	$(MAKE) check-generic

# generic_matter_cpp README の設定例(scripts/smgen-tlv.py examples の出力)を検算する。
# sm_init はプロセス 1 回きりなので、例ごとに別プロセスで走らせる。
check-generic: compose_check
	./compose_check \
	  --comp 1715250001002601000100002402023603060300000006040000000606000000181818 \
	  --bind 17152500010026010600000024020135032400072801181818 \
	  --expect 1:0003,1:0004,1:0006
	./compose_check \
	  --comp 1715250001002601010100002402033603060300000006040000000606000000060800000018181525000200260102030000240202360306020400000605040000181818 \
	  --bind 17152500010026010800000024020335032400002401062602e803000018181525000200260102040000240204350324000824010925028813181818 \
	  --expect 1:0003,1:0004,1:0006,1:0008,2:0402,2:0405

# Phase C(WASM スクリプト)のホストゲート。ファームと同一の script_vm.cpp を Linux 用
# WAMR にリンクし、サンプル .wasm(momentary-toggle)でフックのラウンドトリップと
# 暴走スクリプトの打ち切りを検証する。初回のみ WAMR 取得でネットワークが要るので
# `check` には含めない(docs/design/generic-firmware.md §9.3)。
check-wasm:
	$(ROOT)/tools/wasm-harness/run.sh

clean:
	rm -f onoff_light controller ble_loopback composed_loopback compose_check
	rm -rf $(RUNDIR)

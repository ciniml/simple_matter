// C++17 RAII ラッパ(ヘッダオンリー)。C FFI シム(simple_matter.h)を 1 枚の
// SmStack クラスに包む。設計 docs/design/c-ffi-shim.md §1 末尾。
//
// - コンストラクタで sm_init。デストラクタは無し(スタックは shim 内 static 単一実体)。
// - pump() が sm_poll ループ + イベント dispatch(std::function)。
// - TX 送出は呼び出し側の Sender コールバック(tx, len, dst)へ委譲(sans-IO)。
//
// 単一インスタンス・単線アクセス契約(全 API を同一スレッドから呼ぶこと)。
#pragma once

#include "simple_matter.h"

#include <cstdint>
#include <functional>
#include <utility>

class SmStack {
public:
  // TX 1 件を送る呼び出し側コールバック(バイト列・長さ・宛先)。
  using Sender = std::function<void(const uint8_t *buf, size_t len, const sm_addr_t &dst)>;
  // アプリイベント通知(OnOff 変化・コミッション完了等)。
  using EventFn = std::function<void(const sm_event_t &ev)>;

  // sm_init を呼ぶ。ok() で成否を確認する。
  SmStack(const sm_config_t &cfg, uint64_t now_ms) { rc_ = sm_init(&cfg, now_ms); }

  // コピー・ムーブ禁止(単一 static 実体を包むだけ)。
  SmStack(const SmStack &) = delete;
  SmStack &operator=(const SmStack &) = delete;

  int rc() const { return rc_; }
  bool ok() const { return rc_ == 0; }

  void on_event(EventFn fn) { ev_ = std::move(fn); }

  // Matter UDP 受信を処理し、応答があれば send() で送る。続けて pump()。
  void udp_rx(uint8_t *dg, size_t len, const sm_addr_t &src, uint64_t now, const Sender &send) {
    sm_addr_t dst{};
    size_t n = sm_udp_rx(dg, len, &src, now, tx_, sizeof(tx_), &dst);
    if (n) {
      send(tx_, n, dst);
    }
    pump(now, send);
  }

  // 時間駆動の送出(MRP 再送・ACK・購読レポート)を 0 になるまで排出し、イベントを配る。
  void pump(uint64_t now, const Sender &send) {
    sm_addr_t dst{};
    size_t n;
    while ((n = sm_poll(now, tx_, sizeof(tx_), &dst)) > 0) {
      send(tx_, n, dst);
    }
    drain_events();
  }

  // mDNS 受信クエリに応答する(QU ユニキャスト / QM マルチキャストはシムが宛先を決める)。
  void mdns_rx(const uint8_t *pkt, size_t len, const sm_addr_t &src, const Sender &send) {
    sm_addr_t dst{};
    size_t n = sm_mdns_rx(pkt, len, &src, tx_, sizeof(tx_), &dst);
    if (n) {
      send(tx_, n, dst);
    }
  }

  // mDNS の定期 announce を送る。
  void mdns_poll(uint64_t now, const Sender &send) {
    sm_addr_t dst{};
    size_t n = sm_mdns_poll(now, tx_, sizeof(tx_), &dst);
    if (n) {
      send(tx_, n, dst);
    }
  }

  void set_addrs(const uint8_t ipv4[4], const uint8_t ipv6_ll[16]) {
    sm_set_addrs(ipv4, ipv6_ll);
  }
  uint64_t next_deadline(uint64_t now) { return sm_next_deadline(now); }
  void onoff_set(bool on, uint64_t now) { sm_onoff_set(on, now); }
  bool onoff_get() { return sm_onoff_get(); }
  uint8_t fabric_count() { return sm_fabric_count(); }

  // 溜まったイベントを on_event へ配る。
  void drain_events() {
    sm_event_t e;
    while (sm_take_event(&e)) {
      if (ev_) {
        ev_(e);
      }
    }
  }

private:
  int rc_ = -1;
  EventFn ev_;
  uint8_t tx_[1600];
};

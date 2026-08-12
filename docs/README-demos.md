# simple-matter demos — バイナリ配布セット

[simple_matter](https://github.com/ciniml/simple_matter)(小フットプリント Matter
実装、Rust)のデモバイナリ集。タグ push 時に CI(release.yml)がビルドして
GitHub Release に添付する。リポジトリ全体の説明は同梱の README.md を参照。

## 内容物

| バイナリ | 役割 |
|---|---|
| `smctl` | CLI Matter コントローラ(**BLE 有効ビルド**。pairing / read / write / subscribe / invoke / batch)|
| `onoff-light` `dimmable-light` `color-light` `door-lock` `thermostat` `air-quality-sensor` `sensor-hub` `switch-demo` | クラスターデモデバイス(UDP/5540 + mDNS 広告で待ち受け)|
| `commissioner` | 最小コミッショナ example(UDP。機能的には smctl が上位互換)|
| `ble-commissioner` | BLE(BTP)コミッショナ example |
| `ble-onoff-light` | BLE デバイス側デモ(BlueZ 前提のため **Linux 版のみ**)|

## クイックスタート(同一ホスト or 同一 LAN)

デバイス側:

```sh
./onoff-light        # UDP/5540 で待ち受け、mDNS で commissionable 広告
```

コントローラ側(別ターミナル):

```sh
./smctl pairing onnetwork 1 20202021   # mDNS 発見 → コミッショニング
./smctl onoff toggle 1 1               # <cluster> <command> <node-id> <endpoint>
./smctl onoff read on-off 1 1
./smctl --help                         # コマンド一覧
```

デモデバイスの既定は passcode `20202021` / discriminator `3840`(いずれも開発用の
周知値)。`SM_PASE_VERIFIER=<iters>:<salt>:<w0l>` で verifier を外部供給できる
(verifier の生成は `smctl pase-verifier`)。

## 注意

- **開発用ツール**です。smctl の attestation 検証は `--paa-trust-store-path`
  指定時のみ(未指定はスキップ)。
- BLE(`smctl pairing ble*` / `ble-commissioner` / `ble-onoff-light`):
  Linux は BlueZ、Windows は WinRT を使う。Linux で複数アダプタがある場合は
  `SM_BLE_ADAPTER=hci1` のように選択。
- Windows の mDNS ブラウズは LAN 向きインタフェースを自動選択する(VPN 等で
  発見できない場合は `SM_MDNS_TRACE=1` で送受信をトレースできる)。
- Linux で 5353/udp を Avahi 等が専有していても QU ユニキャスト応答で動作する
  設計だが、発見が不安定な場合はデバイスログと `SM_MDNS_TRACE=1` を確認。

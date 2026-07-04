# simple-matter-ble

`simple-matter` の BTP(Bluetooth Transport Protocol)を **PC の実 BLE スタック**で駆動する
std クレート。コアの GATT 抽象 trait を Linux 上で実装し、BLE コミッショニングを端から端まで
実機で通す(`docs/design/ble-btp.md` フェーズ P4 / §9.2)。

- **device 側**(`device` feature): `BluerPeripheral` — BlueZ(bluer)で GATT peripheral。
  0xFFF6 service data の commissionable 広告 + C1 write / C2 indicate を提供する。
- **commissioner 側**(`commissioner` feature): `BtleplugCentral` — btleplug で GATT central。
  scan(discriminator 照合)→ connect → C2 subscribe → C1 write / indication 受信。

btleplug は central ロール専用なので、device 側 peripheral には bluer を使う分担
(設計 doc §6.1)。BTP 状態機械・handshake・window はコア(`simple-matter`)側の sans-IO
実装をそのまま共有し、このクレートは無線 I/O の橋渡しだけを担う。

## 前提

- **Linux + BlueZ**。`bluetoothd` が稼働していること(`systemctl status bluetooth`)。
  `device` feature は BlueZ 依存のため **Linux 専用**(`#[cfg(target_os = "linux")]` でガード)。
  `commissioner`(btleplug)は他 OS でもビルド可能だが、動作確認は Linux を想定する。
- **Bluetooth アダプタ**が有効(`bluetoothctl show` / `hciconfig`)。
- **権限**: BLE の広告登録・GATT サーバ公開・スキャンには特権が要る。いずれかで対応する:
  - 実行ユーザを `bluetooth` グループに入れる(D-Bus ポリシで許可される操作が広がる)。
  - もしくはバイナリに `CAP_NET_ADMIN`(および環境により `CAP_NET_RAW`)を付与するか、
    `sudo` で実行する。うまく広告/スキャンできない場合はまず権限を疑う。

## ビルド

```sh
cargo build -p simple-matter-ble --features device        # bluer peripheral
cargo build -p simple-matter-ble --features commissioner  # btleplug central
cargo clippy -p simple-matter-ble --all-features -- -D warnings
```

## 実 BLE E2E(段階2、設計 doc §9.2)

### アダプタ構成

- **推奨: 2 アダプタ**(内蔵 HCI + USB ドングル)または **2 台の PC**。device 側(bluer)と
  commissioner 側(btleplug)が別アダプタを使えば衝突しない。
- **単一アダプタでの同時起動**: BlueZ は同一アダプタで peripheral / central を同時に持てるため
  原理的には 1 台で可能だが、bluer と btleplug が同じ hci を奪い合う実運用リスクがあるため
  **追試扱い**。まずは 2 アダプタ構成を推奨する。
- **アダプタの指定**: 環境変数 `SM_BLE_ADAPTER` にアダプタ名(`hci0` 等)を渡す。
  device 側は BlueZ のアダプタ名そのもの、commissioner 側は btleplug の
  `adapter_info()` への前方一致。未指定は default(device)/最初の adapter(commissioner)。

### 実行(2 本のプロセス、同一 PC・2 アダプタ構成で動作確認済み)

デバイス(advertise 側)を先に起動する:

```sh
SM_BLE_ADAPTER=hci1 cargo run -p simple-matter-ble --features device --example ble-onoff-light
```

別ホスト/別アダプタでコミッショナを起動する(passcode と discriminator を渡す):

```sh
SM_BLE_ADAPTER=hci0 cargo run -p simple-matter-ble --features commissioner \
    --example ble-commissioner -- 20202021 3840
```

- discriminator(第 2 引数)は省略可能(任意の commissionable に接続)。既定は device 側と
  同じ `3840` / passcode `20202021`。
- 期待動作: `scan → connect → BTP handshake → PASE → ArmFailSafe → CSR →
  AddTrustedRoot → AddNOC → CASE → CommissioningComplete → OnOff Toggle → 切断`。
  device 側 stdout に `[onoff] light is now ON/OFF` が出れば属性反映まで通っている。
- BLE 特有の window/ack 挙動は `btmon`(BlueZ 付属)や nRF Sniffer + Wireshark の BTP
  dissector でフラグメントを確認できる。手軽には両 example とも `SM_BTP_TRACE=1` で
  BTP フラグメントの先頭バイト(flags/ack/seq)を stderr にトレースできる。
- 実測メモ(2026-07-05, 2 USB ドングル構成): btleplug は ATT_MTU を公開しないため
  BTP は既定 fragment=20 で動く(AddNOC は 20 フラグメント程度に分割される)。
  この経路でフルコミッショニング+Toggle まで確認済み。

## chip-tool / chip サンプルとの相互運用(段階3、設計 doc §9.3 の要点)

既存の connectedhomeip 相互運用実績(UDP)に BLE を接続する。

- **本デバイス(bluer)⇔ chip-tool**: `ble-onoff-light` を広告させ、chip-tool の BLE
  ペアリング経路で commission する。PASE-only を見るなら
  `chip-tool pairing ble-<transport> <node-id> <passcode> <discriminator>`(実 NW join を伴う
  `ble-wifi` / `ble-thread` は NetworkCommissioning 実 join が将来スコープのため、まずは
  0xFFF6 広告 → BTP handshake → PASE → CASE → CommissioningComplete が通ることを確認する)。
- **本コントローラ(btleplug)⇔ chip サンプルデバイス**: `chip-lighting-app` を
  `--discriminator 3840 --passcode 20202021` 等で BLE 広告させ、`ble-commissioner` で
  commission する。
- 突き合わせ観点: Wireshark(Matter dissector + BTP dissector)で handshake バイト列・
  discriminator・PASE session parameters・Sigma1 destination-id を chip 側キャプチャと比較する。

## 設計上の注意

- **同時接続は 1**(初期スコープ、設計 doc §11-2)。`BtpConnId` は単一接続に採番する。
- **ATT_MTU**: btleplug は MTU を公開しないため commissioner 側は `None` で handshake する
  (BTP は既定フラグメント長で交渉)。bluer 側は C1 write 要求の MTU を利用する。
- pump ループは設計 doc §6.2 のとおり、`stack.next_deadline` と `btp.next_deadline` を min で
  待ちつつ **毎周 `poll` を呼ぶ**(BLE は MRP 無効のため、poll を怠ると閉じた exchange が
  回収されずプールが枯渇する、§11-4)。

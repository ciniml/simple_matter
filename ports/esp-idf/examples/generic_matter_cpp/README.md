# generic_matter_cpp — 設定駆動の汎用 Matter ファームウェア(Phase B = G1 + G2)

**1 つのビルド済みファームウェアを、再ビルド無しに別のデバイスへ変える**ための example。
設計は `docs/design/generic-firmware.md`(§9.1 composition / §9.2 本 example)、
C FFI シムは `docs/design/c-ffi-shim.md`。

- **G1(構成)**: NVS の `composition` TLV でエンドポイント・デバイスタイプ・搭載クラスタを決める。
- **G2(配線)**: NVS の `binding` TLV でクラスタとハードウェア(GPIO / LEDC / I2C)を結ぶ。
- 設定はコンソール(USB-Serial-JTAG)から流し込み、**再起動で反映**する。
- Phase C(スクリプト VM)/ Phase D(ScriptStore OTA)は未実装。`smscript` パーティションと
  `script` ドライバ ID だけ予約してある。

ベースは `onoff_light_cpp`(WiFi/BLE/Thread、UDP+mDNS、KVS、128KB スタック pump タスク)。
差分は「起動時に設定 blob を読む」「`on_cluster_change` を HAL へ dispatch する」
「`cfg-*` コンソールを持つ」の 3 点だけ。

## 構成

| 要素 | 実体 |
|---|---|
| 合成器 | シムの composition モード(`sm_config_t.composition`。`crates/simple-matter-cffi/src/compose.rs`) |
| 設定格納 | NVS namespace `smgen`、blob key `comp`(composition TLV)/ `bind`(binding TLV) |
| HAL バインディング | `main/bindings.cpp`(gpio_out / gpio_in / ledc / i2c_sht30 / script) |
| binding TLV パーサ | `main/bind_tlv.hpp`(ESP-IDF 非依存のヘッダオンリー = ホスト検算と共用) |
| コンソール | `main/cfg_store.cpp`(esp_console REPL、USB-Serial-JTAG) |
| TLV ジェネレータ | `scripts/smgen-tlv.py`(ホスト側。hex を出す) |

**既定構成**(NVS に `comp` / `bind` が無いとき):
EP1 = On/Off Light(device type `0x0100` rev 2、Identify + Groups + OnOff)、
OnOff → `gpio_out`(pin = `CONFIG_SM_DEFAULT_GPIO`、既定 GPIO7 = M5 NanoC6 / S3 は GPIO48)。

## ビルド

```sh
cd ports/esp-idf/examples/generic_matter_cpp
idf.py set-target esp32c6
idf.py build
```

docker(Rust をコンテナに入れない場合はホストと同一パスで rustup をマウントする):

```sh
REPO=$(git rev-parse --show-toplevel)
docker run --rm -v $REPO:$REPO -v $HOME/.cargo:$HOME/.cargo -v $HOME/.rustup:$HOME/.rustup \
  -e HOME=$HOME -w $REPO/ports/esp-idf/examples/generic_matter_cpp espressif/idf:release-v5.4 \
  bash -ec 'export PATH=$HOME/.cargo/bin:$PATH; idf.py set-target esp32c6 && idf.py build'
```

Thread 構成(ESP32-C6):

```sh
idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.esp32c6;sdkconfig.defaults.thread" \
       set-target esp32c6 build
```

WiFi 資格情報などの秘密は Kconfig の default に書かない。`sdkconfig.local`(gitignore 済み)に
`CONFIG_SM_WIFI_SSID="..."` / `CONFIG_SM_WIFI_PASSWORD="..."` を置く。

## コンソール(USB-Serial-JTAG)

`idf.py monitor` か任意の端末で接続すると `smgen>` プロンプトが出る。

| コマンド | 内容 |
|---|---|
| `cfg-comp <hex>` | composition TLV を NVS `smgen/comp` に保存 |
| `cfg-bind <hex>` | binding TLV を NVS `smgen/bind` に保存(保存前にパース検証する) |
| `cfg-show` | 保存済み blob を hex 表示 + binding をデコード表示 |
| `cfg-clear` | 両方を消す(次回起動は既定構成) |
| `restart` | 再起動して設定を反映 |
| `help` | コマンド一覧 |

コンソールタスクは `sm_*` を一切呼ばない(NVS と `esp_restart` のみ)ので、
Matter の単線アクセス契約を壊さない。

## 設定変更の実例

hex は `scripts/smgen-tlv.py examples` の出力そのもの。**ホスト検算済み**
(`crates/simple-matter-cffi/ctest` の `make check-generic` = 実際に `sm_init` へ食わせて
合成結果の (endpoint, cluster) が一致することを確認している)。

### ① 既定 = On/Off ライト(EP1、GPIO7)

```
cfg-comp 1715250001002601000100002402023603060300000006040000000606000000181818
cfg-bind 17152500010026010600000024020135032400072801181818
restart
```

- composition: EP1 / device type `0x0100`(On/Off Light)rev 2 / Identify(0x0003)+
  Groups(0x0004)+ OnOff(0x0006)。Descriptor は自動付与。
- binding: EP1 の OnOff → `gpio_out`(pin=7、invert=false)。
- これは**ファームの既定構成と同一のバイト列**なので、`cfg-clear` + `restart` でも同じになる。

### ② 調光ライト + 温湿度計(2 エンドポイント)

```
cfg-comp 1715250001002601010100002402033603060300000006040000000606000000060800000018181525000200260102030000240202360306020400000605040000181818
cfg-bind 17152500010026010800000024020335032400002401062602e803000018181525000200260102040000240204350324000824010925028813181818
restart
```

- composition: EP1 / `0x0101`(Dimmable Light)rev 3 / Identify + Groups + OnOff +
  LevelControl(0x0008)、EP2 / `0x0302`(Temperature Sensor)rev 2 /
  TemperatureMeasurement(0x0402)+ RelativeHumidityMeasurement(0x0405)。
- binding: EP1 の LevelControl → `ledc`(ch=0、pin=6、freq=1000Hz)、
  EP2 の Temperature → `i2c_sht30`(sda=8、scl=9、poll_ms=5000)。
- **OnOff にバインディングは要らない**: `ledc` は同一 EP に OnOff が合成されていれば
  それも見て duty を決める(off = duty 0、on = CurrentLevel から算出)。
- SHT30 は温度を EP2/0x0402 に、湿度を同一 EP の 0x0405 に push する
  (0x0405 が無い構成なら push は黙って無視される)。

### 自分で作る

```sh
cat > /tmp/comp.json <<'JSON'
[ { "ep": 1, "device_type": "0x0106", "rev": 1, "clusters": ["0x0003", "0x0400"] } ]
JSON
scripts/smgen-tlv.py comp /tmp/comp.json      # → hex(cfg-comp に貼る)
scripts/smgen-tlv.py decode-comp <hex>        # 逆変換で検算
scripts/smgen-tlv.py selftest                 # 例のラウンドトリップ
```

## composition TLV スキーマ(§9.1)

```
anonymous list|array of endpoint structs:     ← struct 直書き(単一 EP)も受理
  {
    0: endpoint-id     u16   必須。1..=8(0 = システム EP は予約)
    1: device-type     u32   DeviceTypeList に載る
    2: device-type-rev u8    既定 1
    3: cluster list    [u32, ...]   合成可能クラスタ ID(重複と 0x001D は無視)
    4: options         [ {0: cluster u32, 1: attr u32, 2: value(scalar|null)}, ... ]  optional
  }
```

合成可能クラスタ(括弧内 = 個数上限): Identify(8)/ Groups(8)/ OnOff(8)/ LevelControl(4)/
ColorControl(2)/ BooleanState(4)/ OccupancySensing(2)/ Temperature・RelativeHumidity・
Illuminance・Pressure・Flow(各 4)/ Switch(4)/ FanControl(2)/ DoorLock(1)/ Thermostat(1)。
最大 EP 8・EP あたり 12 クラスタ・slot 総数 40・options 16。
上限超過は `sm_init` が `-8`、TLV 不正/未対応クラスタは `-7` を返す
(その場合ファームは起動を止めてログを出すので、`cfg-clear` + `restart` で戻す)。

## binding TLV スキーマ(§9.2)

```
anonymous list|array of binding structs:      ← struct 直書き(単一 binding)も受理
  {
    0: endpoint u16   必須(1..)
    1: cluster  u32   必須(ドライバを結び付けるクラスタ ID)
    2: drv-id   u8    必須(1=gpio_out 2=gpio_in 3=ledc 4=i2c_sht30 5=script)
    3: params   struct(ドライバ固有。context tag → スカラ)。省略可
  }
```

| drv | id | params(context tag) | 対象クラスタ | 動作 |
|---|---|---|---|---|
| `gpio_out` | 1 | 0=pin u8、1=invert bool | OnOff(0x0006) | 属性変化 → GPIO 出力 |
| `gpio_in` | 2 | 0=pin u8、1=invert bool、2=poll_ms u16(既定 50)、3=pull u8(0=none 1=up 既定 2=down) | BooleanState(0x0045)/ Switch(0x003B) | ポーリング + 2 連続一致デバウンス → `sm_attr_set_value` |
| `ledc` | 3 | 0=ch u8、1=pin u8、2=freq u32(既定 1000)、3=invert bool | LevelControl(0x0008) | CurrentLevel(0..254)→ duty(10bit)。同一 EP の OnOff が off なら duty 0 |
| `i2c_sht30` | 4 | 0=sda u8、1=scl u8、2=poll_ms u16(既定 5000)、3=port u8(既定 0) | Temperature(0x0402) | 単発測定(0x2C06、CRC 検証)→ 0x0402 と同一 EP の 0x0405 へ push |
| `script` | 5 | (予約) | 任意 | Phase C(WASM フック)で接続。現状 no-op |

バインディング上限 16(`bind_tlv.hpp` の `kMaxBindings`)。
params の tag → 名前の対応は `scripts/smgen-tlv.py` の `PARAMS` と 1 対 1。

## パーティション

`partitions.csv`(4MB flash):

| 名前 | 型 | サイズ | 用途 |
|---|---|---|---|
| `nvs` | data/nvs | 24KB | コア KVS(`smatter`)+ 設定 blob(`smgen`)+ WiFi/Thread 資格情報 |
| `factory` | app | 2.5MB | アプリ本体(Thread 構成の openthread 込みでも収まる) |
| `nvs_factory` | data/nvs | 24KB | esp-matter-mfg-tool 互換 factory データ(`CONFIG_SM_FACTORY_DATA`) |
| `smscript` | data/0x40 | 256KB | **Phase D 用に予約**(Phase B では未使用) |

## 制約・注意

- **構成変更は再起動で反映**。コミッショニング済みの fabric がある状態で
  エンドポイント構成を変えると Matter 的には「別デバイス」になり得る(R-G1)ので、
  構成変更時は factory reset を推奨する。
- 汎用 FW は attestation と相性が悪い(VID/PID が設定次第。R-G5)。開発・自家用前提。
- `on_cluster_change` は IM write / コマンド由来の変化でのみ発火し、
  `sm_attr_set_value`(アプリ発 = センサ push)では発火しない → HAL のループが起きない。
- I2C 読み出しは pump タスクを ~15ms 占有する(clock stretching)。`poll_ms` は
  1 秒以上を推奨。
- 実機検証はユーザの機材で行う(本 example のゲートはビルド + ホスト検算まで)。

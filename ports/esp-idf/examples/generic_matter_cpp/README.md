# generic_matter_cpp — 設定駆動の汎用 Matter ファームウェア(Phase B = G1 + G2)

**1 つのビルド済みファームウェアを、再ビルド無しに別のデバイスへ変える**ための example。
設計は `docs/design/generic-firmware.md`(§9.1 composition / §9.2 本 example)、
C FFI シムは `docs/design/c-ffi-shim.md`。

- **G1(構成)**: NVS の `composition` TLV でエンドポイント・デバイスタイプ・搭載クラスタを決める。
- **G2(配線)**: NVS の `binding` TLV でクラスタとハードウェア(GPIO / LEDC / I2C)を結ぶ。
- 設定はコンソール(USB-Serial-JTAG)から流し込み、**再起動で反映**する。
- **G3(スクリプト)**: `smscript` パーティションに置いた WASM(WAMR interp)のフックが
  属性変化・センサ更新・タイマで走る(Phase C。下の「スクリプト(WASM)」節)。
- Phase D(ScriptStore による OTA 転送)は未実装。イメージは今のところ esptool で書く。

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
| スクリプト VM | `main/script_vm.cpp`(WAMR ラッパ。ESP-IDF 非依存)+ `main/script_host.cpp`(ESP 実体) |
| スクリプト ABI | `main/script_abi.hpp`(16B 値表現・フック名・import 名)/ `main/script_img.hpp`(`SMWS` ヘッダ) |
| スクリプト SDK | `crates/sm-script-api`(Rust)/ `web/sdk/sm.d.ts`(AssemblyScript 宣言) |

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
mkdir -p $HOME/.cache/Espressif      # ← WAMR を取りに行く component manager のキャッシュ
docker run --rm -u $(id -u):$(id -g) -e CCACHE_DISABLE=1 \
  -v $REPO:$REPO -v $HOME/.cargo:$HOME/.cargo -v $HOME/.rustup:$HOME/.rustup \
  -v $HOME/.cache/Espressif:$HOME/.cache/Espressif \
  -e HOME=$HOME -w $REPO/ports/esp-idf/examples/generic_matter_cpp espressif/idf:release-v5.4 \
  bash -ec 'export PATH=$HOME/.cargo/bin:$PATH; idf.py set-target esp32c6 && idf.py build'
```

Phase C から **WAMR を ESP Component Registry から取得する**ため、初回ビルドは
ネットワークと `~/.cache/Espressif`(component manager のキャッシュ)への書き込みが要る。
非 root で docker を回す場合はこのディレクトリをマウントしないと
`Failed to create cache directory` で configure が失敗する。

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
| `script` | 5 | 0=poll_ms u32(既定 0 = 周期発火しない) | 任意 | 周期で WASM の `on_sensor(bind index)` を呼ぶ(§9.3) |

バインディング上限 16(`bind_tlv.hpp` の `kMaxBindings`)。
params の tag → 名前の対応は `scripts/smgen-tlv.py` の `PARAMS` と 1 対 1。

## パーティション

`partitions.csv`(4MB flash):

| 名前 | 型 | サイズ | 用途 |
|---|---|---|---|
| `nvs` | data/nvs | 24KB | コア KVS(`smatter`)+ 設定 blob(`smgen`)+ WiFi/Thread 資格情報 |
| `factory` | app | 2.5MB | アプリ本体(Thread 構成の openthread 込みでも収まる) |
| `nvs_factory` | data/nvs | 24KB | esp-matter-mfg-tool 互換 factory データ(`CONFIG_SM_FACTORY_DATA`) |
| `smscript` | data/0x40 | 256KB | WASM スクリプト(128KB × 2 スロット。`SMWS` ヘッダ)。オフセット `0x296000` |

## スクリプト(WASM / Phase C = G3)

`smscript` パーティションに有効なイメージがあれば、起動時に WAMR(interpreter)へ
ロードしてフックを実行する。**イメージが無ければ従来どおり動く**(全フックが no-op)。

### ランタイム

| 項目 | 値 |
|---|---|
| VM | WAMR **2.4.0**(ESP Component Registry の `espressif/wasm-micro-runtime`。`main/idf_component.yml`。リポジトリに vendor しない) |
| モード | classic interpreter のみ(AOT / WASI / libc-builtin / app-framework は無効。`sdkconfig.defaults` の `CONFIG_WAMR_*`) |
| 線形メモリ | スクリプトの宣言どおり(Rust の既定は 1 page = 64KB)。プールから確保する |
| ヒーププール | `CONFIG_SM_SCRIPT_POOL_KB`(既定 96KB)。既定では**スクリプトが見つかったときだけ**内部 RAM から確保する(`CONFIG_SM_SCRIPT_POOL_STATIC=y` で .bss 常時確保) |
| 実行モデル | フックは Matter ポンプと**同一タスクで同期実行**(単線契約) |
| 暴走対策 | フック呼び出し前に esp_timer ワンショット(`CONFIG_SM_SCRIPT_BUDGET_MS`、既定 50ms)を武装。満了で `wasm_runtime_terminate` → trap でフックを打ち切る |
| 無効化 | `CONFIG_SM_SCRIPT_ENABLE=n`(WAMR ごとリンクしない = Phase B と同じサイズ) |

### フックとホスト import

フック ABI・ホスト import・**16B 値レイアウト**は `crates/sm-script-api/README.md`
(および `main/script_abi.hpp` / `web/sdk/sm.d.ts`)に定義がある。発火元だけ再掲:

| フック | 発火元(このファーム) |
|---|---|
| `on_boot()` | `script_init()`(sm_init + バインディング初期化の直後) |
| `on_attr_write(ep,cluster,attr)` | `sm_config_t.on_cluster_change`(IM write / コマンド由来の変化)。HAL への dispatch の**後** |
| `on_sensor(bind)` | `gpio_in` の確定変化、`i2c_sht30` の push、`script` binding の周期(`poll_ms`) |
| `on_timer(id)` | pump ループの `script_poll`(`timer_after` / `timer_every`) |
| `on_command(ep,cluster,cmd)` | **カスタムクラスタ(ScriptStore)の invoke のみ**(Phase D で配線)。合成クラスタ(OnOff 等)のコマンドは現行シムに口が無く**未接続**。戻り値は観測のみ |

**`on_attr_write` の非 0 戻り値は「観測のみ」**: `on_cluster_change` は既に適用された
変化の通知で、シムに write を拒否させる口が無い。ファームは警告ログを出すだけで
書き込みは取り消さない(拒否したいスクリプトは `attr_set` で元の値へ書き戻す)。

### イメージ形式と書き込み

`smscript`(256KB)は 128KB × 2 スロット。各スロット先頭 16B が
`"SMWS"` + ver u16 + flags u16 + len u32 + crc32 u32(`main/script_img.hpp`)。
active slot = ヘッダ妥当 + CRC 一致のうち **ver 最大**(同値なら A)。両方無効なら
スクリプト無し。

```sh
# 1) スクリプトをビルド(Rust の例)
cd crates/sm-script-api/examples-wasm/momentary-toggle
cargo build --release --target wasm32-unknown-unknown

# 2) SMWS ヘッダを付ける
scripts/smscript-img.py pack \
  target/wasm32-unknown-unknown/release/momentary_toggle.wasm -o slotA.bin --ver 1

# 3) slot A(= smscript の先頭)へ書く
esptool.py write_flash 0x296000 slotA.bin
# slot B は 0x296000 + 0x20000 = 0x2B6000
```

`scripts/smscript-img.py show <dump>` でスロットの検査ができる。

## スクリプト OTA — ScriptStore クラスタ(Phase D = G4)

書き込み済みのデバイスへ**Matter セッション経由で**スクリプトを差し替える。
vendor クラスタ **`0xFFF1FC01`(ScriptStore)** を CustomCluster(C FFI シムの F4b)で
実装しており、シム・コアは無改造。既定のエンドポイントは **EP1**
(`CONFIG_SM_SCRIPTSTORE_EP`)、無効化は `CONFIG_SM_SCRIPTSTORE_ENABLE=n`。

| コマンド | ID | 引数 |
|---|---|---|
| `Begin` | `0x00` | `0` = size u32(本体バイト数)、`1` = crc32 u32(CRC-32/IEEE) |
| `Data` | `0x01` | `0` = offset u32(**受信済みバイト数と一致する順次のみ**)、`1` = bytes octstr |
| `Commit` | `0x02` | なし |
| `Abort` | `0x03` | なし |

| 属性 | ID | 型 | 内容 |
|---|---|---|---|
| `State` | `0x0000` | u8 | 0=idle / 1=receiving / 2=committing / 3=error |
| `ActiveSlot` | `0x0001` | u8 | 0=A / 1=B / 255=スクリプト無し |
| `Version` | `0x0002` | u32 | active イメージの `SMWS` ver |
| `ChunkMax` | `0x0003` | u16 | `Data` 1 発の上限バイト数(= **64**。下記) |

### 転送手順(smctl)

```sh
# 1) .wasm → 転送バッチ(Begin / Data ×N / Commit / Version 読み)を生成
scripts/smscript-img.py batch \
  target/wasm32-unknown-unknown/release/momentary_toggle.wasm \
  --node 1 --ep 1 > store.batch

# 2) 単一プロセス = 単一 CASE セッションで流し込む
smctl batch store.batch

# 3) 反映の確認(State=0 idle、ActiveSlot が A↔B で切り替わり、Version が +1)
smctl any read 1 1 0xFFF1FC01 0    # State
smctl any read 1 1 0xFFF1FC01 1    # ActiveSlot
smctl any read 1 1 0xFFF1FC01 2    # Version
```

生成される行はそのまま手で打てる形式:

```text
any invoke 1 1 0xFFF1FC01 0x00 0=u32:1452 1=u32:2894...   # Begin(size, crc32)
any invoke 1 1 0xFFF1FC01 0x01 0=u32:0 1=hex:0061736d...  # Data(offset, bytes)
any invoke 1 1 0xFFF1FC01 0x02                            # Commit
```

`smctl batch` は 1 プロセスで CASE セッションを共有するので、チャンク 1 本ごとに
CASE をやり直す無駄が無い(23 チャンク ≒ 1.5KB のスクリプトで数百 ms)。

### 動作と制約(必読)

- **チャンクは 64 バイトが上限**。設計 §9.4 は「≤512」だが、シムの
  `sm_attr_value_t` は octet string を **64B 固定バッファ**(`STR_CAP`)で運ぶため、
  シム無改造では 64B が実効上限になる。`ChunkMax` 属性がこの値を返す。
- **`Data` は順次のみ**。`offset` は受信済みバイト数と一致しなければならず、
  再送(同じ offset の再投入)も `ConstraintError(0x87)` で弾く。落ちたら
  `Abort` → `Begin` からやり直す(バッチを頭から流し直す)。
- 受信先は**非 active スロット**。`Begin` で必要分だけ 4KB 単位で消去し、本体を
  順に書き、**`SMWS` ヘッダは Commit の最後に書く**。途中で電源が落ちたスロットは
  magic 無し = 無効なので、旧スロットが active のまま残る(半焼けで文鎮化しない)。
- `Commit` = 書き戻し読みによる **CRC 検証** → ヘッダ書き込み(ver = 現行 +1)→
  `State=committing`。**VM の再ロードは invoke ハンドラの中ではなく pump ループ**で
  実行する(単線契約・再入回避)。成功で `State=idle`、失敗なら**新スロットのヘッダを
  消して旧スロットへロールバック**し `State=error`(旧スクリプトが再ロードされる)。
- 状態遷移: `idle --Begin--> receiving --Commit--> committing --(pump)--> idle`。
  `Abort` はいつでも `idle` へ(`committing` 中だけ `Busy(0x9c)`)。`error` からは
  `Begin` / `Abort` で復帰する。
- **認可はシムの CustomCluster 既定 = invoke は Operate 権限**(read は View)。
  F4b に「このコマンドは Administer」を指定する口が無いため、Administer 限定には
  できない(設計 §9.4 は CASE + Administer を想定)。運用上は ACL で Operate を
  与える相手を絞ること。Matter セッション(CASE)の外からは投入できない。
- `Commit` の CRC は**フラッシュから読み返して**計算するので、転送誤りと書き込み
  失敗の両方を検出する。イメージそのものの妥当性(WASM として読めるか)は
  再ロード時に WAMR が判定し、駄目ならロールバックする。

### スクリプト用 KVS

`kvs_get` / `kvs_set` は NVS namespace **`smscr`**(コアの `smatter`・設定の `smgen` とは別)。
キーは 15 バイトまでの非 NUL バイト列。

### ホスト検証

`tools/wasm-harness/run.sh`(= `make -C crates/simple-matter-cffi/ctest check-wasm`)が、
**このファームと同一の `script_vm.cpp`** を Linux 用 WAMR にリンクして、
`momentary-toggle` のフックのラウンドトリップと暴走スクリプトの打ち切りを検証する。

## 制約・注意

- **構成変更は再起動で反映**。コミッショニング済みの fabric がある状態で
  エンドポイント構成を変えると Matter 的には「別デバイス」になり得る(R-G1)ので、
  構成変更時は factory reset を推奨する。
- 汎用 FW は attestation と相性が悪い(VID/PID が設定次第。R-G5)。開発・自家用前提。
- `on_cluster_change` は IM write / コマンド由来の変化でのみ発火し、
  `sm_attr_set_value`(アプリ発 = センサ push)では発火しない → HAL のループが起きない。
- I2C 読み出しは pump タスクを ~15ms 占有する(clock stretching)。`poll_ms` は
  1 秒以上を推奨。
- **スクリプトはサンドボックス内**: 線形メモリの外へは触れない(ポインタ引数は VM 側で
  範囲検証する)。触れる外界は module `"sm"` の import だけ = 能力ベース。
- スクリプトのフックは pump タスクを占有する。長い処理は `timer_after` で分割する
  (1 フックあたり既定 50ms で強制打ち切り = そのフックの副作用は途中で止まる)。
- 実機検証はユーザの機材で行う(本 example のゲートはビルド + ホスト検算まで)。

# T10(検討): Tab5 のカメラで Matter QR を読んでコミッショニングする

対象: `ports/esp-idf/examples/tab5_ctrl_app`(M5Stack Tab5 / ESP32-P4)。
関連: `docs/design/p4-thread-controller.md` §9(LVGL アプリ)、§10(T2 WiFi)、§11(T3 BLE)、
§13(T5 デバッグ自動化)、§17(T9 コミッショニング窓 / `discovery::onboarding`)。

**本ドキュメントは検討のみ。コード変更は含まない。**

---

## 1. 結論

### 1.1 実現性

**実現可能**。ハード・ソフトとも既製部品が揃っており、新規に書くのは
「カメラ→グレースケール→quirc→`MT:` パーサ→既存 pair op」の接着コードだけ。

根拠(詳細は §2):

| 要素 | 状況 |
| --- | --- |
| カメラ実体 | SC2356 / **SC202CS**(2MP 1600×1200)、MIPI-CSI 2 レーン。Tab5 に実装済み |
| ドライバ | Espressif `esp_video` + `esp_cam_sensor` + `esp_ipa`。**SC202CS の driver は上流に存在**し、IDF **>= 5.4**(本プロジェクトのビルド環境と一致) |
| 実績 | M5Stack 純正 `M5Tab5-UserDemo` が **IDF 5.4.2 / SC202CS / MIPI RAW8 1280×720 30FPS / V4L2 / LVGL canvas** で動作。同一基板の実証コードが読める |
| QR デコード | `espressif/quirc`(ISC ライセンス、全ターゲット可、依存なし)。必要メモリは概ね `w*h` バイト |
| payload 解析 | コアに `discovery::onboarding`(**生成側は T9 で実装済み**)。**解析側を足すだけ**でビット配置・base38 表・テストベクタを再利用できる |
| コミッショニング導線 | `SM_UI_OP_PAIR` / `SM_UI_OP_PAIR_BLE`(+ `sm_ui_via_t`)が既にある。QR は**フォームを自動入力する入力手段**として差せる |

### 1.2 推奨案(要旨)

1. **カメラは `esp_video` の V4L2 経路、フォーマットは RAW8(`V4L2_PIX_FMT_SBGGR8`)**。
   ISP / IPA(自動露出)は **v1 では無効**にする。理由は「quirc が欲しいのは 1bpp/px の
   グレースケールであり Bayer RAW8 をそのまま食わせられる」「ISP を切ると
   **ストリーミング中の SCCB(I2C)アクセスが消え**、M5GFX の I2C 直叩きとの競合が
   初期化時の数十 ms に限定される」の 2 つ(§4.2、§5.2)。
2. **quirc へは 2×2 サブサンプル(同一 Bayer 位相の 1 チャネル抽出)で 640×360 を渡す**。
   Bayer の市松模様が消え、quirc の作業量とメモリが 1/4 になる。
3. **プレビューは v1 では低頻度(3〜5 fps)の L8(グレースケール)`lv_canvas`**。
   フルカラーのなめらかなプレビューが要るなら v2 で ISP + PPA(`M5Tab5-UserDemo` と同型)。
4. **payload 解析はコア(`crates/simple-matter/src/discovery/onboarding.rs`)に
   `parse_qr_payload` / `parse_manual_pairing_code` を追加**、shim に純関数
   `sm_onboarding_parse()` を 1 本出す(スタック状態に触らないので UI タスクから直接呼べる)。
5. **UI は「pair ダイアログに `Scan QR` ボタン」**。読めたらフォーム
   (discriminator / passcode)を自動入力し、discovery caps から経路を推定して
   **確認画面を必ず経由**してから既存 op を post(§4.5)。

### 1.3 主要な未確認事項(実機で潰す)

- **MIPI LDO の共存**: DSI(M5GFX)と CSI(esp_video)が**どちらも LDO ch3 @ 2500 mV** を
  `esp_ldo_acquire_channel()` する。IDF の仕様上、固定電圧チャネルは参照カウントで
  多重取得できる**はず**だが、実機で「カメラ open 時に画面が消えない」ことの確認が必須(§5.1)。
- **I2C の共存**: M5GFX は IDF の i2c ドライバを使わず**レジスタ直叩き + トランザクション毎の
  save/load**。esp_video の SCCB は IDF `i2c_master`。理屈上は共存するが実機確認が必須(§5.2)。
- **カメラ電源 EN が IO エキスパンダ(PI4IOE5V6408)の pin 6**。M5Unified がこれを
  HIGH にしているか(していなければ自前で叩く)(§2.1)。

---

## 2. 調査結果(出典付き)

### 2.1 ハードウェア

- Tab5 は ESP32-P4 + 16MB flash + 32MB PSRAM、5 インチ 1280×720 MIPI-DSI、
  **SC2356 2MP(1600×1200)カメラを MIPI-CSI 接続**。
  出典: [M5Stack Tab5 製品ページ](https://shop.m5stack.com/products/m5stack-tab5-iot-development-kit-esp32-p4)、
  [m5-docs Tab5](https://docs.m5stack.com/en/core/Tab5)
- Espressif BSP `esp-bsp/bsp/m5stack_tab5` は **camera を「SC202CS via MIPI-CSI」としてサポート**と
  明記(`BSP_CAPS_CAMERA 1`)。同 BSP のピン定義から:
  - 共有 I2C は **SCL = GPIO32 / SDA = GPIO31**
  - **`BSP_CAMERA_RST` は無し(`GPIO_NUM_NC`)、`BSP_CAMERA_XCLK` も無し**
    (センサは基板上の発振器から給クロック → CSI 初期化に XCLK 設定が要らない)
  - **`BSP_CAMERA_EN` = IO エキスパンダ pin 6**(`ESP_IO_EXPANDER_I2C_PI4IOE5V6408`、
    アドレス 0x43 / 0x44)
  - `BSP_CAMERA_ROTATION = 270`(画面に対して 270° 回転して実装されている)
  出典: [esp-bsp m5stack_tab5 README](https://github.com/espressif/esp-bsp/blob/master/bsp/m5stack_tab5/README.md)、
  [`include/bsp/m5stack_tab5.h`](https://github.com/espressif/esp-bsp/blob/master/bsp/m5stack_tab5/include/bsp/m5stack_tab5.h)
- `SC202CS` は **`SC2356` の別名**。`esp_cam_sensor` の対応表に
  「SC202CS(SC2356)/ 1600×1200 / MIPI / 8-10bit Raw RGB」として載る。ライセンスは Apache-2.0。
  出典: [components.espressif.com esp_cam_sensor](https://components.espressif.com/components/espressif/esp_cam_sensor)
- **注意**: `esp-bsp` の README には CSI の実装状況について時期により
  「not yet implemented」の記述もある。**BSP には依存しない**方針(本アプリは既に BSP を捨てて
  M5GFX を使っている。§9.5)なので影響しないが、BSP 経由の作例をそのまま真似ないこと。

### 2.2 ソフトウェア(Espressif コンポーネント)

- `espressif/esp_video`: Linux V4L2 互換フレームワーク。MIPI-CSI / DVP / SPI / USB。
  ESP32-P4 が第一級ターゲット。依存は `esp_cam_sensor` / `esp_ipa` / `esp_h264` / `usb_host_uvc`。
  **1.2.0 以降のすべてのバージョンが `idf: ">=5.4"`** なので、本プロジェクトの
  `espressif/idf:release-v5.4` docker でそのまま使える。
  ライセンスは **ESPRESSIF MIT**(Espressif 製品上での利用は無償・改変再配布可。
  本リポジトリの Boost ライセンスとは別建てのサードパーティ component として扱えばよい)。
  出典: [components.espressif.com esp_video](https://components.espressif.com/components/espressif/esp_video)、
  [esp_video 2.4.1 license.txt](https://components-file.espressif.com/components/espressif/esp_video/2.4.1/license.txt)、
  [esp-video-components docs](https://docs.espressif.com/projects/esp-video-components/en/latest/esp32p4/index.html)
- **M5Stack 純正 `M5Tab5-UserDemo` が同一基板で動く実証コード**。特に:
  - `platforms/tab5/sdkconfig` は **IDF 5.4.2**、
    `CONFIG_CAMERA_SC202CS=y` / `..._AUTO_DETECT=y` /
    `..._AUTO_DETECT_MIPI_INTERFACE_SENSOR=y` /
    **`CONFIG_CAMERA_SC202CS_MIPI_RAW8_1280x720_30FPS=y`**、
    `CONFIG_ESP_VIDEO_ENABLE_MIPI_CSI_VIDEO_DEVICE=y` / `CONFIG_ESP_VIDEO_ENABLE_ISP=y` /
    `CONFIG_ESP_VIDEO_ENABLE_ISP_PIPELINE_CONTROLLER=y` / `CONFIG_ESP_IPA_*`。
  - `platforms/tab5/main/hal/components/hal_camera.cpp` が、
    **`reset_pin = -1` / `pwdn_pin = -1`、SCCB は `bsp_i2c_get_handle()` の
    共有 I2C(400 kHz)** で `esp_video_init()` → `/dev/video0`(`ESP_VIDEO_MIPI_CSI_DEVICE_NAME`)を
    `V4L2_PIX_FMT_RGB565` で open → `VIDIOC_REQBUFS`(MMAP、2 枚)→ `mmap` →
    `VIDIOC_STREAMON` → `DQBUF` → **PPA(SRM)で mirror_x → `lv_canvas_set_buffer(..., LV_COLOR_FORMAT_RGB565)`** → `QBUF`。
  出典: [M5Tab5-UserDemo sdkconfig](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/sdkconfig)、
  [hal_camera.cpp](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/main/hal/components/hal_camera.cpp)
- **`esp_video` 0.7.0 の CSI デバイスが受け付ける出力フォーマット**は
  `SBGGR8` / `SBGGR10` / `SBGGR12` / `RGB565` / `RGB24` / `YUV420` / `YUV422P`。
  **`V4L2_PIX_FMT_GREY` は CSI 経路では選べない**(ISP の出力に GREY が無い)。
  → グレースケールは「RAW8 をそのまま使う」か「RGB565 から自前で落とす」の 2 択(§4.2)。
  出典: [esp_video_csi_device.c(UserDemo が vendoring している 0.7.0)](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/components/esp_video/src/device/esp_video_csi_device.c)
- CSI のフレームバッファは **`MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM | MALLOC_CAP_CACHE_ALIGNED`**
  で確保される(= PSRAM)。内蔵 RAM を食うのはドライバ構造体程度
  (`heap_caps_calloc(1, sizeof(struct csi_video), MALLOC_CAP_INTERNAL)`)。出典: 同上。

### 2.3 MIPI PHY の電源(CSI と DSI の共存)

- ESP32-P4 の MIPI D-PHY は 2.5 V が要る。DSI も CSI も内蔵 LDO で供給する。
  `esp_video` の CSI デバイスは `CSI_LDO_UNIT_ID 3` / `CSI_LDO_CFG_VOL_MV 2500` で
  `esp_ldo_acquire_channel()` し、**ストリーム停止時に `esp_ldo_release_channel()`** する。
  出典: [esp_video_csi_device.c](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/components/esp_video/src/device/esp_video_csi_device.c)
- 本アプリが使っている **M5GFX の `Bus_DSI::init()` も `ldo_chan_id = 3` / `ldo_voltage_mv = 2500` で
  `esp_ldo_acquire_channel()`** している。
  出典(ローカル): `managed_components/m5stack__m5gfx/src/lgfx/v1/platforms/esp32p4/Bus_DSI.cpp:42-50`、
  `Bus_DSI.hpp:58-59`、`M5GFX.cpp:3041-3042`
- IDF の LDO ドライバは「**固定電圧チャネルはアプリの複数箇所から多重に acquire でき、
  内部で参照カウントされ、最後の解放でオフになる**。可変電圧チャネルは多重取得不可」。
  両者とも 2500 mV 固定で取るので**共存できる見込み**。
  出典: [ESP-IDF v5.4 LDO Regulator](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32p4/api-reference/peripherals/ldo_regulator.html)
- → **ゲート項目**: 「カメラ open / close を繰り返しても DSI パネルが落ちない」。

### 2.4 I2C(SCCB)の共存

- Tab5 の内部 I2C(GPIO31/32)は **タッチ(GT911/ST7123)/ IO エキスパンダ / 電源 / IMU /
  カメラ SCCB が相乗り**する 1 本のバス。
- 本アプリの I2C は **M5GFX が握っている**が、M5GFX は ESP-IDF の i2c ドライバを使わず
  `i2c_dev_t` を**レジスタ直叩き**しており、しかも **トランザクションの開始時に `load_reg()`、
  終了時に `save_reg()`** して「他のユーザと同じ I2C ペリフェラルを共有する」設計になっている
  (`i2c_temporary_switcher_t` も同じ思想)。
  出典(ローカル): `managed_components/m5stack__m5gfx/src/lgfx/v1/platforms/esp32/common.cpp:1278-1310`(save/load)、
  `:1600`(load_reg = beginTransaction)、`:1824,1987`(save_reg = endTransaction)
- `esp_video` 側は `esp_video_init_sccb_config_t` で
  **`init_sccb=false` + 既存の `i2c_master_bus_handle_t` を渡す**か、
  **`init_sccb=true` + `port/scl_pin/sda_pin`** を渡して自前でバスを作らせるかを選べる。
  出典: [esp_video_init.h](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/components/esp_video/include/esp_video_init.h)
- 本アプリには渡せる `i2c_master_bus_handle_t` が**無い**(M5GFX は IDF ドライバを使わないので
  ハンドルを公開していない)。→ `init_sccb=true` で **`i2c_master` バスを自前で作らせる**のが素直。
  M5GFX が毎トランザクションでレジスタを復元するので理屈上は共存するが、
  **`esp_ipa` が毎フレーム露出/ゲインを SCCB 書き込みする**と衝突確率が跳ね上がる。
  → **v1 は ISP/IPA を無効にして SCCB を初期化時のみに限定**する(§4.2)。

### 2.5 QR デコードライブラリ

| 候補 | 評価 |
| --- | --- |
| **`espressif/quirc` 1.2.0**(採用) | ISC ライセンス、**全 IDF ターゲット対応**、依存ゼロ、アーカイブ 70KB。C99。`quirc_new` / `quirc_resize` / `quirc_begin`(バッファを貰う)/ `quirc_end` / `quirc_count` / `quirc_extract` / `quirc_decode`。**入力は 1 バイト/px のグレースケールのみ** |
| Espressif `qrcode-demo` | **生成でなく認識**の公式サンプル。ESP32-S3-EYE + `esp32-camera` + `quirc` + LVGL。Apache-2.0。**「デコード ~3 ms、フレーム処理 22〜229 ms」**という実測値が README にある。P4(400MHz RISC-V ×2)ならこれ以上の余裕がある |
| `espressif/qrcode` | **生成専用**(Project Nayuki、MIT)。T9 で使っている `lv_qrcode` と用途が同じで、読取には使えない |
| **`esp-code-scanner`** | **一次情報で確認できず**。ESP Component Registry にも espressif GitHub にも該当なし。**候補から外す** |
| ZXing-C++ | **不適**。重い C++(例外 / RTTI / STL 多用)。本アプリは `CONFIG_COMPILER_CXX_EXCEPTIONS=n` / `CONFIG_COMPILER_CXX_RTTI=n` でビルドしており、そのままでは通らない。フラッシュ・RAM も桁違い |

出典: [components.espressif.com quirc](https://components.espressif.com/components/espressif/quirc)、
[espressif/qrcode-demo](https://github.com/espressif/qrcode-demo)、
[components.espressif.com qrcode](https://components.espressif.com/components/espressif/qrcode)、
[dlbeer/quirc](https://github.com/dlbeer/quirc)

**quirc のメモリ**(`lib/quirc.c` の `quirc_resize`):

- `image = calloc(w, h)` → **`w*h` バイト**
- `pixels` は既定設定(`QUIRC_MAX_REGIONS` < 255 → `quirc_pixel_t = uint8_t`)では
  **`image` にエイリアスされ追加確保なし**
- `flood_fill_vars = malloc(sizeof(vars) * (h*2/3))` → 数 KB
- `struct quirc_data` に `payload[QUIRC_MAX_PAYLOAD = 8896]` が含まれる(スタックに置かないこと)

→ 640×360 なら **約 230 KB**、1280×720 なら **約 900 KB**。
本アプリは `CONFIG_SPIRAM_USE_MALLOC=y` / `CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=16384` なので、
**quirc の `calloc` はそのまま PSRAM に落ちる**(閾値 16KB 超)。内蔵 RAM は消費しない。

### 2.6 コア側の既存資産(T9)

`crates/simple-matter/src/discovery/onboarding.rs` に**生成側が実装済み**:

- `OnboardingPayload { vendor_id, product_id, discriminator, passcode, discovery_caps }`
- `DISCOVERY_CAP_SOFT_AP = 1<<0` / `DISCOVERY_CAP_BLE = 1<<1` / `DISCOVERY_CAP_ON_NETWORK = 1<<2`
- `qr_payload()` — **ビット配置が既にコメントで確定**している:
  `version(3) ‖ VendorID(16) ‖ ProductID(16) ‖ commissioning flow(2) ‖
  discovery capabilities(8) ‖ discriminator(12) ‖ passcode(27) ‖ padding(4)` = 88 bit = 11 byte、
  リトルエンディアンのビットストリームを 3B→5 文字 / 2B→4 文字 / 1B→2 文字で base38 符号化
- `BASE38_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."`
- `manual_pairing_code()` + Verhoeff、`passcode_is_valid()`、`random_passcode()`、`random_discriminator()`
- **chip-tool 一致のテストベクタ**(`MT:-24J0AFN00KA0648G00` 等)がテストに入っている
  → **解析側はこのベクタを逆向きに流すだけでラウンドトリップ試験になる**

shim 側は `sm_ctrl_window_t { ... char manual_code[12]; char qr_payload[32]; }` /
`sm_ctrl_last_window()` があり(`crates/simple-matter-cffi/include/simple_matter.h:450-472, 818`)、
命名・構造体の作法はここに揃える。

---

## 3. 設計: 全体像

```
[SC202CS] --MIPI-CSI--> [esp_video /dev/video0, RAW8 1280x720, PSRAM x2]
                              |  DQBUF
                              v
                   +----------------------------+
                   | qr_scan タスク (core1)      |
                   |  1. 2x2 サブサンプル        |  -> 640x360 gray (PSRAM, 230KB)
                   |  2. quirc_begin/end/decode  |
                   |  3. "MT:" を見つけたら停止  |
                   |  4. 低頻度で L8 プレビュー  |--> sm_display_lock() + lv_canvas
                   +----------------------------+
                              | 読取成功(文字列)
                              v
                   sm_onboarding_parse()   <-- shim の純関数(コアの解析器)
                              |
                              v
              [UI: 確認カード(VID/PID/discriminator/経路)]
                              |  ユーザ確認
                              v
              sm_ui_op_t{ kind=PAIR_BLE, via=BLE_THREAD|BLE_WIFI,
                          discriminator, passcode, node_id } --> 既存 pump
```

新規ファイルは `main/camera_qr.cpp` / `camera_qr.hpp` の 2 本に閉じる。
**`sm_ctrl_*` / `ot_*` はこのファイルから呼ばない**(`display_gfx.cpp` と同じ契約)。
UI への通知はコールバックか `app_state` のスナップショット経由。

### 3.1 タスク配置

- 既存: LVGL タスク、`sm_ctrl` pump タスク(静的スタック 128KB)、OT、コンソール。
- 追加: `qr_scan` タスク 1 本(スタック 8KB、`xTaskCreatePinnedToCore(..., core 1)`)。
  UserDemo も core1 に 8KB で置いている。**スキャン画面を開いている間だけ生存**させ、
  閉じたら `STREAMOFF` → `close()` → `vTaskDelete`(LDO も解放される)。
- pump タスクとは**同時に走らせない**運用にできればなお安全だが、
  QR 読取中はコミッショニングが走っていないので実質競合しない。

---

## 4. 設計: 各層

### 4.1 カメラ初期化

```c
// camera_qr.cpp(擬似コード)
static esp_video_init_csi_config_t csi = {
  .sccb_config = { .init_sccb = true,
                   .i2c_config = { .port = <M5GFX と同じポート>, .scl_pin = 32, .sda_pin = 31 },
                   .freq = 400000 },
  .reset_pin = -1,   // Tab5 は RST 配線なし(BSP_CAMERA_RST = NC)
  .pwdn_pin  = -1,
};
static const esp_video_init_config_t cfg = { .csi = &csi, .dvp = NULL, .jpeg = NULL, .isp = NULL };
esp_video_init(&cfg);
int fd = open("/dev/video0", O_RDONLY);   // ESP_VIDEO_MIPI_CSI_DEVICE_NAME
// VIDIOC_S_FMT: V4L2_PIX_FMT_SBGGR8, 1280x720
// VIDIOC_REQBUFS(count=2, V4L2_MEMORY_MMAP) -> QUERYBUF -> mmap -> QBUF -> STREAMON
```

- **カメラ EN(IO エキスパンダ pin 6)**を先に HIGH にする。M5Unified の PI4IOE 初期化が
  既に全ピン出力 HIGH にしていれば何もしなくてよい(要実機確認)。していなければ
  `M5.getIOExpander(0)` 相当か `M5.In_I2C` で 0x43 のレジスタ 0x05 の bit6 を立てる。
- **`esp_video_init()` の呼び出し中は LVGL のタッチ読みを止める**(§5.2)。
  `display_gfx` に `sm_display_suspend_indev(bool)` を足すのが素直
  (`lv_indev_enable()` を LVGL タスク文脈で叩くか、read_cb の先頭でフラグを見て
  即 RELEASED を返すだけでもよい。既存の合成ポインタ機構と同じ作法)。

### 4.2 なぜ RAW8 + ISP/IPA 無効か

| 案 | 利点 | 欠点 |
| --- | --- | --- |
| **A: RAW8(SBGGR8)+ ISP/IPA 無効**(v1 採用) | quirc の入力そのもの(1B/px、変換ゼロ)。**ストリーミング中の SCCB が消える** → I2C 競合リスクが初期化時に限定。ISP/IPA/H264/JPEG をビルドから外せて **フラッシュ・ビルド時間が最小**。フレームバッファ 1280×720 = 900KB ×2 | **自動露出が効かない**(固定露出)。明暗差の大きい環境で読取率が落ちる。プレビューがモノクロ |
| B: RGB565 + ISP + IPA(UserDemo と同型) | 自動露出・自動ホワイトバランスが効く。プレビューが綺麗 | **毎フレーム SCCB 書き込み**が発生し M5GFX の I2C 直叩きと競合しうる。RGB565→gray の変換が 1 フレームあたり 92 万画素(PSRAM 読み)。バッファ 1.8MB ×2 |

v1 は A。**A で読取率のゲートを割ったら、B ではなく「自前の低頻度 AE」を先に試す**
(2 Hz くらいで平均輝度を見て `V4L2_CID_EXPOSURE` / `V4L2_CID_GAIN` を `VIDIOC_S_CTRL` する。
SCCB アクセスが 0.5 秒に 1 回なら競合確率は無視できる)。

### 4.3 グレースケール化

RAW8 は BGGR ベイヤ。**行・列を 1 つおきに取ると単一チャネル画像になる**:

```c
// src: 1280x720 SBGGR8 (stride 1280)。位相 (1,0) を取ると G(Gb) 面 = 640x360。
for (int y = 0; y < 360; ++y) {
  const uint8_t *s = src + (size_t)(2*y + 1) * 1280;   // 奇数行 = G B G B ...
  uint8_t *d = gray + (size_t)y * 640;
  for (int x = 0; x < 640; ++x) d[x] = s[2*x];         // 偶数列 = G
}
```

- 市松模様が消え、**quirc の二値化が素直に効く**。
- 作業量は 23 万画素の strided read。PSRAM でも数 ms。
- ROI を狭めたければ中央 640×360 のクロップに切り替えるだけ(コードは同型)。

`quirc_begin()` が返すバッファに直接この変換結果を書けば、**中間バッファは不要**。

### 4.4 プレビュー(LVGL)

- v1: 変換後の 640×360 グレースケールを `lv_canvas_set_buffer(canvas, gray, 640, 360,
  LV_COLOR_FORMAT_L8)` でそのまま表示。**追加のバッファ・変換ゼロ**。
  更新は 3〜5 fps に間引く(`sm_display_lock()` を長く握らない)。
  `CONFIG_LV_USE_CANVAS=y` は既に有効(`sdkconfig:3239`)。
  **L8 canvas が LVGL9 の描画経路で通ることは要実機確認**(通らなければ
  gray → RGB565 の 23 万画素変換を足す。それでも数 ms)。
- カメラは画面に対して **270° 回転**して実装されている(`BSP_CAMERA_ROTATION`)。
  **QR デコードは回転不変なので v1 は補正不要**。プレビューだけ気持ち悪いので、
  v2 で PPA(`ppa_do_scale_rotate_mirror`、UserDemo と同じ)で回転・ミラーする。
  なお UserDemo は `mirror_x = true` を掛けている。
- プレビューを出す枠は 1280×720 の中央に 640×360 のカード。周囲は既存 UI の作法
  (全画面半透明モーダル + カード、`open_pair_dialog` と同型)。

### 4.5 payload 解析(コア → shim → UI)

#### コア(`crates/simple-matter/src/discovery/onboarding.rs` に追加)

```rust
/// 解析結果。`OnboardingPayload` に「どこまで確からしいか」を足したもの。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedOnboarding {
    pub payload: OnboardingPayload,
    /// discriminator の有効ビット数。QR なら 12、manual code なら 4(short discriminator)。
    pub discriminator_bits: u8,
    /// commissioning flow(0 = Standard、1 = User-intent、2 = Custom)。
    pub commissioning_flow: u8,
    /// TLV 拡張(§5.1.5)が付いていたか(中身は解釈しない)。
    pub has_tlv: bool,
}

/// `"MT:"` + base38(§5.1.3)を解析する。前後の空白は無視する。
///
/// 88 ビットを超える分(TLV 拡張)は読み飛ばし、`has_tlv = true` にする。
/// 失敗: `Error::InvalidArgument`(prefix 不正 / base38 外の文字 / 長さ不足)。
pub fn parse_qr_payload(text: &[u8]) -> Result<ParsedOnboarding>;

/// 11 桁 manual pairing code(§5.1.4.1)を解析する。`-` と空白は無視する。
///
/// Verhoeff 検査数字を検証する。VID/PID 付き(21 桁)は今は未対応。
/// 得られる discriminator は**上位 4 ビットのみ**(`discriminator_bits = 4`)。
/// 失敗: `Error::InvalidArgument`。
pub fn parse_manual_pairing_code(text: &[u8]) -> Result<ParsedOnboarding>;

impl OnboardingPayload {
    pub const fn has_ble(&self) -> bool;
    pub const fn has_on_network(&self) -> bool;
    pub const fn has_soft_ap(&self) -> bool;
}
```

- `no_std` / ヒープ非依存のまま。既存の `BASE38_ALPHABET` と `verhoeff_check_digit` を再利用。
- テストは **既存ベクタのラウンドトリップ**(`qr_payload()` → `parse_qr_payload()` で元に戻る)と、
  `MT:-24J0AFN00KA0648G00` → `{vid:0xFFF1, pid:0x8001, disc:3840, passcode:20202021,
  caps:ON_NETWORK|BLE}` 相当の直値照合(chip-tool と一致していること)。
- 異常系: 文字数不足 / base38 外文字 / version != 0 / passcode が `passcode_is_valid()` を
  満たさない → エラー。**`passcode` の妥当性検査は解析側でも掛ける**(印刷ミス・誤読の弾き)。

#### shim(`crates/simple-matter-cffi`)

**スタック状態に一切触らない純関数**にする。UI タスクから直接呼べるので pump を経由しない。

```c
// 解析済みのオンボーディング情報(§5.1)。
typedef struct {
  uint16_t vendor_id;          // 取れなければ 0
  uint16_t product_id;         // 取れなければ 0
  uint16_t discriminator;      // 12 ビット(manual code 由来なら上位 4 ビットのみ有効)
  uint8_t  discriminator_bits; // 12 = QR / 4 = manual code
  uint32_t passcode;           // 27 ビット
  uint8_t  discovery_caps;     // bit0=SoftAP bit1=BLE bit2=on-network
  uint8_t  commissioning_flow; // 0=Standard
  uint8_t  has_tlv;            // 1 = TLV 拡張付き(中身は未解釈)
} sm_onboarding_t;

// "MT:..." でも 11 桁 manual pairing code でも受ける(先頭 3 文字で判別)。
// 戻り値: 0=OK、-5=解析失敗。スタック初期化は不要(純関数)。
int32_t sm_onboarding_parse(const char *text, sm_onboarding_t *out);
```

`sm_ctrl_window_t` と対称な形にしてある(payload を「作る」のが T9、「読む」のがこれ)。

### 4.6 既存コミッショニング導線への接続

既存(`main/app_state.hpp`):

```
SM_UI_OP_PAIR      (via = SM_UI_VIA_THREAD | SM_UI_VIA_WIFI)      … on-network PASE、ipv6 手入力
SM_UI_OP_PAIR_BLE  (via = SM_UI_VIA_BLE_WIFI | SM_UI_VIA_BLE_THREAD) … discriminator + passcode
```

**QR から取れるのは discriminator / passcode / VID / PID / discovery caps だけ**。
`NodeId` も「入れるネットワークの種別」も QR には入っていない。ここが設計の肝。

#### 経路の決定表

| discovery caps | 既定の経路 | 備考 |
| --- | --- | --- |
| BLE(bit1)あり | **`SM_UI_OP_PAIR_BLE`**。`via` は「Tab5 の Thread が上がっていれば `BLE_THREAD`、そうでなければ `BLE_WIFI`」を**プリセット**し、確認カードで 2 択トグルを見せる | **自動判定は原理的に不可能**。caps は「デバイスをどう見つけるか」であって「どのネットワークに入れるか」ではない。VID/PID からの推定もしない(誤爆する) |
| on-network(bit2)のみ | v1: **非対応**として「on-network の QR です。IP を入力してください」と表示し、既存フォームに passcode だけ入れて返す | 本来は `_matterc._udp` の `_L<discriminator>` サブタイプを browse してアドレスを引く。コアに `discovery` クライアント(commissionable browse)はあるが shim 未公開。**v2 の課題**(§6) |
| SoftAP(bit0)のみ | **エラー**。「SoftAP コミッショニングは非対応」 | Tab5 の WiFi は C6 経由の STA 専用(§10) |
| 複数立つ | BLE を優先 | 実機の大半は `BLE | on-network` |

#### v2 での自動化(推奨)

BLE 接続後、**PASE 確立直後に `NetworkCommissioning`(0x0031)の `FeatureMap` を read** すれば
デバイスが WiFi(bit0)/ Thread(bit1)/ Ethernet(bit2)のどれを持つか分かる。
これで `via` のユーザ選択を消せる。pump 側(`ctrl_pump.cpp:1938` 付近で `via` から
資格情報の種別を決めている箇所)に分岐を足す形になる。

#### NodeId

QR には無いので**自動採番**する。`node_book` の既存最大 + 1(または未使用の最小値)を
既定にし、確認カードで手編集できるようにする。既存 pair ダイアログの `ta_node` は
そのまま残す(QR 経路では初期値が埋まっているだけ)。

### 4.7 UI フロー

1. Devices タブのツールバー `Pair new device`(`ui.cpp:1293`)→ 既存 pair ダイアログ。
2. そこに **`Scan QR` ボタン**を 1 つ足す(`make_button` の作法どおり)。
3. 押下 → `open_qr_scan_dialog()`:全画面モーダル + 640×360 プレビュー canvas +
   ステータスラベル + `Cancel`。同時に `camera_qr_start()`。
4. `qr_scan` タスクが `MT:` を読んだら
   → `camera_qr_stop()`(STREAMOFF/close/LDO 解放)
   → UI に文字列を渡す(`lv_async_call` かフラグ + `refresh_*` の既存周期処理)。
5. `sm_onboarding_parse()` → 確認カード:
   `Vendor 0xFFF1 / Product 0x8001 / discriminator 3840 / passcode ****`、
   経路トグル `BLE→Thread` / `BLE→WiFi`、NodeId(自動採番済み)、`Start` / `Cancel`。
6. `Start` → 既存 `on_pair_start` と同じ経路で `sm_ui_op_t` を post。
   以降の進捗表示(`refresh_pair_dialog`、`SM_UI_BLE_*`)は**一切変更不要**。

**passcode は画面に出さない**(伏せ字)。T5 のスクリーンショット機能でログに残るため。

### 4.8 T5(デバッグ自動化)との整合

`console_dbg.cpp` に以下を足すとゲート測定が自動化できる(§13.1 の 3 層目):

- `qrscan start` / `qrscan stop` — カメラの起動・停止
- `qrscan status` — 直近の読取文字列 / 試行フレーム数 / 平均デコード時間
- `qrpayload <MT:...>` — **カメラを介さず**文字列を `sm_onboarding_parse()` に流し、
  経路決定まで走らせる(パーサと UI 結線の回帰試験がカメラ無しでできる)

---

## 5. リスク

### 5.1 MIPI DSI と CSI の共存(**最大のリスク**)

- 症状候補: カメラ open で画面が黒くなる / カメラ close で画面が落ちる / どちらかの
  `esp_ldo_acquire_channel()` が `ESP_ERR_NOT_FOUND` を返す。
- 根拠と見込みは §2.3。**固定電圧チャネルの多重取得は IDF が明示的に許している**ので
  通る見込みが高い。ただし `Bus_DSI` は起動時 1 回 acquire、CSI は open/close ごとに
  acquire/release する非対称な使い方になる。
- **P4 の VDD_MIPI_DPHY は最大 50 mA**。DSI PHY + CSI PHY を同時に食わせる余裕があるかは
  ハードウェア設計ガイドライン上の懸念事項として残る(Tab5 は両方載せている基板なので
  設計上は想定内のはず)。
- **緩和**: それでも駄目なら「カメラ使用中は DSI を落とす」は成立しない(プレビューが出せない)ので、
  **静止画 1 枚方式(v1)ですらブロッカー**になる。**最優先で単体スパイクを打つこと**(§6 の P0)。

### 5.2 I2C の共存

- 根拠は §2.4。**M5GFX がトランザクション毎にレジスタを退避・復元する**設計なので、
  IDF `i2c_master` と同一ポートを共有しても理屈上は動く。
- **緩和 1**: ISP/IPA を無効にして SCCB を初期化時のみに限定(§4.2 の案 A)。
- **緩和 2**: `esp_video_init()` の前後で LVGL のタッチ読みを止める(§4.1)。
- **緩和 3**: それでも化けるなら、SCCB を**別の I2C ポート**(P4 の GPIO マトリクス経由で
  同じ GPIO31/32 に I2C1 を割り付ける)にして、M5GFX(I2C0)とパッドだけ共有し、
  ソフト側でミューテックス排他する。汚いが確実。

### 5.3 メモリ

Tab5 は **32MB PSRAM / 16MB flash**、内蔵 SRAM は 768KB。

| 用途 | 量 | 置き場 |
| --- | --- | --- |
| CSI フレームバッファ 1280×720 RAW8 ×2 | 1.8 MB | PSRAM(`CSI_MEM_CAPS`) |
| quirc 640×360 | 約 230 KB | PSRAM(`calloc` > 16KB 閾値) |
| `struct quirc_data`(payload 8896B) | 約 9 KB | **静的 or ヒープ。スタックに置かない** |
| プレビュー(L8 なら追加ゼロ / RGB565 なら) | 0 〜 460 KB | PSRAM |
| 既存 LVGL 描画バッファ | 約 360 KB | PSRAM(既存) |
| 既存 pump 静的スタック | 128 KB | 内蔵 |
| 追加の内蔵 RAM(esp_video ドライバ構造体 / DMA descriptor / タスクスタック 8KB) | 十数 KB | 内蔵 |

→ **PSRAM は余裕。内蔵 RAM の増分も十数 KB で、Matter スタック(OT/lwIP/mbedTLS)を
圧迫しない**。RGB565 720p 経路(案 B)に行っても PSRAM 3.6MB で足りる。

### 5.4 スループット / 読取率

- 参考値: Espressif の `qrcode-demo`(ESP32-S3)で**デコード 約 3 ms、フレーム処理 22〜229 ms**。
  P4 は 400 MHz デュアル RISC-V で S3 より速いが、**画像を PSRAM に置く分キャッシュミスが増える**。
  640×360 で **50〜150 ms/frame(6〜20 fps 相当)** を見込む。QR をかざす用途には十分。
- 読取率を落とす要因: 固定露出(§4.2)、手ブレ、5 インチ画面に映る自分の UI の映り込み、
  小さく印刷された QR(Matter デバイスの QR は数 mm 角のことがある)。
- **ROI を中央に絞る + 「枠内に合わせてください」のガイド**を UI に描くのが効く。
- Matter の QR は **`MT:` + base38 19 文字 = 22 文字**と短い(version 1〜2 の小さな QR)。
  デコード自体は軽い。

### 5.5 ライセンス

| component | ライセンス | 判断 |
| --- | --- | --- |
| `espressif/quirc` | ISC(dlbeer/quirc 由来) | 問題なし。permissive |
| `espressif/esp_cam_sensor` | Apache-2.0 | 問題なし |
| `espressif/esp_video` | **ESPRESSIF MIT**(Espressif 製品上での利用に限る) | Tab5 = ESP32-P4 上でしか使わないので条件を満たす。**リポジトリ本体(Boost)には取り込まず、`idf_component.yml` の managed component のまま**にすること |
| `espressif/esp_ipa` | Espressif 系(案 A なら不要) | 案 A では依存に入らない可能性がある。入るなら esp_video と同条件 |

**方針**: どれも `managed_components/` に降ってくる形のままにし、
`crates/` にも `ports/esp-idf/components/` にもコピーしない。
`ports/esp-idf/examples/tab5_ctrl_app/README.md` に出典とライセンスを 1 段落追記する。

### 5.6 ビルド時間 / フラッシュ

- 追加 component は `esp_video` + `esp_cam_sensor`(SC202CS だけ有効化)+ `quirc`
  (+ 案 B なら `esp_ipa` / `esp_h264`)。
- **フルビルドの増分は 2〜4 分程度**の見込み(`esp_cam_sensor` は Kconfig で
  SC202CS 以外のセンサをすべて落とすこと。既定で多数のドライバが入る)。
- バイナリ増分: 案 A で **+150〜250 KB**、案 B(ISP/IPA/H264/JPEG)で **+400〜600 KB**。
  現状 2.32 MB / 4 MB パーティション(`partitions.csv`)なので**どちらでも余裕**。
- `sdkconfig.defaults` に足す項目(案 A):
  ```
  CONFIG_CAMERA_SC202CS=y
  CONFIG_CAMERA_SC202CS_AUTO_DETECT=y
  CONFIG_CAMERA_SC202CS_AUTO_DETECT_MIPI_INTERFACE_SENSOR=y
  CONFIG_CAMERA_SC202CS_MIPI_RAW8_1280x720_30FPS=y
  CONFIG_ESP_VIDEO_ENABLE_MIPI_CSI_VIDEO_DEVICE=y
  CONFIG_ESP_VIDEO_ENABLE_ISP=n
  CONFIG_ESP_VIDEO_ENABLE_ISP_VIDEO_DEVICE=n
  CONFIG_ESP_VIDEO_ENABLE_ISP_PIPELINE_CONTROLLER=n
  CONFIG_ESP_VIDEO_ENABLE_DVP_VIDEO_DEVICE=n
  CONFIG_ESP_VIDEO_ENABLE_HW_JPEG_VIDEO_DEVICE=n
  CONFIG_ESP_VIDEO_ENABLE_HW_H264_VIDEO_DEVICE=n
  ```
  **既知の罠(§9.3 の罠 7 / メモリ)**: `sdkconfig` が既にあると `sdkconfig.defaults` の
  変更が反映されない。`rm -f sdkconfig` してから `set-target` し直すこと。
  かつ **`SDKCONFIG_DEFAULTS` に `sdkconfig.local` も必ず含める**(WiFi OFF FW を防ぐ)。
  Rust 側を触ったら `target/<triple>/release/libsimple_matter_cffi.a` を消してから docker ビルド。

### 5.7 その他

- **QR の読取は「認証」ではない**。QR を読めた = そのデバイスをコミッショニングしてよい、
  ではある(物理的に手元にある証拠)が、**画面に映った他人の QR を誤って読む**事故はある。
  → 必ず**確認カードを挟む**(§4.7 の 5)。自動で pair を始めない。
- **カメラのプライバシー**。スキャン画面を閉じたら必ず `STREAMOFF` + `close()` し、
  ステータスバー等に「カメラ動作中」の表示を出す。
- **T8 の購読 pump との干渉**。QR スキャン中も pump は回り続ける(購読レポート処理)。
  `sm_display_lock()` を長時間握らないこと(プレビュー更新は 3〜5 fps に間引く)。
  未解決の「Tab5 pump の間欠停止」との切り分けを難しくしないため、
  **カメラ機能は既定 OFF の Kconfig(`CONFIG_TAB5_QR_SCAN`)**にしておくのが安全。

---

## 6. 段階計画と工数見積り

### P0(スパイク、0.5 日)— **ゲートを兼ねる**

**カメラと DSI が共存できるかだけを見る。** 既存アプリのブランチで、
コンソールコマンド `qrscan start/stop` から `esp_video_init()` → open → STREAMON →
DQBUF を 10 回 → STREAMOFF → close を回す。UI は一切触らない。

- ゲート G0-1: **カメラ open 中も LVGL 画面が正常に描画される**(DSI が落ちない)。
- ゲート G0-2: **カメラ close 後もタッチが効く**(I2C が壊れない)。
- ゲート G0-3: DQBUF が 30 fps 相当で回り、フレームの平均輝度が照明の on/off に追従する。

**ここで落ちたら §5.1 / §5.2 の緩和策を順に試す。全部駄目なら本機能は不成立**
(その場合は「スマホで読んで manual code を Tab5 に打つ」に退避)。

### v1(静止画 1 枚デコード、2〜3 日)

- コア: `parse_qr_payload` / `parse_manual_pairing_code` + ラウンドトリップテスト(0.5 日)
- shim: `sm_onboarding_parse()`(0.25 日)
- `main/camera_qr.cpp`: カメラ起動 → RAW8 → 2×2 サブサンプル → quirc(1 日)
- UI: `Scan QR` ボタン + スキャン画面(静止画。「Capture」を押した 1 枚だけデコード)+
  確認カード + 既存 op への post(1 日)
- コンソール: `qrscan` / `qrpayload`(0.25 日)

**ゲート G1**:
1. `qrpayload MT:-24J0AFN00KA0648G00` が `vid=0xFFF1 pid=0x8001 disc=3840 passcode=20202021
   caps=BLE|on-network` を出す(chip-tool と一致)。
2. 実機で NanoC6 / AirQ の QR を **10 回中 8 回以上**(明るい室内、10〜20 cm)で読める。
3. QR 読取 → 確認 → `BLE-Thread` で NanoC6 のコミッショニングが**手入力なしで完了**する
   (T3 の E2E と同じ終端)。
4. スキャン画面を 20 回開閉しても画面・タッチ・pump が壊れない。

### v2(ライブプレビュー + 経路自動判定、2〜3 日)

- 連続デコード(3〜10 fps)+ 枠ガイド + 読取時のフィードバック(枠が緑 + 短いビープ)
- PPA で回転 270° / mirror(UserDemo と同型)。必要なら ISP + RGB565 に切替
- 低頻度 AE(§4.2)で暗所・逆光の読取率を上げる
- **`NetworkCommissioning::FeatureMap` read による `via` 自動判定**(§4.6)
- on-network 専用 QR: `_matterc._udp` の `_L<discriminator>` browse
  (コアの discovery クライアントを shim に出す)

**ゲート G2**: 読取率 10 回中 9 回以上、読取までの体感 2 秒以内、`via` の手選択が消える。

### 合計

**P0 0.5 日 + v1 2〜3 日 + v2 2〜3 日 = 5〜7 日**(実機検証込み、1 人)。
**P0 が最大の不確実性**であり、ここを最初に潰すこと。

---

## 7. 変更予定ファイル(実装時)

| ファイル | 変更 |
| --- | --- |
| `crates/simple-matter/src/discovery/onboarding.rs` | `parse_qr_payload` / `parse_manual_pairing_code` / `ParsedOnboarding` / caps ヘルパ + テスト |
| `crates/simple-matter-cffi/src/controller.rs`(または新規 `onboarding.rs`) | `sm_onboarding_parse()` |
| `crates/simple-matter-cffi/include/simple_matter.h` | `sm_onboarding_t` / `sm_onboarding_parse` |
| `ports/esp-idf/examples/tab5_ctrl_app/main/camera_qr.{cpp,hpp}` | **新規**。カメラ + quirc |
| `.../main/ui.cpp` | `Scan QR` ボタン、スキャン画面、確認カード |
| `.../main/display_gfx.{cpp,hpp}` | `sm_display_suspend_indev()`(カメラ初期化中のタッチ停止) |
| `.../main/console_dbg.cpp` | `qrscan` / `qrpayload` |
| `.../main/idf_component.yml` | `espressif/esp_video` / `espressif/esp_cam_sensor` / `espressif/quirc` |
| `.../sdkconfig.defaults` | §5.6 の Kconfig |
| `.../main/Kconfig.projbuild` | `CONFIG_TAB5_QR_SCAN`(既定 OFF) |
| `.../README.md` | 依存 component の出典・ライセンス |
| `docs/design/p4-thread-controller.md` | §18 として本機能の実装記録を追記 |

---

## 8. 出典一覧

- [M5Stack Tab5 製品ページ](https://shop.m5stack.com/products/m5stack-tab5-iot-development-kit-esp32-p4)
- [m5-docs Tab5](https://docs.m5stack.com/en/core/Tab5)
- [espressif/esp-bsp bsp/m5stack_tab5 README](https://github.com/espressif/esp-bsp/blob/master/bsp/m5stack_tab5/README.md)
- [espressif/esp-bsp bsp/m5stack_tab5 ピン定義](https://github.com/espressif/esp-bsp/blob/master/bsp/m5stack_tab5/include/bsp/m5stack_tab5.h)
- [m5stack/M5Tab5-UserDemo](https://github.com/m5stack/M5Tab5-UserDemo)
  - [platforms/tab5/sdkconfig](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/sdkconfig)
  - [platforms/tab5/main/hal/components/hal_camera.cpp](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/main/hal/components/hal_camera.cpp)
  - [components/esp_video/src/device/esp_video_csi_device.c](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/components/esp_video/src/device/esp_video_csi_device.c)
  - [components/esp_video/include/esp_video_init.h](https://github.com/m5stack/M5Tab5-UserDemo/blob/main/platforms/tab5/components/esp_video/include/esp_video_init.h)
- [ESP Component Registry: espressif/esp_video](https://components.espressif.com/components/espressif/esp_video)
- [esp_video 2.4.1 license.txt(ESPRESSIF MIT)](https://components-file.espressif.com/components/espressif/esp_video/2.4.1/license.txt)
- [ESP Component Registry: espressif/esp_cam_sensor](https://components.espressif.com/components/espressif/esp_cam_sensor)
- [esp-video-components 開発リファレンス(ESP32-P4)](https://docs.espressif.com/projects/esp-video-components/en/latest/esp32p4/index.html)
- [ESP-IDF v5.4 LDO Regulator(ESP32-P4)](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32p4/api-reference/peripherals/ldo_regulator.html)
- [ESP-IDF Camera Controller Driver(ESP32-P4)](https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/api-reference/peripherals/camera_driver.html)
- [ESP Component Registry: espressif/quirc](https://components.espressif.com/components/espressif/quirc)
- [dlbeer/quirc(本家、ISC)](https://github.com/dlbeer/quirc)
- [espressif/qrcode-demo(quirc + カメラの公式作例、性能値の出典)](https://github.com/espressif/qrcode-demo)
- [ESP Component Registry: espressif/qrcode(生成専用、MIT)](https://components.espressif.com/components/espressif/qrcode)

ローカル参照(このリポジトリ / managed_components):

- `crates/simple-matter/src/discovery/onboarding.rs`(生成側、T9)
- `crates/simple-matter-cffi/include/simple_matter.h:450-472, 795-820`(`sm_ctrl_window_t`)
- `ports/esp-idf/examples/tab5_ctrl_app/main/app_state.hpp:22-52`(op / via の定義)
- `ports/esp-idf/examples/tab5_ctrl_app/main/ui.cpp:264-522, 1108-1140`(pair ダイアログ)
- `ports/esp-idf/examples/tab5_ctrl_app/main/display_gfx.cpp`(LVGL ポート、合成ポインタ)
- `managed_components/m5stack__m5gfx/src/lgfx/v1/platforms/esp32p4/Bus_DSI.cpp:42-50`(DSI の LDO)
- `managed_components/m5stack__m5gfx/src/lgfx/v1/platforms/esp32/common.cpp:1278-1310, 1600, 1824`(I2C の save/load_reg)

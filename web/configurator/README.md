# Web Configurator(Phase E)

汎用 Matter ファームウェア(`ports/esp-idf/examples/generic_matter_cpp`)の
**構成 → 個体プロビジョニング → 書き込み**をブラウザ 1 枚で行う静的サイト。
仕様は `docs/design/generic-firmware.md` §6.3 / §9.5。

- **ビルドステップなし**。ES modules を素で読むだけ(バンドラ・トランスパイラ不要)。
- **CDN 参照なし**。依存は `vendor/` に同梱。
- **すべてクライアントサイド**。passcode / 秘密鍵はネットワークに出ない。

## 使い方

```bash
# リポジトリのルートで
python3 -m http.server 8000
# → http://localhost:8000/web/configurator/ を Chrome / Edge で開く
```

- **Chrome / Edge 系限定**(書き込みに Web Serial API を使う)。Firefox / Safari では
  構成・個体情報・QR の生成とダウンロードまでは動くが、書き込みボタンは使えない。
- `file://` では ES module と WebCrypto が制限されるので **HTTP で配信**すること
  (`http://localhost` は secure context 扱いなので `crypto.subtle` が使える)。

## 画面の流れ

| 節 | 内容 | 出力 |
|---|---|---|
| ① 構成 | プリセット / エンドポイント / クラスタ / バインディング編集 | `comp` / `bind` TLV(§9.1 / §9.2)+ `nvs` パーティション(0x9000、namespace `smgen`) |
| ② 個体情報 | discriminator / passcode / salt 生成 → SPAKE2+ verifier | mfg_tool 互換 factory NVS(0x290000) |
| ③ オンボーディング | QR(`MT:` Base38)+ Manual Pairing Code(Verhoeff)+ 印刷 | ラベル |
| ④ スクリプト | `.wasm` → SMWS イメージ | `smscript` slot A/B(0x296000 / 0x2B6000) |
| ⑤ 書き込み | esptool-js(Web Serial)で一括 flash | — |

オフセットは `ports/esp-idf/examples/generic_matter_cpp/partitions.csv` と一致させてある
(`test/flash.test.js` が CSV を読んで突き合わせる)。bootloader のオフセットは
接続後に検出したチップ名から決める(C6/H2/S3/C3 = 0x0、ESP32/S2 = 0x1000、P4/C5 = 0x2000)。

### 実機フロー

1. `generic_matter_cpp` をビルドして `build/bootloader/bootloader.bin` /
   `build/partition_table/partition-table.bin` / `build/generic_matter_cpp.bin` を用意する
   (または ⑤ の URL 欄に Release asset の URL を入れる)。
2. ①で構成を、②で個体情報を作る(「verifier と factory NVS を生成」を押す)。
3. ⑤で接続 → 書き込み → デバイスをリセット。
4. ③の QR をスマホの Matter アプリで読むか、`smctl` でコミッショニングする:

   ```bash
   cargo run -p smctl -- pairing ble-wifi <passcode> <discriminator> <ssid> <pass>
   # または既にネットワーク上にいるなら
   cargo run -p smctl -- pairing onnetwork <passcode>
   ```

### 注意: DAC を入れないと factory データは無視される

`generic_matter_cpp` の factory ローダ(`main/main.cpp`)は
`dac-cert` / `pai-cert` / `dac-key` が**揃わないと factory データ全体を捨てて**
dev 資格情報(discriminator 3840 / passcode 20202021)にフォールバックする。
そのため ② の既定は「同梱の開発用テスト DAC」(`js/dev-dac.js`)になっている。

同梱 DAC は `crates/simple-matter/tests/fixtures/factory-fff1-8001.bin` に入っている
**公開のテスト鍵**(VID=0xFFF1 / PID=0x8001 固定)。開発・自家用限定で、製品では
CSA 発行 CD と製品 PAI で焼き分けること(§8 R-G5)。VID/PID を変えるときは
自前の DAC 一式(`dac.der` / `pai.der` / `dac_key.bin`)を「ファイル指定」で渡す。

### 注意: 設定 NVS を焼くと commissioning データが消える

`nvs`(0x9000)にはコア KVS(namespace `smatter` = fabric / ACL)と設定 blob
(namespace `smgen`)が同居している。①で作る NVS イメージは `smgen` だけを含むので、
書き込むと **factory reset 相当**になる。構成変更時はそれが望ましい(§8 R-G1)。
構成を変えずに再書き込みしたいだけなら ⑤ の「設定 NVS」チェックを外す。

### 注意: URL 取得は CORS 次第

GitHub Release の asset(`objects.githubusercontent.com`)はブラウザからの
クロスオリジン `fetch` に必要な CORS ヘッダを返さないことがある。失敗したら
ダウンロードしてローカルファイル指定に切り替える(UI にもその旨を出す)。

## vendor(同梱依存)

`npm install` はスクラッチパッドで行い、**必要な成果物だけ**をコピーした
(`node_modules` はリポジトリに入れない)。

| ディレクトリ | 版 | 取得元 | ファイル | サイズ |
|---|---|---|---|---|
| `vendor/esptool-js/` | 0.6.1 | `npm i esptool-js` → `node_modules/esptool-js/bundle.js` | `esptool-js.bundle.js` + `LICENSE`(Apache-2.0) | 218,551 B |
| `vendor/noble/` | @noble/curves 2.3.0(+ @noble/hashes 2.3.0) | `npm i @noble/curves` → 下記 esbuild で単一 ESM 化 | `noble-p256.js` + `LICENSE`(MIT) | 39,665 B |
| `vendor/qrcode-generator/` | 2.0.4 | `npm i qrcode-generator` → `node_modules/qrcode-generator/dist/qrcode.mjs` | `qrcode.mjs` + `LICENSE`(MIT) | 51,907 B |

**vendor 合計 322,597 B(約 315 KiB)**、サイト全体(js/css/test/vendor 込み)445 KiB。

- `esptool-js` の `bundle.js` は rollup 済みの **自己完結 ESM**(pako / tslib / atob-lite と
  **全チップの flasher stub JSON を内包**)。追加の import map もフェッチも不要。
- `@noble/curves` は `nist.js` から frost / oprf / hash-to-curve / @noble/hashes まで
  bare specifier で辿るため、そのままではブラウザで読めない。P-256 だけを
  esbuild で 1 ファイルに固めた:

  ```bash
  echo 'export { p256 } from "@noble/curves/nist.js";' > noble-entry.js
  npx esbuild@0.28.2 noble-entry.js --bundle --format=esm --minify \
      --legal-comments=none --outfile=vendor/noble/noble-p256.js
  ```

### AssemblyScript(asc)は Phase E' に分離した

ブラウザ内コンパイルには `assemblyscript` 本体(asc.js 880 KB + assemblyscript.js 756 KB)
に加えて **binaryen の `index.js` が 13.6 MB**、さらに `long` と AssemblyScript の
stdlib(約 1 MB)が要る。合計 **約 16 MB** で、リポジトリに同梱すると本体
(vendor 315 KiB)の 50 倍になる。**本フェーズでは同梱しない**判断とし、④ は

- `.wasm` ファイルのアップロード → SMWS イメージ化 → 書き込み対象に追加
- AssemblyScript の下書きエディタ(`.ts` としてダウンロード。コンパイルはしない)

に留めた。ローカルでのコンパイル手順は ④ のエディタ内コメントに入れてある。
将来 Phase E' で入れるなら「別ページ + 遅延 import + Cache Storage」で、
初回アクセス時にだけ取得する形が現実的(それでも CDN 禁止方針との調整が要る)。

## テスト

```bash
node --test web/configurator/test/          # 35 tests
cargo test -p simple-matter --features factory-data,rustcrypto factory
```

| テスト | 何を検証するか | 突き合わせ先 |
|---|---|---|
| `test/tlv.test.js` | `comp` / `bind` TLV hex | `scripts/smgen-tlv.py examples`(埋め込みベクタ + 実行時比較 + decode 往復) |
| `test/spake2p.test.js` | SPAKE2+ verifier(w0‖L) | `cargo run -p smctl -- pase-verifier`(4 ベクタ埋め込み + 実行時比較) |
| `test/onboarding.test.js` | QR payload / Base38 / MPC / Verhoeff | 公知ベクタ `MT:-24J0AFN00KA0648G00` / `34970112332` |
| `test/nvs.test.js` | NVS ライタ | `esp-matter-mfg-tool` 実生成物 `factory-fff1-8001.bin` を**バイト単位で完全再現** |
| `test/smscript.test.js` | SMWS イメージ | `scripts/smscript-img.py pack` / `show` |
| `test/flash.test.js` | オフセット表 | `generic_matter_cpp/partitions.csv` |
| `factory/tests.rs::web_configurator_*` | JS 生成 NVS を Rust パーサが読めること | `tools/gen-test-fixture.js` の生成物 |

Rust 側フィクスチャの再生成:

```bash
node web/configurator/tools/gen-test-fixture.js
# → crates/simple-matter/tests/fixtures/factory-webconfig.bin
```

`node --test` に**ディレクトリ**を渡せるのは Node 22 以降。それ未満(手元は v21.7.1)では
`test/index.js` がディレクトリ解決の入口になって全テストを import する。
個別に走らせたいときは `node --test web/configurator/test/*.test.js`。

## ブラウザ実操作のチェックリスト(ユーザ確認事項)

自動テストで担保できるのは「生成物のバイト列」まで。以下は実機・実ブラウザでの確認が要る。

- [ ] Chrome / Edge で `http://localhost:8000/web/configurator/` を開き、コンソールにエラーが出ない。
- [ ] 「シリアルポートに接続」でポート選択ダイアログが出て、チップ名(例 `ESP32-C6`)がログに出る。
- [ ] 書き込みプランのオフセットが `partitions.csv` と一致している(bootloader は検出チップ依存)。
- [ ] 「書き込む」で bootloader / partition-table / app / factory NVS / 設定 NVS が全て成功する。
- [ ] リセット後、シリアルログに `factory: loaded VID=... discriminator=<生成値>` が出る
      (dev 資格情報へのフォールバックログが出ていないこと)。
- [ ] ③ の QR をスマホの Matter アプリで読み取ってコミッショニングできる。
- [ ] `smctl pairing ble-wifi <passcode> <discriminator> ...` でコミッショニングできる。
- [ ] ①で構成を変えて焼き直すと、`descriptor` の DeviceTypeList / ServerList が変わる
      (例: プリセット① → ②で EP2 に温湿度が生える)。
- [ ] ④で `.wasm` を焼いた場合、起動ログに WASM ロード成功が出る。
- [ ] 「ラベルを印刷」で QR と Manual Pairing Code だけが印刷される。

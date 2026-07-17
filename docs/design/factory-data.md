# 工場出荷データ(factory data)対応

connectedhomeip / esp-matter の製造フロー(`esp-matter-mfg-tool`)と互換の工場データ
供給を simple-matter に実装する。デバイス固有の DAC(Device Attestation Certificate)・
PAI・DAC 秘密鍵・SPAKE2+ verifier・discriminator・VID/PID を、コードに埋め込まず
**工場データパーティション / ファイル / C API から供給**できるようにする。

- 目標: `mfg_tool` が発行した passcode / discriminator / DAC で simple-matter デバイスが
  コミッショニングでき、**attestation の実検証(mfg 発行 PAA を信頼ストアに)が通る**。
- 既存の dev 資格情報(`TestDacProvider` / `dev_pase`)は残し、**未供給時は従来動作**
  (後方互換)。
- 実装は 2 フェーズ: **FD1**(DAC 供給の一般化 + C FFI の口)/ **FD2**(mfg NVS リーダ)。

関連: `docs/design/attestation.md`(DAC チェーン + CD CMS 検証)、
`docs/design/c-ffi-shim.md`(sm_config_t)、`dba8b09`(PASE verifier 外部供給統一)。

---

## 1. mfg_tool 調査結果(実生成物で裏取り)

`esp-matter-mfg-tool` 1.0.24 を venv に導入し、テスト PAA(自己署名 P-256、CA:TRUE、
100 年有効)を渡して 1 個生成した:

```text
esp-matter-mfg-tool -v 0xFFF1 -p 0x8001 --vendor-name SimpleMatter --product-name OnOffLight \
  --passcode 20202021 --discriminator 3840 --hw-ver 1 --hw-ver-str HW1 \
  --serial-num SM-ONOFF-0001 --paa -c paa_cert.pem -k paa_key.pem --outdir out
```

生成物: factory NVS パーティション(`*-partition.bin`、24 KiB)+ DAC/PAI(mfg 生成、
PAA 署名)+ DAC 秘密鍵 + QR/manual code。

### 1.1 `chip-factory` namespace のキー一覧

パーティションは ESP-IDF NVS 形式(平文)。namespace は **`chip-factory`**。実生成物を
Python でパースして確定したキーと型:

| キー | NVS 型 | 値 | 備考 |
|------|--------|----|------|
| `discriminator` | u32 | 3840 | 12 ビット |
| `iteration-count` | u32 | 10000 | SPAKE2+ PBKDF2 |
| `salt` | **str(base64)** | 32 B へデコード | `SZ` 型に base64 テキストを格納 |
| `verifier` | **str(base64)** | 97 B へデコード | `w0‖L`(32+65) |
| `vendor-id` | u32 | 0xFFF1 | |
| `product-id` | u32 | 0x8001 | |
| `vendor-name` / `product-name` | str | | |
| `hardware-ver` | u32 / `hw-ver-str` str | | |
| `serial-num` | str | | |
| `dac-cert` | blob | 518 B | X.509 DER |
| `pai-cert` | blob | 466 B | X.509 DER |
| `dac-key` | blob | 32 B | 生 P-256 スカラ(BE) |
| `dac-pub-key` | blob | 65 B | SEC1 非圧縮(検証用) |
| `cert-dclrn` | blob | (任意) | CD。`-cd` 指定時のみ。**既定では含まれない** |

**要注意の発見**:

1. **`salt` / `verifier` は `string` 型で base64 エンコードされたテキスト**を格納する
   (生バイトではない)。デバイス側で base64 デコードして生バイトへ戻す必要がある。
   verifier は 132 base64 文字 → 97 バイト(`w0‖L`)、salt は 44 文字 → 32 バイト。
2. **CD(`cert-dclrn`)は `-cd` を渡さない限り factory に含まれない**。含まれない場合は
   デバイス側が別途 CD を供給する(本実装は VID=0xFFF1/PID=0x8001 の埋め込み dev CD で
   補う。製品では CSA 発行 CD を `-cd` で焼くか別途供給する)。
3. **PAA の有効期間は DAC の lifetime(既定 100 年)を包含**していないと mfg-tool が
   検証エラーで停止する。テスト PAA は `not_valid_after` を十分先(例 2130)にする。

### 1.2 NVS バイナリフォーマット(読み取りに必要な要点)

- ページ = 4096 バイト。先頭 32 B がページヘッダ(先頭 u32 = 状態: `0xFFFFFFFE`=ACTIVE /
  `0xFFFFFFF8`=FULL / `0xFFFFFFFF`=未使用)、続く 32 B がエントリ状態ビットマップ
  (2 ビット × 126 エントリ: `0b11`=empty / `0b10`=written / `0b00`=erased)、以降 126 個の
  32 バイトエントリ。
- エントリ: `[0]=NsIndex [1]=Type [2]=Span [3]=ChunkIndex [4..8]=CRC32 [8..24]=Key(NUL 詰め)
  [24..32]=Data`。
  - 固定長型(U8=0x01/U32=0x04 等): Data 先頭が LE 値。
  - 可変長型(SZ=0x21 / BLOB_DATA=0x42): Data の `[0..2]` がサイズ(u16 LE)、本体は
    後続エントリ領域に連続配置(Span がまたぐエントリ数)。
- namespace は `NsIndex=0 / Type=U8` のエントリが「名前 → インデックス」を定義する。
- blob は `BLOB_DATA`(0x42、チャンク本体)+ `BLOB_IDX`(0x48、チャンク数/総サイズ)の
  ペア。工場データの証明書はいずれも単一チャンク(< 4 KiB)。

---

## 2. FD1: DAC 供給の一般化

### 2.1 コア: `BorrowedDacProvider`(`operational_credentials.rs`)

`DacProvider` trait の第 2 実装。`TestDacProvider`(DER/CD を所有)と異なり、証明書
DER / CD を **借用スライス `&'a [u8]`** で保持し、DAC 秘密鍵署名を `DacSigner` に委譲する。

```rust
pub trait DacSigner {
    fn sign_with_dac(&self, msg: &[u8], out: &mut [u8; 64]) -> Result<()>;
}
pub struct KeypairDacSigner<K: P256Keypair>(pub K);   // 生鍵 32B から復元
pub struct FnDacSigner<F>(pub F);                      // クロージャ / セキュアエレメント委譲

pub struct BorrowedDacProvider<'a, S: DacSigner> { /* dac/pai/cd: &'a [u8], signer: S */ }
impl<'a, S: DacSigner> BorrowedDacProvider<'a, S> {
    pub fn new(dac_der, pai_der, cd, signer) -> Self;
}
impl<'a, K: P256Keypair> BorrowedDacProvider<'a, KeypairDacSigner<K>> {
    pub fn from_raw_key<C: Crypto<Keypair=K>>(crypto, dac_der, pai_der, cd, privkey: &[u8;32]) -> Result<Self>;
}
```

- **セキュアエレメント対応**: 秘密鍵をエクスポートできない実装は `DacSigner` を直接
  実装(署名だけ委譲)。生鍵運用は `from_raw_key`。
- VID/PID は DAC 証明書内に符号化されるため本型は保持しない(BasicInformation と独立)。
- ヒープレス・no_std。既存 `TestDacProvider` は不変(後方互換)。

### 2.2 C FFI シム: DAC 供給の口(`sm_config_t`)

`sm_config_t` に追加(未指定 = 従来の `TestDacProvider` = 後方互換):

```c
const uint8_t *dac_der; size_t dac_der_len;   // X.509 DER
const uint8_t *pai_der; size_t pai_der_len;
const uint8_t *cd_der;  size_t cd_der_len;    // NULL なら埋め込み dev CD で補う
const uint8_t *dac_privkey;                   // 32B 生鍵(NULL なら dac_sign を使う)
int32_t (*dac_sign)(void *ctx, const uint8_t *msg, size_t, uint8_t out[64]);  // セキュアエレメント
void *dac_sign_ctx;
```

- `dac_der` と `pai_der` が揃えば C 供給 DAC(`BorrowedDacProvider`)、揃わなければ dev DAC。
- 署名は `dac_privkey`(生鍵)優先、無ければ `dac_sign` コールバック。
- DER は `sm_init` 時に単一 static(`Owned::dac_store`、各 ≤ 1024 B)へコピー →
  provider が `&'static` で借用。ヘッダは `scripts/gen-cffi-header.sh` で再生成(冪等)。
- 型を単一に保つため `ShimDac { Test | Borrowed }` enum ディスパッチ。

### 2.3 PC 検証経路(examples / ctest)

- **onoff-light**(`examples/common/factory.rs`):
  - `SM_FACTORY_NVS=<bin>`(**`factory-data` feature 必須**): mfg NVS を [`FactoryData`] で
    パースし verifier + DAC + discriminator + VID/PID を一括供給。
  - `SM_FACTORY_DIR=<dir>`: DER ファイル群(`dac.der`/`pai.der`/`cd.der`/`dac_key.bin`)から
    DAC を供給(verifier は `SM_PASE_VERIFIER`、discriminator は `SM_DISCRIMINATOR`)。
- **ctest onoff_light.cpp**: `SM_FACTORY_DIR=<dir>` で DER ファイルを読み `sm_config_t` へ
  供給(C FFI の DAC 口の PC 検証)。`SM_CTEST_MATTER_PORT` / `SM_CTEST_MDNS_PORT` で
  ポートを上書き可(同一ホストの他デバイスと同居時)。

---

## 3. FD2: mfg factory パーティションリーダ(`src/factory/`、`factory-data` feature)

非 factory 構成のフットプリントに影響しないよう **feature gate**(default 無効)。

### 3.1 `factory::nvs::NvsReader`(ESP-IDF NVS 読み取り専用パーサ)

- フラッシュ内容の `&[u8]` から namespace / キーを **ゼロコピー**で引く(no_std・ヒープレス)。
- `get_u32` / `get_str`(末尾 NUL 除去)/ `get_blob`(単一チャンク)/ `has_namespace`。
- ACTIVE / FULL ページの written エントリを走査。CRC は検証しない割り切り。
- 暗号化 NVS・複数チャンク blob(> 約 4 KiB)は非対応(証明書は単一チャンクに収まる)。

### 3.2 `factory::FactoryData`(変換ヘルパ)

```rust
let fd = FactoryData::parse(flash)?;          // chip-factory namespace の存在を確認
fd.discriminator()?; fd.vendor_id()?; fd.product_id()?;
fd.salt(&mut buf)?; fd.verifier(&mut w0l)?;    // base64 デコード込み
fd.dac_cert()?; fd.pai_cert()?; fd.dac_key()?; // 証明書 DER / 生鍵
fd.pase_config()?;                             // PaseConfig(verifier + salt + iter)
fd.dac_provider(&crypto, cd_der)?;             // BorrowedDacProvider(CD は引数供給)
```

- **base64 デコードは自前実装**(no_std、ヒープレス、パディング対応)。salt/verifier に適用。
- 単体テストは **mfg-tool 実生成の NVS バイナリ**をフィクスチャに
  (`tests/fixtures/factory-fff1-8001.bin`、24 KiB)。検証項目:
  - discriminator/iteration/VID/PID、salt(32 B)、verifier(97 B, `w0` 先頭 = 04 の L)。
  - **stored verifier が passcode 20202021 + factory salt/iter からの導出値と一致**
    (= コミッショナの passcode 導出とデバイスの factory verifier が整合)。
  - **BorrowedDacProvider の署名を factory の dac-pub-key で検証**(生鍵経路の実証)。

---

## 4. ESP32 ポート配線

### 4.1 esp32c6-firmware(Rust、`e5-light`)

- `simple-matter` に `factory-data` feature を追加。
- `E5Dac { Test | Factory }` enum ディスパッチ。`FACTORY_BUF`(`'static`)へ flash の
  factory 領域(`FACTORY_OFFSET` / `FACTORY_LEN`)を読み、`FactoryData` でパース。
- `kvs::read_flash_region` + `EspKvs::from_flash`: **同じ `FlashStorage` で factory を先に
  読んでから KVS へ引き継ぐ**(FLASH ペリフェラルは 1 個)。
- 有効なら factory verifier + `BorrowedDacProvider`、無ければ dev 定数(後方互換)。CD は
  埋め込み dev CD。

### 4.2 ESP-IDF C++ example(`onoff_light_cpp`)

- Kconfig `CONFIG_SM_FACTORY_DATA`(既定 n)+ `CONFIG_SM_FACTORY_PARTITION`(既定
  `nvs_factory`)。
- 有効時、IDF 標準 nvs API(`nvs_flash_init_partition` → `nvs_open_from_partition(...,
  "chip-factory", ...)`)で discriminator/iteration/salt/verifier/VID/PID/DAC/PAI/鍵を読み、
  **base64 デコード**して `sm_config_t` に供給。CD は shim の埋め込み dev CD(`cd_der=NULL`)。
- パーティション未 flash / 読み取り失敗時は dev 定数にフォールバック。

---

## 5. 実機 flash 手順(スコープ外だが記録)

`mfg_tool` 出力の `*-partition.bin` を factory NVS パーティションへ焼く。

### 5.1 パーティションテーブル

`partitions.csv` に factory データ用エントリを追加する(KVS の `nvs` とは別領域):

```csv
# Name,        Type, SubType, Offset,   Size
nvs_factory,   data, nvs,     0x3F0000, 0x6000
```

- オフセット/サイズはアプリ・`nvs`・`phy_init` と衝突しない領域を選ぶ。
- ESP-IDF C++ example はこのラベル(`CONFIG_SM_FACTORY_PARTITION`)を `nvs_open_from_partition`
  で開く。Rust firmware は `FACTORY_OFFSET` 定数(このオフセットと一致させる)で読む。

### 5.2 flash

```bash
# 生成
esp-matter-mfg-tool -v 0xFFF1 -p 0x8001 --passcode 20202021 --discriminator 3840 \
  --paa -c paa_cert.pem -k paa_key.pem --outdir out
# 焼き込み(オフセットはパーティションテーブルの nvs_factory に合わせる)
espflash write-bin 0x3F0000 out/fff1_8001/<uuid>/<uuid>-partition.bin
# もしくは esptool:
python -m esptool --chip esp32c6 write_flash 0x3F0000 <uuid>-partition.bin
```

- 暗号化 NVS は本リーダのスコープ外(平文パーティションのみ)。
- コミッショナ側は `mfg_tool` が発行した passcode/discriminator でペアリングし、
  `mfg_tool` の PAA を `--paa-trust-store-path` に置いて attestation を実検証する。

---

## 6. 検証ゲート(実測)

### 6.1 gate 1: ビルド/テスト/フットプリント

- `cargo test --workspace`: 564 core + 各 crate green。`--features factory-data`: NVS 実
  バイナリフィクスチャ含め 9 factory テスト green。全 feature 併用(controller+ble+
  factory-data+alloc)573 green。
- clippy: workspace(+factory-data)/ cffi(ble・no-ble)いずれも **0 警告**
  (DAC enum の large_enum_variant は justified `#[allow]`: provider は単一常駐で Box 化しない)。
- クロス: `riscv32imc` / `thumbv6m` の core を baseline / factory-data 両方で green。
- **bloat-check(フットプリント増分)**: `flash-probe`(riscv32imc release)の `.text` =
  **133236 B**。`factory-data` を強制有効にしても **133236 B(増分 0 B)** — 未使用の
  factory リーダ / BorrowedDacProvider は `--gc-sections` で完全に除去される。
  **非 factory 構成のフットプリント増分はゼロ**。
- cffi .a: riscv32imac の `panic-abort+ble` / `panic-abort`(no-ble)両方 green。
- ヘッダ: `gen-cffi-header.sh --check` 冪等(up to date)。

### 6.2 gate 2: ホスト E2E(製造フロー実証)

`onoff-light`(`SM_FACTORY_NVS`= mfg 実 factory bin)→ `smctl pairing address`
(`--paa-trust-store-path`= mfg PAA):

- `[factory] loaded ... VID=0xfff1 PID=0x8001 discriminator=3840 (DAC 518 B, PAI 466 B, CD 539 B)`
- `[ctl] attestation: verifying DAC chain against 1 PAA cert(s)` → 全フェーズ完走
  (Attestation → CSR → AddNOC → CASE → CommissioningComplete)→ toggle → read=true。
- **負例**: 別の(署名者でない)PAA を信頼ストアに置くと
  `commissioning failed at stage 3: Attestation(PaaNotFound)` — attestation が実検証で
  あり bypass でないことを確認。

### 6.3 gate 3: C FFI ctest E2E

`ctest/onoff_light`(`SM_FACTORY_DIR`= DER ファイル群)→ `smctl pairing address`
(mfg PAA):`[factory] DAC from SM_FACTORY_DIR ...` → `attestation: verifying DAC chain
against 1 PAA cert(s)` → CommissioningComplete → toggle(`EVENT ONOFF_CHANGED arg=1`)。

### 6.4 gate 4: ESP ビルド

- ESP-IDF docker(`espressif/idf:release-v5.4`、`SM_PREBUILT_A` 経路、WiFi 構成 +
  `CONFIG_SM_FACTORY_DATA=y`): **Project build complete**、app 1,515,216 B(partition 42% free)。
- esp32c6-firmware(`e5-light`、`factory-data` feature): §6 の実測ログ参照。

---

## 7. 既知の割り切り

- CD は mfg NVS に含まれない構成が一般的なため、埋め込み dev CD(VID=0xFFF1/PID=0x8001)で
  補う。製品では CSA 発行 CD を `-cd` で焼くか `SM_FACTORY_CD` / `cert-dclrn` で供給する。
- 暗号化 NVS・複数チャンク blob(> 約 4 KiB)は非対応。
- NVS エントリ CRC は検証しない(フラッシュ健全性は下位層の責務)。
- 実機 flash は本作業のスコープ外(手順は §5 に記録)。

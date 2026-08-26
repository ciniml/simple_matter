# Device Attestation 実検証 設計

status: 設計確定(2026-07-07)。現状は `AttestationPolicy::Skip` のみ
(commissioner は AttestationRequest/CertificateChainRequest を**発行すらしない**)。
デバイス側は chip 開発クレデンシャル(DAC/PAI/CD、`dev_creds.rs`)で応答済みで、
chip-tool の `--bypass-attestation-verifier` が要るのはテスト PAA が信頼ストアに
無いためだけ。本作業は **controller 側の実検証 + smctl/chip-tool E2E** が主体。

## 1. スコープ(段階実装の割り切り)

実装するのは:
- **DAC チェーン検証**: DAC(X.509 DER)が PAI で署名され、PAI が PAA(トラスト
  ストア内)で署名されていること。PAA はストア内に DER 完全一致 or
  subject/SKID 一致のものを探し、PAI の署名を検証する。
- **attestation 署名検証**: `attestation_elements ‖ attestation_challenge(16B)` を
  DAC 公開鍵で ECDSA-P256 検証。challenge は PASE セッションから取得。
- **nonce エコー検証**: elements 内 cx2 が送信した 32B nonce と一致。
- **CD は presence チェックのみ**(elements cx1 が非空の CMS blob であること)。
  CMS(PKCS#7)署名検証・VID/PID クロスリファレンスは**スコープ外**
  (chip の CD 署名鍵の埋め込みと CMS parser が必要で重い。タスク合意済みの割り切り)。

その他の割り切り:
- **X.509 の有効期間(notBefore/notAfter)は検証しない**(コアは clock を持たない
  sans-IO。chip のテスト証明書も長期有効)。
- firmware information(elements cx4)は無視(オプション項目)。

## 2. コア: X.509 検証プリミティブ(`cert/x509.rs` 新設)

`issue.rs` の DER 補助(`der_tlv` / `der_ecdsa_to_raw` / SPKI 抽出)を `pub(crate)` 化
して再利用し、最小の X.509 リーダを作る:

```rust
pub struct X509Cert<'a> {
    pub tbs: &'a [u8],        // TBSCertificate(署名対象、ヘッダ込み)
    pub sig: [u8; 64],        // ECDSA-Sig-Value → raw r‖s
    pub spki_pubkey: [u8; 65],// SEC1 uncompressed P-256
    pub issuer: &'a [u8],     // issuer Name(DER そのまま、比較用)
    pub subject: &'a [u8],    // subject Name(DER そのまま)
}
pub fn parse_x509(der: &[u8]) -> Result<X509Cert<'_>>;
pub fn verify_signed_by<C: Crypto>(crypto, child: &X509Cert, issuer_pubkey: &[u8;65]) -> Result<bool>;
```

- 署名アルゴリズムは ecdsa-with-SHA256 のみ想定(それ以外は `Error::Unsupported` 系)。
- チェーン検証は `issuer(child) == subject(parent)` の DER バイト一致 + 署名検証。
  AKID/SKID 照合は簡略化のため必須にしない(chip のテスト証明書は Name 一致で足りる)。

## 3. コア: Commissioner の Verify ポリシ

```rust
pub enum AttestationPolicy<'a> {
    Skip,
    Verify { paa_store: &'a [&'a [u8]] },  // PAA DER のリスト(no_std/ヒープレス)
}
```

- ライフタイム追加は `Commissioner<'a, …>` に伝播(破壊的変更、呼び出し側は少数)。
- `Phase::Attestation` を実装: `Verify` のとき
  1. CertificateChainRequest(DAC=1) → `dac_der` 捕捉(固定バッファ、~600B)
  2. CertificateChainRequest(PAI=2) → `pai_der` 捕捉
  3. AttestationRequest(nonce = Rng 32B) → elements/signature 捕捉
  4. 検証(§1)。失敗は `CommissionError::Attestation(AttestationError)` で
     コミッショニング失敗(fail-safe はデバイス側の期限切れで解除)。
- attestation_challenge は `ControllerStack` のセッション
  (`Session::att_challenge()`)から PASE セッション ID で取得する
  (アクセサが無ければ薄い getter を追加)。
- ImClient の invoke 応答から DAC/PAI/elements/sig を取り出す経路は CSR と同型
  (`im_result()` の TLV を parse)。

## 4. smctl / examples

- smctl: グローバル `--paa-trust-store-path <dir>`。指定時はディレクトリ内の
  `*.der` を全部読み(std 側で `Vec<Vec<u8>>`)、`AttestationPolicy::Verify` で
  コミッショニング。未指定は従来どおり Skip(help 文言を更新)。
- テスト PAA(`Chip-Test-PAA-FFF1-Cert.der`、chip の
  credentials/development/paa-root-certs 由来)を **テスト用定数としてコアに埋め込む**
  (`dev_creds.rs` に追加、単体テストとループバック e2e 用)。smctl の E2E では
  ディレクトリから読む実路を使う。

## 5. 検証ゲート

- 単体: `parse_x509`(DAC/PAI/PAA 実データ)、`verify_signed_by`
  (DAC←PAI、PAI←PAA、負例: 鍵違い)、attestation 署名の固定
  (elements‖challenge、正/改竄/チャレンジ違い)、nonce 不一致。
- ループバック: `controller_end_to_end` 系に `Verify` ポリシ版を追加
  (デバイス=TestDacProvider、PAA=埋め込みテスト定数。改竄 nonce の失敗系も)。
- 実機 E2E:
  1. chip-tool **`--bypass` 無し** + `--paa-trust-store-path`(テスト PAA を置いた
     ディレクトリ)で PC onoff-light をフルコミッショニング+toggle。
  2. smctl `--paa-trust-store-path` で同等(成功)+ ストアに PAA が無い場合の
     失敗報告(Attestation エラーで中断)。

## 6. 実装メモ(2026-07-07、E2E で確定)

- **埋め込み CD が誤っていた**: `dev_creds.rs` の CD は VID=0xFFF2 用(541B、
  `25 01 f2 ff`)が埋まっており、chip-tool の実検証で err 604(CD vendor ID
  cross-reference)により発覚(`--bypass` では一切検証されないため今まで潜伏)。
  DeviceAttestationCredsExample.cpp の FFF1 ブロック(539B)に差し替えて解消。
- E2E 実測:
  - chip-tool `pairing onnetwork`(**--bypass 無し** + `--paa-trust-store-path`
    に Chip-Test-PAA-FFF1-Cert.der): "Successfully validated 'Attestation
    Information'" → コミッショニング完走 + toggle。
  - smctl `--paa-trust-store-path`: `[attestation] verifying DAC chain against
    1 PAA cert(s)` → 完走 + toggle。
  - smctl + 不一致 PAA(NoVID のみのストア): `Attestation(PaaNotFound)` で
    ステージ 3 中断(fail-safe はデバイス側期限切れで解除)。
- x509 検証は controller feature 配下(issue.rs の DER 補助を再利用するため。
  設計 §2 の「コア」からの軽微な乖離)。

## 7. CD の CMS 検証(§1 の割り切り解消、2026-07-08)

§1 で「presence チェックのみ」としていた CD(Certification Declaration)の
CMS SignedData(PKCS#7、RFC 5652)検証と VID/PID クロスチェックを実装した。

### 7.1 CMS 最小リーダ(`cert/cms.rs`、controller feature 配下)

chip の CD 形状に必要な範囲だけを読む(それ以外は `Error::Decode`):

- 署名者 1 名、`sid` = `[0] IMPLICIT subjectKeyIdentifier`(SignerInfo version 3)
- digest = SHA-256、signature = ecdsa-with-SHA256(P-256)
- **signedAttrs 無し**(署名対象は eContent = CD の Matter TLV そのもの)
- `[0] certificates` / `[1] crls` はあればスキップ(chip の CD には無い)

`parse_cms_signed_data()` → `CmsSignedData { econtent, signer_kid, sig }`(借用
ビュー、ヒープレス)。`verify_cms_signature()` は eContent を署名者公開鍵で
ECDSA-P256-SHA256 検証する。

### 7.2 既知 CD 署名者(テーブル `KNOWN_CD_SIGNERS`)

chip `DefaultDeviceAttestationVerifier.cpp` の `gCdSigningKeys`(6 本)の
サブセットを KID → 公開鍵の静的テーブルで埋め込む:

1. **chip テスト CD 署名鍵**("Matter Test CD Signing Authority"、
   `gTestCdPubkeyBytes`。credentials/test の Chip-Test-CD-*.der 用)
2. **CSA 公式 "Signing Key 001"**(`gCdSigningKey001*`)。**chip の
   `DeviceAttestationCredsExample` 埋め込み CD(= 本実装の
   `DEV_CD_FOR_ALL_EXAMPLES`)はテスト鍵ではなくこの公式鍵で署名されている**
   (実測。KID `FE 34 3F 95 ...`)ため必須。

割り切り: 公式鍵 002-005 は未収載(必要時にテーブルへ追加)。CD 署名 CA
(Matter Certification and Testing CA)チェーンの動的検証・失効確認はしない。
署名者の同定は KID 完全一致のみ。

### 7.3 検証手順(Commissioner `verify_attestation` ステップ 5)

1. elements cx1 の CD を CMS としてパース(失敗 = `AttestationError::CdParse`)
2. `signer_kid` を既知署名者テーブルと照合(不一致 = `CdSignerUnknown`)
3. CMS 署名検証(失敗 = `CdSignature`)
4. **VID/PID クロスチェック**: DAC subject の Matter DN 属性
   (OID 1.3.6.1.4.1.37244.2.1 / 2.2、16 進 4 桁文字列)から VID/PID を読み
   (`cert::x509::matter_vid_pid`。CN 埋め込み fallback `Mvid:`/`Mpid:` は
   非対応の割り切り)、CD の `vendor_id`(cx1)一致 + `product_id_array`
   (cx2)に PID が含まれること(不一致 = `CdVidPidMismatch`)

### 7.4 検証ゲート実測(2026-07-08)

- 単体: 埋め込み CD の parse+署名検証(Signing Key 001)、eContent 改竄 →
  署名検証失敗、署名バイト改竄 → 失敗、VID/PID クロスチェック正負
  (FFF1/8001 ∈、FFF2 ∉、PID 0x9000 ∉)、DAC subject の VID/PID DN 抽出。
- ループバック: `controller_end_to_end_attestation_verify`(CD 検証込みで完走)、
  `controller_end_to_end_attestation_rejects_tampered_cd`(CD 1 バイト改竄
  デバイス → `Attestation(CdSignature)` で中断、fabric 残留なし)。
- 実機 E2E: chip-tool `--paa-trust-store-path`(--bypass 無し)完走 + toggle、
  smctl `--paa-trust-store-path` 完走(CD 検証込み)、`SM_TAMPER_CD=1` の
  onoff-light 相手に smctl が `Attestation(CdSignature)` で中断。

## 8. PAA を辿らない最小検証(`VerifyNoPaa`、2026-08-27)

### 8.1 背景

実機で AirQ が **DAC(VID=0xFFF1 / PID=0x8001)を持つのに Basic Information の
ProductID を 0x8007 と報告**していた(DAC と焼き込み Basic Info の不整合)。厳格
検証する Alexa はこれをアテステーションで拒否したが、本コントローラは
`AttestationPolicy::Skip` で不整合を素通しし、smctl の既定も Skip だった。

`Verify`(PAA まで辿る完全検証)は本来の対策だが、開発フローでは PAA 信頼ストアを
用意しない運用が多い。そこで **PAA 信頼アンカーは要求しないが、DAC/PAI の 1 段
チェーン・attestation 署名・nonce・CD・そして「DAC の VID/PID がデバイスの報告値と
一致するか」までは検証する** 中間モード `VerifyNoPaa` を追加し、smctl の**既定**とする。

### 8.2 `AttestationPolicy::VerifyNoPaa`

```rust
pub enum AttestationPolicy<'a> {
    Skip,
    Verify { paa_store: &'a [&'a [u8]] },
    VerifyNoPaa,
}
```

検証内容(`Verify` から PAA 段だけを外し、報告 VID/PID 照合を足したもの):

1. DAC / PAI を X.509 DER としてパース。
2. **DAC が PAI 公開鍵で署名されている**こと(チェーン 1 段)。**PAI←PAA は
   検証しない**(PAA ストア不要)。
3. attestation 署名(`elements ‖ challenge`)を DAC 公開鍵で ECDSA-P256 検証、
   nonce エコー一致。
4. **CD の CMS 署名検証 + VID/PID クロスチェックは `Verify` と同一ロジックを流用**
   (§7。既に `KNOWN_CD_SIGNERS` と CMS リーダが実装済みなので最小スコープでも
   実施する。CD の CMS 署名検証は「やる」が本設計の選択)。
5. **本モードの主眼**: DAC 証明書 subject の Matter VID/PID DN 属性
   (`cert::x509::matter_vid_pid`)が、コミッショニング対象デバイスが報告する
   Basic Information の **VendorID / ProductID** と一致すること。不一致は新エラー
   `AttestationError::ReportedVidPidMismatch`。

上記のため、`VerifyNoPaa` では attestation 検証(1〜4)の成功後に **Basic Information
の VendorID / ProductID を Read** し、DAC の VID/PID と照合する(§8.3)。

**注意: 属性 ID はコアの Basic Information 実装(`basic_information.rs`)= Matter
仕様に従い VendorID=`0x0002` / ProductID=`0x0004`**(タスク記載の 0x0001/0x0002 は
それぞれ VendorName / VendorID を指すため不採用)。

### 8.3 Commissioner のサブステップ拡張

`Phase::Attestation` の `att_step` を拡張(`Verify` は 0〜2 のまま):

- 0: CertificateChainRequest(DAC)
- 1: CertificateChainRequest(PAI)
- 2: AttestationRequest → 捕捉 + 検証(チェーン/署名/nonce/CD)。成功時、
  - `Verify` は `Phase::Csr` へ遷移(従来どおり)。
  - **`VerifyNoPaa` は `att_step = 3` に進み同フェーズに留まる**。
- 3(`VerifyNoPaa` のみ): **Basic Information の VendorID(`0x0002`)+
  ProductID(`0x0004`)を 1 本の ReadRequest で Read**。`ImEvent::ReadDone` を
  受けて報告 VID/PID を取り出し、DAC の VID/PID と照合。一致で `Phase::Csr`、
  不一致(または読めない)で `Attestation(ReportedVidPidMismatch)`。

Read は `ControllerStack::start_read`(既存)で PASE セッション上に発行する。
`consume_event` は `Phase::Attestation && att_step == 3` を専用分岐で処理し、
`ReadDone` を待つ(他ステップは従来どおり `InvokeDone`)。

**割り切り**: 報告 VID/PID 照合は `VerifyNoPaa` 専用とする。`Verify`(PAA)は
既存テストのデバイス(Basic Info PID=0x8000 だが DAC PID=0x8001)を壊さないため
報告照合を足さない(§8.5)。将来 `Verify` にも報告照合を入れる場合は、テスト
デバイスの焼き込み PID を DAC と一致させる必要がある。

### 8.4 smctl 既定の変更

- `--paa-trust-store-path <dir>` 指定 → 従来の完全 `Verify`(PAA まで)。
- **無指定(既定)→ `VerifyNoPaa`**(従来は Skip 相当)。ログは
  `attestation: verifying DAC (no PAA trust anchor)`。成功ログは
  コミッショニング完走で観測。
- `--bypass-attestation` → 明示 `Skip`(DAC/PAI/CD を取得も検証もしない)。

### 8.5 検証ゲート(2026-08-27)

- ループバック(`stack/tests.rs`):
  - `controller_end_to_end_attestation_no_paa`(デバイス報告 PID=0x8001、
    PAA ストア無しで完走)。
  - `controller_end_to_end_attestation_no_paa_reported_pid_mismatch`(デバイス
    報告 PID=0x8007 に偽装 → `Attestation(ReportedVidPidMismatch)` で中断、
    fabric 残留なし。実機 AirQ バグの再現)。
  - `controller_end_to_end_attestation_no_paa_rejects_tampered_dac`(DAC 署名
    改竄デバイス → `Attestation(DacChain)` で中断)。
  - `controller_end_to_end_attestation_no_paa_rejects_bad_nonce`(コミッショナが
    エコー照合する nonce を検証時に差し替え → `Attestation(Nonce)`)。
  - 既存 `Verify`(PAA)テストは不変。

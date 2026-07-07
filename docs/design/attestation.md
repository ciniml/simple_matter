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

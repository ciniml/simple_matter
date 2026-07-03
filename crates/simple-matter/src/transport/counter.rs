//! メッセージカウンタ:送信側の単調カウンタと、受信側のリプレイ保護窓。
//!
//! Matter Core Specification §4.5(Message Counters)に基づく。
//!
//! - 送信は [`LocalCounter`]。セッションごと(暗号)およびグローバル(非暗号)に
//!   1 本ずつ持ち、単調増加する 32bit を払い出す。Matter 仕様の 28bit マスクは
//!   用いず 32bit 全域を使う(設計ドキュメント §3.2)。
//! - 受信は [`PeerWindow`]。直近に受理した最大カウンタ `max_ctr` と、その手前
//!   [`PeerWindow::WINDOW`] 個ぶんの受理履歴をビットマップで持ち、重複・順序前後・
//!   窓外を判定してリプレイを弾く(rs-matter `RxCtrState` の 32bit 版)。
//!
//! ここではユニキャストセッション(モジュラ比較なし)のみを扱う。グループ
//! セッションのロールオーバー比較は本ピースのスコープ外。

/// セッション/グローバルの送信メッセージカウンタ。
///
/// 単調増加する 32bit を払い出す。u32 の上限に達すると `wrapping_add` で 0 に
/// 戻るが、ユニキャストの暗号セッションではカウンタ枯渇時にセッション再確立が
/// 要求されるため、通常運用でラップは起きない。
#[derive(Debug, Clone, Copy)]
pub struct LocalCounter(u32);

impl LocalCounter {
    /// 初期値 `start` のカウンタを生成する。
    ///
    /// 仕様上、初期値はセッション確立時に乱数で選ぶことが推奨される
    /// (初期値の選択は呼び出し側の責務)。
    pub const fn new(start: u32) -> Self {
        Self(start)
    }

    /// 現在値を返し、内部カウンタを 1 進める(払い出し)。
    ///
    /// 名称は設計ドキュメント §3.2 に合わせる。`Iterator::next` とは無関係。
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u32 {
        let c = self.0;
        self.0 = self.0.wrapping_add(1);
        c
    }

    /// 次に払い出す値を消費せずに覗く。
    pub const fn peek(&self) -> u32 {
        self.0
    }
}

/// 受信メッセージのリプレイ保護窓(スライディングウィンドウ)。
///
/// `max_ctr` はこれまでに受理した最大カウンタ。`bitmap` のビット `i` は
/// カウンタ `max_ctr - (i + 1)` を既に受理済みかどうかを表す(1 = 受理済み)。
/// 窓幅は [`WINDOW`](Self::WINDOW) = 32。
#[derive(Debug, Clone, Copy)]
pub struct PeerWindow {
    max_ctr: u32,
    bitmap: u32,
}

impl PeerWindow {
    /// 窓幅(ビットマップのビット数)。
    pub const WINDOW: u32 = 32;

    /// 最大カウンタ `max_ctr` で窓を初期化する。
    ///
    /// `max_ctr` は受理済みとみなし、その手前は全て受理済み(`bitmap` 全 1)として
    /// 開始する(rs-matter と同じ。窓の左側での取りこぼしを防ぐ)。
    pub const fn new(max_ctr: u32) -> Self {
        Self {
            max_ctr,
            bitmap: u32::MAX,
        }
    }

    /// 現在の最大カウンタを返す。
    pub const fn max_ctr(&self) -> u32 {
        self.max_ctr
    }

    /// ビット `i`(`max_ctr - (i + 1)`)が受理済みか。
    const fn contains(&self, i: u32) -> bool {
        self.bitmap & (1u32 << i) != 0
    }

    /// ビット `i` を受理済みにする。
    fn insert(&mut self, i: u32) {
        self.bitmap |= 1u32 << i;
    }

    /// カウンタ `ctr` のメッセージを受理してよいか判定し、窓を更新する。
    ///
    /// 新規(未受理)なら `true` を返して窓を更新する。重複または窓外(リプレイ)
    /// なら `false` を返し、状態は変えない。
    ///
    /// `encrypted` はセッションが暗号化されているか。暗号セッションのユニキャスト
    /// カウンタは単調で、窓を超える後方ジャンプはリプレイとして拒否する。非暗号
    /// (`encrypted == false`)では、ピア再起動で新しい乱数カウンタに飛ぶことがあるため
    /// 窓外の後方ジャンプも新規として受理する。
    pub fn accept(&mut self, ctr: u32, encrypted: bool) -> bool {
        if ctr == self.max_ctr {
            // 最大値そのものは受理済み(重複)。
            return false;
        }

        let is_forward = ctr > self.max_ctr;
        let udiff = ctr.abs_diff(self.max_ctr);

        if !is_forward && udiff <= Self::WINDOW {
            // 窓の内側にある後方カウンタ。
            let i = udiff - 1;
            if self.contains(i) {
                false
            } else {
                self.insert(i);
                true
            }
        } else if is_forward {
            // 前進:最大値を更新し、旧履歴を左へシフトする。
            self.max_ctr = ctr;
            if udiff < Self::WINDOW {
                self.bitmap <<= udiff;
                // 直前の max_ctr は今や udiff だけ手前で、受理済み。
                self.insert(udiff - 1);
            } else {
                // 窓幅以上に飛んだ場合、過去履歴は全て窓外になる。
                self.bitmap = u32::MAX;
            }
            true
        } else if !encrypted {
            // 非暗号:ピア再起動による窓外の後方ジャンプを新規として受理。
            self.max_ctr = ctr;
            self.bitmap = u32::MAX;
            true
        } else {
            // 暗号セッションで窓外の後方ジャンプ = リプレイ。
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENC: bool = true;
    const PLAIN: bool = false;

    #[test]
    fn local_counter_monotonic_and_wraps() {
        let mut c = LocalCounter::new(41);
        assert_eq!(c.next(), 41);
        assert_eq!(c.next(), 42);
        assert_eq!(c.peek(), 43);

        let mut c = LocalCounter::new(u32::MAX);
        assert_eq!(c.next(), u32::MAX);
        assert_eq!(c.next(), 0);
    }

    #[test]
    fn window_forward_and_duplicate() {
        let mut w = PeerWindow::new(100);
        assert!(w.accept(101, ENC));
        assert!(w.accept(102, ENC));
        assert!(w.accept(103, ENC));
        // 同じ最大値は重複。
        assert!(!w.accept(103, ENC));
        assert_eq!(w.max_ctr(), 103);
    }

    #[test]
    fn window_out_of_order_within_window() {
        let mut w = PeerWindow::new(100);
        assert!(w.accept(105, ENC)); // 前進(飛び)
        assert_eq!(w.max_ctr(), 105);
        // 窓内の抜けを順不同で埋める。
        assert!(w.accept(103, ENC));
        assert!(w.accept(101, ENC));
        // 一度受理したものは重複。
        assert!(!w.accept(103, ENC));
        assert!(!w.accept(101, ENC));
        assert!(!w.accept(105, ENC));
    }

    #[test]
    fn window_boundary_edges() {
        let mut w = PeerWindow::new(100);
        // ちょうど窓幅ぶん前進。
        assert!(w.accept(100 + PeerWindow::WINDOW, ENC));
        assert_eq!(w.max_ctr(), 100 + PeerWindow::WINDOW);
        // 旧最大値 100 は今や WINDOW だけ手前 = ビット 31、受理済み扱い。
        assert!(!w.accept(100, ENC));
        // 窓の左端 +1(WINDOW+1 手前)は窓外。暗号では拒否。
        assert!(!w.accept(100 + PeerWindow::WINDOW - 33, ENC));
    }

    #[test]
    fn window_encrypted_rejects_far_backward() {
        let mut w = PeerWindow::new(1_000_000);
        // 窓外の後方(リプレイ)は暗号セッションで拒否。
        assert!(!w.accept(500_000, ENC));
        assert_eq!(w.max_ctr(), 1_000_000);
    }

    #[test]
    fn window_plaintext_accepts_reboot_jump() {
        let mut w = PeerWindow::new(20_010);
        assert!(w.accept(20_011, PLAIN));
        // ピア再起動で 0 付近へ飛ぶ:非暗号なら新規受理。
        assert!(w.accept(0, PLAIN));
        assert_eq!(w.max_ctr(), 0);
    }

    #[test]
    fn window_no_panic_on_large_diff() {
        // 片側が i32::MIN 付近でもオーバーフロー・パニックしない。
        let mut w = PeerWindow::new(1);
        assert!(w.accept(0x8000_0000, ENC));
        let mut w = PeerWindow::new(0x8000_0000);
        assert!(!w.accept(1, ENC));
    }

    #[test]
    fn window_encrypted_no_rollover_past_u32_max() {
        // 暗号ユニキャストは数値比較。u32 上限付近で前進し、0 へのラップは
        // 後方ジャンプ = リプレイ扱いで拒否される(仕様: 枯渇時は再確立)。
        let mut w = PeerWindow::new(u32::MAX - 1);
        assert!(w.accept(u32::MAX, ENC));
        assert!(!w.accept(0, ENC));
        // 非暗号なら再起動として受理。
        let mut w = PeerWindow::new(u32::MAX - 1);
        assert!(w.accept(u32::MAX, ENC));
        assert!(w.accept(0, PLAIN));
    }
}

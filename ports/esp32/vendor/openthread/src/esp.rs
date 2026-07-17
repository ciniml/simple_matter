//! `Radio` trait implementation for the `esp-hal` ESP IEEE 802.15.4 radio.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use esp_radio::ieee802154::Config as EspConfig;

use crate::fmt::Bytes;
use crate::{Capabilities, Cca, Config, MacCapabilities, PsduMeta, Radio, RadioErrorKind};

pub use esp_radio::ieee802154::Ieee802154;

/// The `esp-hal` ESP IEEE 802.15.4 radio.
pub struct EspRadio<'a> {
    driver: Ieee802154<'a>,
    config: Config,
    /// [simple_matter R9] RX キック用ダミー ACK のシーケンス番号。
    rx_kick_seq: u8,
}

impl<'a> EspRadio<'a> {
    const DEFAULT_CONFIG: Config = Config::new();

    /// Create a new `EspRadio` instance.
    pub fn new(ieee802154: Ieee802154<'a>) -> Self {
        let mut this = Self {
            driver: ieee802154,
            config: Self::DEFAULT_CONFIG,
            rx_kick_seq: 0,
        };

        this.driver.set_rx_available_callback_fn(Self::rx_callback);
        this.driver.set_tx_done_callback_fn(Self::tx_done_callback);
        this.driver
            .set_tx_failed_callback_fn(Self::tx_failed_callback);

        this.update_driver_config();

        this
    }

    fn update_driver_config(&mut self) {
        let config = &self.config;

        let esp_config = EspConfig {
            auto_ack_tx: true,
            auto_ack_rx: true,
            enhance_ack_tx: true,
            promiscuous: config.promiscuous,
            coordinator: false,
            rx_when_idle: config.rx_when_idle,
            txpower: config.power,
            channel: config.channel,
            cca_threshold: match config.cca {
                Cca::Carrier => 0,
                Cca::Ed { ed_threshold } => ed_threshold as _,
                Cca::CarrierAndEd { ed_threshold } => ed_threshold as _,
                Cca::CarrierOrEd { ed_threshold } => ed_threshold as _,
            },
            cca_mode: match config.cca {
                Cca::Carrier => esp_radio::ieee802154::CcaMode::Carrier,
                Cca::Ed { .. } => esp_radio::ieee802154::CcaMode::Ed,
                Cca::CarrierAndEd { .. } => esp_radio::ieee802154::CcaMode::CarrierAndEd,
                Cca::CarrierOrEd { .. } => esp_radio::ieee802154::CcaMode::CarrierOrEd,
            },
            pan_id: config.pan_id,
            short_addr: config.short_addr,
            ext_addr: config.ext_addr,
            // The default of 10 is too small for OpenThread,
            // which can have bursts of incoming frames, so we increase it to 50.
            // TODO: See if we can get by with a smaller number to save memory.
            rx_queue_size: 50,
            ..Default::default()
        };

        self.driver.set_config(esp_config);
    }

    fn rx_callback() {
        RX_SIGNAL.signal(());
    }

    fn tx_done_callback() {
        TX_SIGNAL.signal(true); // success
    }

    fn tx_failed_callback() {
        TX_SIGNAL.signal(false); // failure
    }
}

impl Radio for EspRadio<'_> {
    type Error = RadioErrorKind;

    const CAPS: Capabilities = Capabilities::ACK_TIMEOUT
        .union(Capabilities::CSMA_BACKOFF)
        // .union(Capabilities::RX_ON_WHEN_IDLE) TODO: Depends on coex being off in ESP-IDF
        ;

    const MAC_CAPS: MacCapabilities = MacCapabilities::all();

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        if self.config != *config {
            debug!("Setting radio config: {:?}", config);

            self.config = config.clone();
            self.update_driver_config();
        }

        Ok(())
    }

    async fn transmit(
        &mut self,
        psdu: &[u8],
        cca: bool,
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduMeta>, Self::Error> {
        TX_SIGNAL.reset();

        trace!(
            "802.15.4: About to TX {} bytes ch{}",
            psdu.len(),
            self.config.channel
        );
        // [simple_matter 診断] 多フラグメント TX の切り分け(>100B フレームのみ)。
        // T3: info! は毎 TX で USB-Serial-JTAG コンソールを飽和させ、リーダ未接続時に
        // println ブロックで executor を止める(ソーク不能)ため debug! へ格下げ。
        if psdu.len() > 100 {
            debug!("802.15.4: TX large frame {} bytes", psdu.len());
        }

        self.driver
            .transmit_raw(psdu, cca)
            .map_err(|_| RadioErrorKind::Other)?;

        // [simple_matter R9 拡張ワークアラウンド]
        // esp-radio 0.18 は tx_done/tx_failed イベントを取りこぼすことがあり
        // (RX 沈黙と同族の状態機械バグ)、その場合 `TX_SIGNAL.wait()` が永久に
        // 完了せず OT の radio タスク全体(TX/RX とも)が停止する。多フラグメント
        // 送信バースト(6LoWPAN 断片化した CASE sigma2 ~900B)で実機再現。
        // 完了待ちに 500ms のタイムアウトを入れ、タイムアウト時は同一 PSDU を
        // 再送出する(esp-radio の tx_init は stop_current_operation を先行させる
        // ため、座礁した状態機械ごと復帰する)。数回で回復しなければ TxFailed を
        // 返し、OT SubMac のリトライに委ねる。根本修正は esp-radio 側。
        let mut attempts = 0u8;
        let success = loop {
            let timeout = embassy_time::Timer::after(embassy_time::Duration::from_millis(500));
            match embassy_futures::select::select(TX_SIGNAL.wait(), timeout).await {
                embassy_futures::select::Either::First(ok) => break ok,
                embassy_futures::select::Either::Second(_) => {
                    attempts += 1;
                    warn!(
                        "802.15.4: TX completion timeout; re-kicking TX (attempt {})",
                        attempts
                    );
                    if attempts >= 3 {
                        break false;
                    }
                    TX_SIGNAL.reset();
                    if self.driver.transmit_raw(psdu, cca).is_err() {
                        break false;
                    }
                }
            }
        };

        if success {
            trace!("802.15.4: TX done");
            if psdu.len() > 100 {
                debug!("802.15.4: TX large frame done ({} bytes)", psdu.len());
            }

            // [simple_matter T2 ワークアラウンド / フラグメント TX ペーシング]
            // RCP 構成の親(NanoC6 ot_rcp、spinel over USB-CDC)は、6LoWPAN 断片化
            // フレームのバースト(back-to-back TX)を HW auto-ack した後に spinel 側で
            // 取りこぼす(OTBR で "Dropping rx frag frame"(先頭/中間断片欠落)を実測。
            // ACK 済みのため OT は再送しない)。大きめのフレーム送信後に短い間隔を
            // 空けて RCP の排出(~3ms/frame @460800baud)を待つ。CASE sigma2(~900B、
            // 7 断片)の成立に必須。根本対処は RCP 側バッファ/フロー制御。
            if psdu.len() > 64 {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(8)).await;
            }

            if let Some(ack_psdu_buf) = ack_psdu_buf {
                // After tx_done signal received, get the ACK frame:
                if let Some(ack_frame) = self.driver.get_ack_frame() {
                    if ack_frame.data.len() >= 1 {
                        // Must have at least 1 byte for PSDU
                        let ack_psdu_len =
                            (ack_frame.data.len() - 1).min((ack_frame.data[0] & 0x7f) as usize);

                        if ack_psdu_len <= ack_psdu_buf.len() {
                            ack_psdu_buf[..ack_psdu_len]
                                .copy_from_slice(&ack_frame.data[1..][..ack_psdu_len]);

                            trace!(
                                "802.15.4: ACK: {} on ch{}",
                                Bytes(&ack_psdu_buf[..ack_psdu_len]),
                                ack_frame.channel
                            );

                            // Only read RSSI if there is at least one byte after the PSDU.
                            let rssi = if ack_frame.data.len() > 1 + ack_psdu_len {
                                Some(ack_frame.data[1..][ack_psdu_len] as i8)
                            } else {
                                None
                            };

                            return Ok(Some(PsduMeta {
                                len: ack_psdu_len,
                                channel: ack_frame.channel,
                                rssi,
                            }));
                        } else {
                            trace!(
                                "802.15.4: ACK frame too large for provided buffer: {} bytes",
                                ack_psdu_len
                            );
                        }
                    }
                }
            }

            Ok(None)
        } else {
            trace!("802.15.4: TX failed");

            // Report as a failure so OpenThread SubMac retries
            Err(RadioErrorKind::TxFailed)
        }
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        RX_SIGNAL.reset();

        trace!("802.15.4: About to RX on ch{}", self.config.channel);

        self.driver.start_receive();

        let raw = loop {
            if let Some(frame) = self.driver.raw_received() {
                break frame;
            }

            // [simple_matter R9 ワークアラウンド]
            // esp32c6 + esp-radio 0.18 では、attach 直後から RX が沈黙する事象が
            // 実機で再現する(TX は正常。役割 Child のまま ping/keepalive 受信ゼロ)。
            // `start_receive()`(state==Receive/TxAck では no-op)や
            // `raw_received()` 内の `ensure_receive_enabled`(RxStart 再発行)の
            // 周期実行では回復しないことを実測済みで、**回復する唯一の経路は実 TX**
            // (tx_init の stop_current_operation → 完了後 next_operation →
            // rx_init + enable_rx のフル再初期化)である。
            // そこで受信シグナル待ちにタイムアウトを入れ、無受信が続いた
            // 場合は宛先なしの imm-ACK フレーム(3 バイト。他ノードは
            // UnexpectedAck として破棄)を CCA 付きで送出し、TX 完了経路で RX を
            // 再初期化する。
            //
            // [T3 item 4: リンク品質改善] タイムアウトを 5s → 1s に短縮する。
            // RX 沈黙は自局 TX(SRP 更新 / MLE keepalive / 6LoWPAN 断片)の直後に
            // 起きやすく、5s 窓では SRP/Matter の応答(RTT < 1s、OT の応答待ちは
            // 数秒でタイムアウト)を取りこぼして RESPONSE_TIMEOUT(err 28)を招く
            // ことを実機で実測(SRP 登録がサーバ側は成功しても DUT が応答を受けられず
            // 再送ループ→radio 負荷増→更なる沈黙)。1s に縮めると沈黙開始から 1s 以内に
            // RX を再アームでき、応答取りこぼしが大幅に減る。副作用は静穏時 1s 毎の
            // 約 200µs airtime(デューティ ~0.02%)のみ。根本修正は esp-radio 側
            // (upstream 報告候補)。thread-port.md R9 / T3 item 4。
            let timeout = embassy_time::Timer::after(embassy_time::Duration::from_millis(1000));
            if let embassy_futures::select::Either::Second(_) =
                embassy_futures::select::select(RX_SIGNAL.wait(), timeout).await
            {
                trace!("802.15.4: RX kick (dummy ack TX to re-init RX)");
                self.rx_kick_seq = self.rx_kick_seq.wrapping_add(1);
                let _ = self.driver.transmit_raw(&[0x02, 0x00, self.rx_kick_seq], true);
                // TX 完了は TX_SIGNAL に来る(RX_SIGNAL ではない)ため待たない。
                // 完了 ISR の next_operation が rx_when_idle=true により RX を
                // フル再初期化する。次周回の raw_received() 前に start_receive()
                // も呼ばれる(下)ので取りこぼしはない。
            }
            self.driver.start_receive();
        };

        if raw.data.len() < 1 {
            // Must have at least 1 byte for PSDU
            return Err(RadioErrorKind::Other);
        }

        let psdu_len = (raw.data.len() - 1).min((raw.data[0] & 0x7f) as usize);
        if psdu_len > psdu_buf.len() {
            // PSDU length is larger than the provided buffer
            trace!(
                "802.15.4: Received frame too large for provided buffer: {} bytes",
                psdu_len
            );
            return Err(RadioErrorKind::Other);
        }

        psdu_buf[..psdu_len].copy_from_slice(&raw.data[1..][..psdu_len]);

        // Only read RSSI if there is at least one byte after the PSDU.
        let rssi = if raw.data.len() > 1 + psdu_len {
            Some(raw.data[1..][psdu_len] as i8)
        } else {
            None
        };

        trace!(
            "802.15.4: RX {} bytes ch{} rssi={:?}",
            psdu_len,
            raw.channel,
            rssi
        );
        // [simple_matter 診断] 多フラグメント RX の切り分け(>100B フレームのみ)。
        // T3: 毎 RX のコンソール飽和を避けるため debug! へ格下げ(上記 TX 側と同理由)。
        if psdu_len > 100 {
            debug!("802.15.4: RX large frame {} bytes", psdu_len);
        }

        Ok(PsduMeta {
            len: psdu_len,
            channel: raw.channel,
            rssi,
        })
    }
}

// Esp chips have a single radio, so having statics for these is OK
static TX_SIGNAL: Signal<CriticalSectionRawMutex, bool> = Signal::new();
static RX_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

//! AirQ の 1.54" e-ink(GDEW0154D67 / GDEY0154D67、200x200)表示タスク。
//!
//! `docs/design/airq-port.md` §7.5(残改善バッチ 2)。パネルのコントローラは
//! **SSD1681 系**(旧 FW の LGFX `Panel_GDEW0154D67` の初期化列 — 0x12 SWReset /
//! 0x01 Driver Output / 0x24 RAM write / 0x22+0x20 update — で判定)。
//!
//! # ドライバ選定(§7.5.1)
//!
//! [`epd-waveshare` 0.6.0](https://crates.io/crates/epd-waveshare) の
//! `epd1in54_v2` を採用。同モジュールは **GDEH0154D67(同一 D67 パネル)向け**と
//! 明記されており、embedded-hal 1.0 / no_std / embedded-graphics `DrawTarget`
//! (`Display1in54`、5000B フレームバッファ)/ フル・クイック両 LUT を備える。
//! esp-hal の `Spi<Blocking>`(`SpiBus` 実装)を `embedded-hal-bus` の
//! `ExclusiveDevice` で `SpiDevice` 化して渡す。
//!
//! # 配線(旧 FW epd.h / airq-port.md §1.3)
//!
//! BUSY=GPIO1(HIGH=busy)、RST=GPIO2、DC=GPIO3、CS=GPIO4、SCK=GPIO5、
//! MOSI=GPIO6(MISO なし)。SPI mode 0。旧 FW は 40MHz だが SSD1681 定格に
//! 収まる **10MHz** で駆動する(配線は筐体内で短いが安全側)。
//!
//! # 更新戦略(e-ink 劣化・ゴースト配慮)
//!
//! - 更新周期は旧 FW と同じ **30 秒**([`UPDATE_PERIOD_S`])。
//! - 通常はクイック更新(`RefreshLut::Quick`、フリッカーなし)、
//!   **[`FULL_REFRESH_EVERY`] 回に 1 回フル更新**(フリッカーあり)でゴーストを
//!   リセットする。旧 FW はクイック相当のみでフル更新なし(= ゴースト蓄積対策
//!   なし)だったので、ここは改善点。
//! - 値が前回表示から変わらなければパネルを触らない(無駄な劣化を避ける)。
//!
//! # 実行モデルの注意
//!
//! epd-waveshare は blocking ドライバで、`wait_until_idle` が BUSY ピンを
//! ポーリングする(= その間 embassy executor 全体が止まる)。リフレッシュ起動
//! (`display_frame`)自体は完了を待たずに戻るため、**次にパネルへ触るまでに
//! リフレッシュ所要(クイック ~0.5s / フル ~2s)より十分長く await する**ことで
//! executor の停止をほぼゼロにする(30 秒周期なので自然に満たされる)。
//! 唯一の例外は起動時の init + 全面クリア(数秒ブロック)で、Matter スタック
//! 起動前の 1 回のみ。

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU8, Ordering};

use embassy_time::Timer;
use embedded_graphics::mono_font::ascii::{FONT_10X20, FONT_6X10};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Line, PrimitiveStyle};
use embedded_graphics::text::Text;
use embedded_hal_bus::spi::ExclusiveDevice;
use epd_waveshare::color::Color;
use epd_waveshare::epd1in54_v2::{Display1in54, Epd1in54};
use epd_waveshare::prelude::*;
use esp_hal::delay::Delay;
use esp_hal::gpio::{Input, Output};
use esp_hal::spi::master::Spi;
use esp_hal::Blocking;
use esp_println::println;

use crate::sensors;

/// 表示更新周期(秒)。旧 FW と同じ 30 秒(e-ink 劣化配慮でこれより短くしない)。
const UPDATE_PERIOD_S: u64 = 30;
/// クイック更新 N 回ごとに 1 回フル更新(ゴーストのリセット)。20 回 × 30s = 10 分。
const FULL_REFRESH_EVERY: u32 = 20;
/// リフレッシュ起動後にパネルへ触らない猶予(ms)。フル更新の所要(~2s)より長く。
const REFRESH_SETTLE_MS: u64 = 4000;

/// pump が算出した AirQualityEnum(0=Unknown..6=ExtremelyPoor)の写し。
/// 表示タスクはクラスタ本体に触れないため、この 1 バイトだけを共有する。
static AIR_QUALITY: AtomicU8 = AtomicU8::new(0);

/// pump から現在の AirQuality(enum 値)を知らせる。
pub fn set_air_quality_level(level: u8) {
    AIR_QUALITY.store(level, Ordering::Relaxed);
}

/// AirQualityEnum 値の表示ラベル。
fn aq_label(level: u8) -> &'static str {
    match level {
        1 => "Good",
        2 => "Fair",
        3 => "Moderate",
        4 => "Poor",
        5 => "VeryPoor",
        6 => "Ex.Poor",
        _ => "----",
    }
}

/// 表示する値のスナップショット(前回表示との差分検出用)。
#[derive(PartialEq, Clone, Copy, Default)]
struct Shown {
    co2: Option<i32>,
    pm25_x10: Option<i32>,
    temp_x10: Option<i32>,
    rh_x10: Option<i32>,
    aq: u8,
}

impl Shown {
    fn capture() -> Self {
        let (_, snap) = sensors::snapshot();
        Self {
            co2: snap.co2_ppm.map(|v| v as i32),
            pm25_x10: snap.pm25.map(|v| (v * 10.0) as i32),
            temp_x10: snap.temp_c.map(|v| (v * 10.0) as i32),
            rh_x10: snap.rh.map(|v| (v * 10.0) as i32),
            aq: AIR_QUALITY.load(Ordering::Relaxed),
        }
    }
}

/// `label` + 右寄せ気味の値 1 行を描く。
fn draw_line(display: &mut Display1in54, y: i32, label: &str, value: &str) {
    let style = MonoTextStyle::new(&FONT_10X20, Color::Black);
    let _ = Text::new(label, Point::new(4, y), style).draw(display);
    let _ = Text::new(value, Point::new(74, y), style).draw(display);
}

/// フレームバッファへ全項目を描画する。
fn render(display: &mut Display1in54, shown: &Shown, updates: u32) {
    let _ = display.clear(Color::White);

    // ヘッダ(小フォント)+ 罫線。
    let small = MonoTextStyle::new(&FONT_6X10, Color::Black);
    let _ = Text::new("simple-matter AirQ", Point::new(4, 12), small).draw(display);
    let _ = Line::new(Point::new(0, 18), Point::new(199, 18))
        .into_styled(PrimitiveStyle::with_stroke(Color::Black, 1))
        .draw(display);

    let mut buf: heapless::String<24> = heapless::String::new();

    // AirQuality(総合評価)は最上段に大きく。
    draw_line(display, 44, "Air", aq_label(shown.aq));

    buf.clear();
    match shown.co2 {
        Some(v) => {
            let _ = write!(buf, "{} ppm", v);
        }
        None => {
            let _ = write!(buf, "---");
        }
    }
    draw_line(display, 74, "CO2", &buf);

    buf.clear();
    match shown.pm25_x10 {
        Some(v) => {
            let _ = write!(buf, "{}.{} ug", v / 10, (v % 10).abs());
        }
        None => {
            let _ = write!(buf, "---");
        }
    }
    draw_line(display, 104, "PM2.5", &buf);

    buf.clear();
    match shown.temp_x10 {
        Some(v) => {
            let _ = write!(buf, "{}.{} C", v / 10, (v % 10).abs());
        }
        None => {
            let _ = write!(buf, "---");
        }
    }
    draw_line(display, 134, "Temp", &buf);

    buf.clear();
    match shown.rh_x10 {
        Some(v) => {
            let _ = write!(buf, "{}.{} %", v / 10, (v % 10).abs());
        }
        None => {
            let _ = write!(buf, "---");
        }
    }
    draw_line(display, 164, "Hum", &buf);

    // フッタ: 更新カウンタ(表示が生きていることの目印。ユーザの目視確認用)。
    buf.clear();
    let _ = write!(buf, "update #{}", updates);
    let _ = Text::new(&buf, Point::new(4, 192), small).draw(display);
}

/// e-ink 表示の常駐タスク(pump / sensor_task と並走)。
///
/// 初期化失敗時はエラーログを出して停止する(表示は補助機能。Matter ノードとして
/// の動作には影響させない)。
pub async fn display_task(
    spi: Spi<'static, Blocking>,
    cs: Output<'static>,
    busy: Input<'static>,
    dc: Output<'static>,
    rst: Output<'static>,
) -> ! {
    let mut delay = Delay::new();
    let mut spi_dev = match ExclusiveDevice::new(spi, cs, Delay::new()) {
        Ok(d) => d,
        Err(e) => {
            println!("[epd] CS setup failed: {:?}; display disabled", e);
            loop {
                Timer::after_secs(3600).await;
            }
        }
    };

    // init(SW reset + LUT)+ 全面クリア + フル更新。ここだけ数秒ブロックする
    // (Matter トラフィック開始前の 1 回きり)。
    let mut epd = match Epd1in54::new(&mut spi_dev, busy, dc, rst, &mut delay, None) {
        Ok(e) => e,
        Err(e) => {
            println!("[epd] init failed: {:?}; display disabled", e);
            loop {
                Timer::after_secs(3600).await;
            }
        }
    };
    if let Err(e) = epd.clear_frame(&mut spi_dev, &mut delay) {
        println!("[epd] clear failed: {:?}", e);
    }
    if let Err(e) = epd.display_frame(&mut spi_dev, &mut delay) {
        println!("[epd] initial refresh failed: {:?}", e);
    }
    println!("[epd] initialized (SSD1681 / epd1in54_v2, full clear done)");
    Timer::after_millis(REFRESH_SETTLE_MS).await;

    let mut display = Display1in54::default();
    let mut last: Option<Shown> = None;
    let mut updates: u32 = 0;
    let mut quick_since_full: u32 = 0;

    loop {
        let shown = Shown::capture();
        // 値が変わらなければパネルを触らない(e-ink 劣化配慮)。
        if last == Some(shown) {
            Timer::after_secs(UPDATE_PERIOD_S).await;
            continue;
        }

        updates += 1;
        render(&mut display, &shown, updates);

        // 通常はクイック更新、FULL_REFRESH_EVERY 回ごとにフル更新でゴーストを消す。
        let full = quick_since_full >= FULL_REFRESH_EVERY || last.is_none();
        let lut = if full {
            quick_since_full = 0;
            RefreshLut::Full
        } else {
            quick_since_full += 1;
            RefreshLut::Quick
        };
        let r = epd
            .set_lut(&mut spi_dev, &mut delay, Some(lut))
            .and_then(|()| {
                epd.update_and_display_frame(&mut spi_dev, display.buffer(), &mut delay)
            });
        match r {
            Ok(()) => println!(
                "[epd] update #{} ({}) aq={} co2={:?} pm2.5(x10)={:?} T(x10)={:?} RH(x10)={:?}",
                updates,
                if full { "full" } else { "quick" },
                aq_label(shown.aq),
                shown.co2,
                shown.pm25_x10,
                shown.temp_x10,
                shown.rh_x10,
            ),
            Err(e) => println!("[epd] update #{} failed: {:?}", updates, e),
        }
        last = Some(shown);

        // リフレッシュ完了(busy 解除)を跨いでから次周期へ。
        Timer::after_millis(REFRESH_SETTLE_MS).await;
        Timer::after_secs(UPDATE_PERIOD_S - REFRESH_SETTLE_MS / 1000).await;
    }
}

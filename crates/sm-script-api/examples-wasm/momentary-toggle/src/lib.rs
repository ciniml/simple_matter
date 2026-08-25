//! momentary-toggle — モーメンタリ(押しっぱなしで ON)スイッチを **トグル**スイッチに
//! 変える実用サンプル。§9.3 の「変則ハードをスクリプトで吸収する」ケース。
//!
//! # 想定する構成(NVS `smgen`)
//!
//! - composition: EP1 = Identify/Groups/OnOff + BooleanState(0x0045)
//! - binding: EP1 BooleanState → `gpio_in`(モーメンタリスイッチ)、
//!   EP1 OnOff → `gpio_out`(負荷)
//!
//! # ふるまい
//!
//! - `on_sensor`: BooleanState が false→true(押下エッジ)になったら OnOff を反転する。
//!   同時に 1 秒の長押しタイマを張る。離した(true→false)らタイマを取り消す。
//! - `on_timer(TIMER_LONG_PRESS)`: 押しっぱなし 1 秒 = 強制 OFF。
//! - `on_boot`: 押下回数を KVS(`smscr` namespace の `cnt`)から復元してログに出す。
//! - `on_attr_write`: 外部(Matter コントローラ)からの変更をログに出すだけ(0 = 承認)。
#![no_std]

use core::cell::Cell;
use core::panic::PanicInfo;

use sm_script_api as sm;

/// 単線(WASM は 1 スレッド)前提の可変グローバル。
struct Single<T>(Cell<T>);
// SAFETY: フックは Matter ポンプと同一タスクで同期実行される(§9.3)ので競合しない。
unsafe impl<T> Sync for Single<T> {}

static PRESSED: Single<bool> = Single(Cell::new(false));
static COUNT: Single<u32> = Single(Cell::new(0));

/// 対象エンドポイント。
const EP: i32 = 1;
/// 長押し判定タイマの id。
const TIMER_LONG_PRESS: i32 = 1;
/// 長押しと見なす時間。
const LONG_PRESS_MS: i32 = 1000;
/// 押下回数を保存する KVS キー。
const KEY_COUNT: &[u8] = b"cnt";

fn boot() {
    let mut buf = [0u8; 4];
    COUNT.0.set(match sm::kvs_get(KEY_COUNT, &mut buf) {
        Ok(4) => u32::from_le_bytes(buf),
        _ => 0,
    });
    // 起動時の物理状態を取り込んでおく(押しっぱなし起動でいきなり反転しないように)。
    PRESSED.0.set(state_value().unwrap_or(false));
    sm::log("momentary-toggle ready");
}

/// EP1 の BooleanState(押下 = true)。
fn state_value() -> Option<bool> {
    sm::attr_get(EP, sm::cluster::BOOLEAN_STATE, sm::attr::VALUE)
        .ok()
        .and_then(|v| v.as_bool())
}

fn sensor(_bind: i32) {
    let now = match state_value() {
        Some(v) => v,
        None => return, // BooleanState が合成されていない構成
    };
    let was = PRESSED.0.get();
    if now == was {
        return; // 変化なし(温湿度センサ等の別バインディング由来)
    }
    PRESSED.0.set(now);
    if now {
        // 押下エッジ = トグル。
        let on = sm::on_off_get(EP).unwrap_or(false);
        let _ = sm::on_off_set(EP, !on);
        COUNT.0.set(COUNT.0.get().wrapping_add(1));
        let _ = sm::kvs_set(KEY_COUNT, &COUNT.0.get().to_le_bytes());
        let _ = sm::timer_after(LONG_PRESS_MS, TIMER_LONG_PRESS);
        sm::log(if on {
            "press: on -> off"
        } else {
            "press: off -> on"
        });
    } else {
        // 離した = 長押しタイマ取り消し。
        let _ = sm::timer_cancel(TIMER_LONG_PRESS);
    }
}

fn timer(id: i32) {
    if id == TIMER_LONG_PRESS && PRESSED.0.get() {
        let _ = sm::on_off_set(EP, false);
        sm::log("long press: forced off");
    }
}

fn attr_write(_ep: i32, cluster: i32, _attr: i32) -> i32 {
    if cluster == sm::cluster::ON_OFF {
        sm::log("on_off changed by controller");
    }
    0 // 承認(非 0 は現状「観測のみ」)
}

sm::sm_script! {
    boot: boot,
    sensor: sensor,
    timer: timer,
    attr_write: attr_write,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // panic = abort。WASM の unreachable を踏んで trap する(ホスト側は trap を記録して
    // Matter 本体の動作は継続する)。
    core::arch::wasm32::unreachable()
}

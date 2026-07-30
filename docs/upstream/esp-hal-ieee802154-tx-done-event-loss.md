<!-- 対象リポジトリ: esp-rs/esp-hal (esp-radio ieee802154) / 投稿先: https://github.com/esp-rs/esp-hal/issues / 既存 issue との関係: 新規。esp-rs/openthread#53 item 6「missing TX acknowledgment handling(driver fails to return transmitted ack frames)」と近縁だが別事象 — こちらは ACK フレームの返却漏れではなく tx_done/tx_failed 完了イベント自体の喪失で送信 future が永久に完了しない件。esp-hal 側に該当 issue は未確認。 -->

# esp-radio ieee802154 (ESP32-C6): tx_done/tx_failed completion event is occasionally lost during fragment bursts, hanging the radio task forever

## Environment

- Chip: ESP32-C6 (bare-metal, `riscv32imac-unknown-none-elf`), stable rustc
- `esp-radio` 0.18 (`ieee802154`, `ble` features), `esp-hal` 1.1.1, `esp-rtos` 0.3 (embassy executor), `embassy-time` 0.5
- Thread stack: `openthread` 0.2.0 + `openthread-sys` 0.2.1, bundled `EspRadio` (`Radio` impl over `esp_radio::ieee802154::Ieee802154`)
- Border router: `openthread/otbr:latest` (docker) + a second ESP32-C6 running esp-idf `ot_rcp` (spinel over USB-Serial-JTAG, 460800 baud)

## Symptom

The `EspRadio` transmit path registers a `tx_done`/`tx_failed` callback that signals completion, and `transmit()` awaits that signal:

```rust
fn tx_done_callback()   { TX_SIGNAL.signal(true);  }
fn tx_failed_callback() { TX_SIGNAL.signal(false); }
// ...
self.driver.transmit_raw(psdu, cca)?;
let ok = TX_SIGNAL.wait().await;   // <-- can wait forever
```

Under bursts of back-to-back transmits — reproducibly a **6LoWPAN fragment burst** carrying a Matter CASE `sigma2` (~900 B, ~7 fragments) — one transmit's completion callback (**neither** `tx_done` **nor** `tx_failed`) never fires. `TX_SIGNAL.wait()` then blocks forever. Because OpenThread drives both TX and RX from the same radio task, that task is now permanently parked and **the entire radio (TX and RX) stops**. From the outside this looks identical to a full radio hang: the device stays `Child` momentarily but never sends or receives again.

## Root cause analysis

**Measured facts:**

- Reproduced on hardware during multi-fragment TX bursts (CASE `sigma2`, ~900 B). Single/small transmits do not trigger it.
- The await never completes: no completion event of either polarity arrives, so it is a **lost event**, not a `tx_failed` we could handle.
- Forcing a re-transmit of the same PSDU (which re-runs `tx_init` -> `stop_current_operation`) unblocks it, so the hardware is not wedged — the completion notification is what went missing.

**Inference:** the driver drops or fails to deliver the TX-completion interrupt/event under rapid consecutive transmits, most likely the same event-loss family as the RX-stall report (a lost state transition around the `TxAck`/completion state). The completion signal is edge-like and there appears to be no timeout/watchdog, so a single lost event is unrecoverable from the caller's side.

## Reproduction

1. Bring up an ESP32-C6 DUT with `openthread` 0.2.0 + `esp-radio` 0.18 as an MTD child of an OTBR (see companion RX-stall report for the border-router setup).
2. Establish a Matter (or any 6LoWPAN) exchange that sends a payload larger than the 802.15.4 MTU so it fragments into a back-to-back burst — a Matter CASE handshake `sigma2` (~900 B) is a reliable trigger.
3. Repeat handshakes. Intermittently, one `transmit()` never completes and the radio task parks permanently; the device goes silent in both directions.

## Workaround we applied

In the vendored `EspRadio::transmit`, bound the completion wait with a 500 ms timeout and, on timeout, re-issue the same PSDU (up to a few attempts) before giving up and reporting `TxFailed` so OpenThread's SubMac can retry:

```rust
TX_SIGNAL.reset();
self.driver.transmit_raw(psdu, cca).map_err(|_| RadioErrorKind::Other)?;

let mut attempts = 0u8;
let success = loop {
    let timeout = Timer::after(Duration::from_millis(500));
    match select(TX_SIGNAL.wait(), timeout).await {
        Either::First(ok) => break ok,
        Either::Second(_) => {
            attempts += 1;
            if attempts >= 3 { break false; }
            TX_SIGNAL.reset();
            // Re-kick: transmit_raw -> tx_init -> stop_current_operation
            // recovers the stalled state machine.
            if self.driver.transmit_raw(psdu, cca).is_err() { break false; }
        }
    }
};
```

This reliably unblocks the radio task; combined with the RX-stall kick it makes CASE-over-Thread complete. It is still a workaround (re-transmitting a frame whose real fate is unknown risks duplicates, mitigated by the MAC/DSN).

## Suggested fix

- Guarantee that **exactly one** completion event (`tx_done` or `tx_failed`) is delivered for every accepted `transmit_raw`, even under back-to-back transmits — i.e. don't lose the completion interrupt during rapid TX sequencing.
- Failing that, expose a `transmit` with an internal timeout / recovery so a single lost completion cannot permanently park the radio.
- Likely shares a root cause with the RX-stall report (dropped `TxAck`/completion state transition); fixing the event delivery should address both.

## Related

- esp-rs/openthread#53 item 6 "missing TX acknowledgment handling" is adjacent but different: that is about not returning the received ACK frame to OpenThread. This report is about the TX *completion* event itself being lost, which hangs the transmit future.
- Companion report: RX permanently stalls after attach, recoverable only by a real TX — same suspected event-loss family in the ieee802154 state machine.

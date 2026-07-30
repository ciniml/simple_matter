<!-- 対象リポジトリ: esp-rs/esp-hal (esp-radio ieee802154) / 投稿先: https://github.com/esp-rs/esp-hal/issues / 既存 issue との関係: 新規。RX 取りこぼしの上位症状は esp-rs/openthread#53 (umbrella stability) の item 1「missed incoming packets」に相当するが、そちらの想定原因(MTD が TX 後 sleep に落ちる → rx_when_idle=true で解決)とは異なる、rx_when_idle=true でも回復しない状態機械の座礁を報告するもの。esp-hal 側に該当 issue は未確認。 -->

# esp-radio ieee802154 (ESP32-C6): RX permanently stalls a few seconds after Thread attach; only a real TX call re-arms the receiver

## Environment

- Chip: ESP32-C6 (bare-metal, `riscv32imac-unknown-none-elf`), stable rustc
- `esp-radio` 0.18 (`ieee802154`, `ble` features), `esp-hal` 1.1.1, `esp-rtos` 0.3 (embassy executor), `embassy-time` 0.5
- Thread stack: `openthread` 0.2.0 + `openthread-sys` 0.2.1, running the crate's bundled `EspRadio` (`Radio` impl over `esp_radio::ieee802154::Ieee802154`)
- Border router: `openthread/otbr:latest` (docker) with a second ESP32-C6 running the esp-idf `ot_rcp` example (spinel over USB-Serial-JTAG, 460800 baud)
- Radio config: `auto_ack_tx/rx = true`, `rx_when_idle = true`, `rx_queue_size = 50`, MTD (rx-on child)

## Symptom

The device joins the Thread network normally (role transitions `disabled -> detached -> child`, appears in the OTBR `child table` with good link quality, RLOC16 assigned). Then, a few seconds after attach, **the receive path goes permanently silent**: no ICMPv6 ping, no MLE keepalive, no UDP is ever delivered up from the radio again. The OTBR side observes the child's `Age` climbing monotonically until the child times out.

This is a **RX-only** stall. Everything else keeps running:

- `transmit()` still works — a periodic outbound UDP probe from the device keeps reaching the OTBR for the entire duration.
- The embassy executor, `embassy-time`, and the OpenThread state machine are all alive — an application heartbeat keeps printing and `net_status().role` stays `Child`.

So the failure is specifically that the ieee802154 driver stops delivering received frames, while the rest of the system is healthy.

## Root cause analysis

**Measured facts (reproduced on hardware):**

- The stall is RX direction only; TX is unaffected (verified with a periodic TX probe that keeps landing at the border router).
- `start_receive()` called periodically does **not** recover RX. When the driver's internal state is `Receive`/`TxAck`, `start_receive()` is effectively a no-op, so re-issuing it does nothing.
- Re-arming via the `RxStart` path (the `ensure_receive_enabled` logic inside the receive loop) does **not** recover RX either.
- The **only** action that recovers RX is a **real TX**. Issuing an actual `transmit_raw()` re-initializes the receiver: `tx_init` runs `stop_current_operation`, and on TX completion `next_operation` runs `rx_init` + `enable_rx`, which fully re-arms the radio.
- Bisected as **independent** of: the `ble` feature (present or absent), coex, and the log level. Toggling those does not change the behavior.

**Inference (not directly instrumented):** the esp-radio 0.18 ieee802154 state machine appears to get stuck in a state from which the normal RX re-arm paths cannot escape — most plausibly a `TxAck`-family state where a completion/transition event is dropped and the driver never returns to an RX-enabled state. Because a full `stop_current_operation -> rx_init -> enable_rx` cycle (only reachable through the TX path today) does recover it, the receiver hardware itself is fine; the driver-side state tracking is what wedges.

## Reproduction

Minimal setup (no application-specific code required):

1. Second ESP32-C6 flashed with esp-idf `ot_rcp` (spinel over USB-Serial-JTAG); host runs `openthread/otbr:latest` as border router and forms a network. Note the Operational Dataset TLV.
2. DUT: ESP32-C6 with `openthread` 0.2.0 + `esp-radio` 0.18 (`ieee802154`), driving the bundled `EspRadio`. Inject the dataset (`set_active_dataset_tlv`), `enable_ipv6(true)`, `enable_thread(true)`, and run `ot.run(EspRadio::new(ieee802154))` on its own task.
3. Wait for role `Child`. From the OTBR, `ping` the device's mesh-local (ML-EID) address.

Observed: ping succeeds for the first few seconds (during/right after attach, which requires bidirectional Parent/Child ID exchange, so RX is briefly working), then goes to 100% loss while the device keeps happily transmitting. `ot-ctl child table` shows the child `Age` climbing to timeout.

## Workaround we applied

In a vendored copy of the `openthread` crate's `EspRadio::receive`, we time out the RX-signal wait and, when no frame has arrived for a while, force a real (dummy) TX to drive the recovery path. The dummy is a 3-byte imm-ACK-shaped frame that other nodes discard as an `UnexpectedAck`:

```rust
async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
    RX_SIGNAL.reset();
    self.driver.start_receive();

    let raw = loop {
        if let Some(frame) = self.driver.raw_received() {
            break frame;
        }
        // No RX for a while -> force RX re-init via a real TX completion.
        // Only a real TX (tx_init: stop_current_operation -> completion:
        // next_operation: rx_init + enable_rx) recovers the stalled receiver.
        let timeout = embassy_time::Timer::after(embassy_time::Duration::from_millis(1000));
        if let Either::Second(_) =
            select(RX_SIGNAL.wait(), timeout).await
        {
            self.rx_kick_seq = self.rx_kick_seq.wrapping_add(1);
            // 3-byte imm-ACK; peers drop it as UnexpectedAck.
            let _ = self.driver.transmit_raw(&[0x02, 0x00, self.rx_kick_seq], true);
            // TX completion arrives on TX_SIGNAL; its next_operation re-arms RX.
        }
        self.driver.start_receive();
    };
    // ... normal PSDU extraction ...
}
```

We initially used a 5 s silence timeout; that was too long — RX tends to stall right after our own TX (SRP refresh / MLE keepalive / 6LoWPAN fragments), and a 5 s window drops the peer's reply (RTT < 1 s), producing `RESPONSE_TIMEOUT` and a retransmit storm. Shortening to **1 s** re-arms RX within ~1 s of the stall and largely eliminates the churn. Cost is ~200 µs of airtime per idle second (~0.02% duty). With the 1 s kick, continuous survival went from ~70 s to 220 s+ in soak.

This is only a workaround — it wastes airtime and papers over a driver bug.

## Suggested fix

- In the esp-radio ieee802154 driver, make the RX re-arm paths (`start_receive` / the `RxStart` path) actually recover from the stuck state, i.e. allow re-arming RX **without** requiring a TX to run `stop_current_operation` first.
- Investigate the `TxAck`-family state transitions for a dropped/lost completion event that leaves the state machine unable to return to an RX-enabled state (see also the companion report on lost `tx_done`/`tx_failed` events — likely the same event-loss family).
- A watchdog inside the driver that detects "RX enabled but no ISR activity" and internally issues `stop_current_operation -> rx_init -> enable_rx` would remove the need for callers to emit dummy TX frames.

## Related

- esp-rs/openthread#53 (umbrella stability) item 1 "missed incoming packets" describes the same *symptom* but attributes it to MTD sleeping after TX, fixed by `rx_when_idle = true`. In our repro `rx_when_idle` is already `true`, yet RX still stalls and is only recoverable by a real TX — suggesting a deeper state-machine issue in the esp-radio driver, distinct from the sleep-after-TX hypothesis.

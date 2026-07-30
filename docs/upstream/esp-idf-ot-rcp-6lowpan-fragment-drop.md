<!-- 対象リポジトリ: espressif/esp-idf (examples/openthread/ot_rcp) / 投稿先: https://github.com/espressif/esp-idf/issues / 既存 issue との関係: 新規(重複未確認 — espressif/esp-idf の issue を確認のうえ投稿すること)。関連は esp-rs/openthread#53 item 3「frame reassembly failures」だが、そちらは DUT 側 esp-radio の再組立、本件は RCP(esp-idf)側 spinel の断片取りこぼしで別レイヤ。 -->

# ot_rcp (ESP32-C6, spinel over USB-Serial-JTAG): back-to-back 6LoWPAN fragments are ACKed by HW but dropped on the spinel path, so OpenThread never retransmits

## Environment

- RCP: ESP32-C6 running esp-idf `examples/openthread/ot_rcp`, built with `CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y` (spinel over the native USB-Serial-JTAG CDC, 460800 baud)
- Host: `openthread/otbr:latest` (docker), `--radio-url spinel+hdlc+uart://<dev>?uart-baudrate=460800`, acting as Border Router / Leader
- Peer (child/DUT): a second ESP32-C6 running a Thread MTD (in our case `openthread` 0.2.0 + `esp-radio` 0.18, but the drop is on the RCP/OTBR side and is peer-agnostic)
- esp-idf: release-v5.4 (also reproduced with release-v6.0)

## Symptom

When the child transmits a payload that fragments into a **back-to-back 6LoWPAN fragment burst** (e.g. a Matter CASE `sigma2`, ~900 B / ~7 fragments), the transfer does not complete. On the OTBR side the log shows:

```
Dropping rx frag frame
```

(a leading/middle fragment is missing, so reassembly is abandoned). Crucially, the child's radio has already received a **hardware auto-ACK** for each fragment, so from the child's point of view every fragment was delivered — OpenThread therefore **does not retransmit**. The exchange stalls: the reassembled datagram never arrives and there is no MAC-level recovery because the link layer already acknowledged the frames.

Single frames and slowly-paced traffic go through fine; only rapid consecutive fragments are lost.

## Root cause analysis

**Measured facts:**

- The fragments are auto-ACKed at the 802.15.4 MAC (HW auto-ack on the RCP), so the sender considers them delivered and never retries.
- OTBR logs `Dropping rx frag frame` for the incomplete reassembly, i.e. at least one fragment of the burst never reached the OpenThread stack on the host even though it was ACKed on air.
- Inserting a small inter-frame gap on the **sender** side (see workaround) makes the drop disappear and the fragmented datagram reassembles reliably.

**Inference:** the loss is between "HW received + auto-ACKed on the RCP" and "frame handed to OpenThread over spinel on the host". The most likely bottleneck is the RCP -> host spinel transport (USB-Serial-JTAG at 460800 with HDLC): a burst of full-size 802.15.4 frames (~3 ms/frame at 460800 baud) arrives faster than the RCP can serialize/drain them over spinel, and a frame is dropped after it has already been ACKed on air. Because the ACK is emitted by hardware before the spinel hand-off, the drop is invisible to the sender and un-retransmittable by Thread.

We have not instrumented whether the drop is in the RCP's radio->spinel queue, the HDLC/USB CDC buffer, or the host `spinel-hdlc` driver — but the ACK-before-drain ordering is what makes it silent.

## Reproduction

1. Build `examples/openthread/ot_rcp` for ESP32-C6 with `CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y` (+ `CONFIG_OPENTHREAD_RCP_UART=n`); flash it. Connect it to a host running `openthread/otbr:latest`.
2. Form a network on the OTBR; attach any Thread MTD child.
3. From the child, send a UDP datagram large enough to fragment into a back-to-back burst (>~600 B; a Matter CASE `sigma2` ~900 B is a reliable trigger), or otherwise generate rapid consecutive 6LoWPAN fragments toward the OTBR.
4. Observe `Dropping rx frag frame` on the OTBR and a stalled transfer with no retransmission from the child.

## Workaround we applied

We paced the **sender** so the RCP has time to drain each frame over spinel: after successfully transmitting any frame larger than 64 B, wait ~8 ms before the next transmit. (Applied in our vendored radio driver; the fix is really on the RCP/transport side.)

```rust
// after a successful transmit_raw of a large frame:
if psdu.len() > 64 {
    embassy_time::Timer::after(embassy_time::Duration::from_millis(8)).await;
}
```

8 ms per fragment (~ the RCP drain time at 460800) was enough to make CASE `sigma2` (7 fragments) reassemble reliably. This costs latency and is not something an unmodified Thread node should have to do.

## Suggested fix

- On the RCP, apply back-pressure so a frame is **not auto-ACKed / not accepted** if it cannot be enqueued for spinel transmission — better to drop it *before* the ACK so Thread's normal retransmission recovers, than to ACK then silently drop.
- Increase / flow-control the RCP radio->spinel and HDLC/USB-CDC buffering so a short burst of full-size frames does not overflow at 460800 baud.
- Consider documenting a higher `uart-baudrate` (or hardware UART) for RCP-over-USB-Serial-JTAG when 6LoWPAN fragmentation / larger UDP payloads (e.g. Matter) are expected.

## Related

- esp-rs/openthread#53 item 3 "frame reassembly failures" describes reassembly trouble on the esp-radio (DUT) side; this report is the RCP/spinel-side drop and is a different layer, but both hurt the same fragmented-payload path.

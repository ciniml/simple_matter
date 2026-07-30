<!-- 対象リポジトリ: esp-rs/openthread / 投稿先: https://github.com/esp-rs/openthread/issues / 既存 issue との関係: 新規(SLAAC 無効プリビルト .a → OMR 不生成は #53/#104 のいずれにも未記載)。末尾の related(otLinkSetPollPeriod 未露出・RX_ON_WHEN_IDLE 未実装)は #53 item 1 / #104 (SSED/CSL) と重複するため、その 2 点は本 issue に新規で立てず #104 / #53 へのコメント追記を推奨。 -->

# esp-rs/openthread: prebuilt libopenthread.a is built with SLAAC disabled, so no OMR address is generated and Matter/operational discovery fails

## Environment

- `openthread` 0.2.0 + `openthread-sys` 0.2.1 (default `matter` bundle + `mbedtls-rs-sys`), no_std, stable rustc
- Target: ESP32-C6 (`riscv32imac-unknown-none-elf`), using the prebuilt `libopenthread.a` shipped by `openthread-sys` (no `force-generate-bindings`, no local C toolchain)
- Role: MTD child; SRP client (`srp` feature) registering `_matter._tcp` with an OTBR (`openthread/otbr:latest`) whose advertising proxy mirrors SRP into LAN mDNS

## Symptom

After a successful attach the device only ever has a **link-local** and a **mesh-local** address — no OMR (Off-Mesh-Routable, i.e. on-mesh SLAAC) address is ever created, even though the network data advertises an on-mesh prefix with the SLAAC flag set.

Downstream consequences:

- The SRP client's auto host address resolves to the **mesh-local** address. The OTBR advertising proxy will not publish an `AAAA` for a mesh-local address, so the operational `AAAA` never appears on the LAN.
- A Matter controller can see the `_matter._tcp` PTR (from SRP) but cannot resolve a reachable address, so **operational discovery / CASE-over-Thread cannot start**. This was the root cause of "device commissions but is undiscoverable" in our bring-up.

## Root cause analysis

**Measured facts:**

- The prebuilt `libopenthread.a` does **not** export `otIp6SetSlaacEnabled` (the symbol is unresolved when we tried to call it) — i.e. the library is compiled with `OPENTHREAD_CONFIG_IP6_SLAAC_ENABLE=0`.
- With SLAAC compiled out, OpenThread never auto-configures an address from the on-mesh SLAAC prefix, so only link-local + mesh-local exist.
- The on-mesh prefix *is* present in network data with the SLAAC flag (we can read it via `netdata_get_on_mesh_prefixes`), confirming the border router is advertising an OMR prefix — the device simply isn't consuming it.

**Inference:** the default prebuilt binary distributed with `openthread-sys` 0.2.x has SLAAC disabled in its build config. Any deployment that relies on an OMR address (SRP host advertising, Matter operational discovery, general off-mesh reachability) is broken out of the box unless the user rebuilds from source (`force-generate-bindings`), which defeats the "stable rustc, no C toolchain" value proposition of the prebuilt path.

## Reproduction

1. `openthread` 0.2.0 with the default prebuilt `libopenthread.a` on an ESP32-C6, MTD child of an OTBR that has formed a network (the OTBR advertises an OMR prefix by default).
2. Attach; enumerate addresses (`ipv6_addrs`). Observe only link-local + mesh-local; no address under the on-mesh SLAAC prefix.
3. Register an SRP service and check the OTBR: the SRP host address is mesh-local and the advertising proxy publishes no `AAAA` on the LAN.

## Workaround we applied

We synthesize the OMR address by hand after attach — take the SLAAC on-mesh prefix from network data, append an EUI-64-derived modified IID, and add it as a unicast address via a small wrapper over `otIp6AddUnicastAddress` (we exposed `add_unicast_address` in a vendored copy of the crate, since the safe API did not surface it):

```rust
// after attach: pull the SLAAC on-mesh (OMR) prefix from network data
let mut prefix: Option<(Ipv6Addr, u8)> = None;
let _ = ot.netdata_get_on_mesh_prefixes(|p| {
    if let Some(cfg) = p {
        if cfg.slaac && cfg.prefix.1 == 64 && prefix.is_none() {
            prefix = Some(cfg.prefix);   // mesh-local is not in netdata
        }
    }
    Ok(())
});
if let Some((pfx, plen)) = prefix {
    let mut iid = eui64;
    iid[0] ^= 0x02;                       // modified EUI-64 (flip u/l bit)
    let p = pfx.octets();
    let addr = Ipv6Addr::from([p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                               iid[0],iid[1],iid[2],iid[3],iid[4],iid[5],iid[6],iid[7]]);
    ot.add_unicast_address(addr, plen)?;  // otIp6AddUnicastAddress
}
```

With the OMR address present, the SRP host address becomes routable, the advertising proxy publishes `AAAA`, and Matter operational discovery / CASE-over-Thread works.

## Suggested fix

- Build the distributed prebuilt `libopenthread.a` with `OPENTHREAD_CONFIG_IP6_SLAAC_ENABLE=1` (and export `otIp6SetSlaacEnabled`), so an OMR address is auto-configured out of the box — this is required for any realistic Thread/Matter deployment.
- If SLAAC must stay optional, gate it behind a cargo feature that selects a SLAAC-enabled prebuilt (or document that OMR must be added manually), and surface `otIp6AddUnicastAddress` / `otIp6SetSlaacEnabled` in the safe API.

## Related issues (please treat as comments on existing issues, not new ones)

While bringing this up we hit two adjacent gaps that overlap existing issues — better added there than duplicated:

- **`otLinkSetPollPeriod` is not exposed** in the safe API. Without it there is no way to tune the MTD data-poll period, which is needed for any sleepy/low-power operation. This belongs with the SSED/CSL discussion in **#104**.
- **`EspRadio` does not implement `RX_ON_WHEN_IDLE`** (its `Capabilities` explicitly omit it, with a `TODO: Depends on coex being off in ESP-IDF`). Without it, an MTD cannot actually save power (it either stays rx-on or misses frames when idle). This is the same area as the "missed incoming packets / rx_when_idle" discussion in **#53** (item 1) and blocks real SED behavior.

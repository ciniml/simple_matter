//! flash 計測(MCU クロスビルド):On/Off ライトのスタック一式をリンクする最小
//! `no_std`/`no_main` バイナリ。
//!
//! HAL/ランタイム crate(cortex-m-rt 等)は持ち込まない。エントリ(`_start`)と
//! `#[panic_handler]` は自前で用意し、リンカ設定は `build.rs` + `link.x` で与える
//! (`docs/ARCHITECTURE.md` 設計原則 10 / 本計測のスコープ)。
//!
//! ネットワーク/時刻はダミー注入で、スタックが**リンクされる**ことのみを保証する。
//! リンカの GC(`--gc-sections`)で消えないよう、構築したスタックとデータパス
//! (`handle_rx`/`poll`/mDNS `handle_query`)を [`core::hint::black_box`] で参照保持する。
//!
//! ビルド例:
//! ```text
//! cargo build -p bloat-check --bin flash-probe --release --target thumbv7em-none-eabihf
//! size -A target/thumbv7em-none-eabihf/release/flash-probe
//! ```
//!
//! ホスト(std)ターゲットでは自前の `#[panic_handler]` が std のものと衝突するため、
//! 実体は `target_os = "none"` のときだけコンパイルし、ホストでは空の `main` に縮退する
//! (ワークスペース横断の clippy/test を壊さないため)。

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod bare {
    use core::cell::RefCell;
    use core::hint::black_box;
    use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use core::panic::PanicInfo;

    use bloat_check::{build_light, pase_config, Backend, DemoRng, Light, MAX_PACKET_SIZE};

    use simple_matter::crypto::rustcrypto::RustCrypto;
    use simple_matter::discovery::{Host, MdnsResponder, MATTER_PORT};
    use simple_matter::fabric::FabricTable;
    use simple_matter::im::engine::InteractionModel;
    use simple_matter::sc::SecureChannel;
    use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
    use simple_matter::transport::net::PeerAddr;

    /// DefaultStack プロファイル(fabric 数)。
    const NF: usize = 5;

    /// 自前パニックハンドラ(計測用途:何もしないループ。unwinding は profile で abort)。
    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        loop {
            black_box(0);
        }
    }

    /// 自前エントリポイント。標準ランタイムを使わず、スタックを構築してデータパスを 1 巡
    /// 参照し、リンカ GC で消えないようにする。実際の入出力は行わない(ダミー)。
    #[no_mangle]
    pub extern "C" fn _start() -> ! {
        // 外部所有:crypto と fabric テーブル(OpCreds/CASE が共有)。
        let crypto = RustCrypto::new(DemoRng::new(1));
        let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());

        let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, DemoRng::new(3), pase_config(), creds);
        let im = InteractionModel::new(build_light::<NF>(&fabrics));
        let mut stack: DefaultStack<Backend, DemoRng, Light<NF>> =
            MatterStack::new(&crypto, sc, im);

        // mDNS レスポンダ(commissionable/operational 広告)も flash に含める。
        let host = Host::from_mac(&[0x02, 0, 0, 0, 0, 1], None, Some(Ipv4Addr::LOCALHOST));
        let mdns: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);

        // データパスを一巡参照して monomorphized コードをリンクに残す。
        let mut rx = [0u8; MAX_PACKET_SIZE];
        let mut tx = [0u8; MAX_PACKET_SIZE];
        let peer = PeerAddr::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5540)));

        let _ = black_box(stack.handle_rx(black_box(&mut rx), peer, 0, &mut tx));
        let _ = black_box(stack.poll(0, &mut tx));
        let _ = black_box(stack.next_deadline(0));

        let mut mdns_out = [0u8; 512];
        let _ = black_box(mdns.handle_query(black_box(&rx[..64]), &mut mdns_out));

        black_box(&stack);
        black_box(&fabrics);
        black_box(&mdns);

        loop {
            black_box(&stack);
        }
    }
}

//! flash 計測(MCU クロスビルド): **controller(commissioner)経路**をリンクする最小
//! `no_std`/`no_main` バイナリ(`docs/design/esp32-controller.md` §6.2 / K1)。
//!
//! 既存の `flash-probe` はデバイス(responder)経路のみを参照するため、
//! `--features simple-matter/controller` を付けても controller コードはリンカ GC で
//! 消える(CI の footprint-invariance チェックが利用している性質)。本バイナリは逆に
//! `ControllerStack` + `Commissioner` + `Ca`(ca-state codec 込み)+ `MdnsClient` の
//! 経路を [`core::hint::black_box`] で参照保持し、controller ビルドの .text/.rodata を
//! CI で記録する。
//!
//! ビルド例:
//! ```text
//! cargo build -p bloat-check --bin controller-probe --release \
//!   --target thumbv7em-none-eabihf --features controller
//! size -A target/thumbv7em-none-eabihf/release/controller-probe
//! ```
//!
//! ホスト(std)ターゲットでは自前の `#[panic_handler]` が std のものと衝突するため、
//! 実体は `target_os = "none"` のときだけコンパイルし、ホストでは空の `main` に縮退する
//! (flash-probe と同じ扱い)。

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod bare {
    use core::hint::black_box;
    use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use core::panic::PanicInfo;

    use bloat_check::{Backend, DemoRng};

    use simple_matter::controller::ca::{Ca, CA_STATE_MAX_LEN};
    use simple_matter::controller::{
        AttestationPolicy, Commissioner, ControllerCreds, ControllerStack,
    };
    use simple_matter::crypto::rustcrypto::RustCrypto;
    use simple_matter::discovery::client::MdnsClient;
    use simple_matter::im::client::ImClient;
    use simple_matter::sc::initiator::ScInitiator;
    use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};

    /// ハブ既定サイジング(esp32-controller.md §6.1: コミッショニング 1 + 運用 CASE 数本)。
    type Ctrl<'s> = ControllerStack<'s, Backend, DemoRng, ControllerCreds<'s, Backend>, 4, 6, 3>;

    /// 自前パニックハンドラ(計測用途: 何もしないループ。unwinding は profile で abort)。
    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        loop {
            black_box(0);
        }
    }

    /// エラー終端(fmt 機構を持ち込まないため unwrap は使わない)。
    fn halt() -> ! {
        loop {
            black_box(1);
        }
    }

    /// 自前エントリポイント。controller 一式を構築してデータパスを 1 巡参照し、
    /// リンカ GC で消えないようにする。実際の入出力は行わない(ダミー)。
    #[no_mangle]
    pub extern "C" fn _start() -> ! {
        let crypto = RustCrypto::new(DemoRng::new(1));

        // CA(RCAC 自己発行 + 自 NOC + FabricTable 登録。P-256 署名経路がリンクされる)。
        let Ok(ca) = Ca::<Backend>::generate(
            &crypto,
            &mut DemoRng::new(2),
            0xFAB0_0000_0000_0001,
            0x0000_0000_1122_3344,
            0xFFF1,
            0,
        ) else {
            halt()
        };

        // ca-state v1 codec(EspKvs / smctl と共有する encode/decode)。
        let mut rec = [0u8; CA_STATE_MAX_LEN];
        let _ = black_box(ca.encode_state(&mut rec));
        let _ = black_box(Ca::<Backend>::decode_state(&crypto, black_box(&rec), 0));

        // ControllerStack + Commissioner(commissioning 状態機械)。
        let creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc = ScInitiator::new(&crypto, DemoRng::new(3), creds);
        let im = ImClient::new();
        let mut stack: Ctrl = ControllerStack::new(&crypto, sc, im);
        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);

        let peer = PeerAddr::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5540)));
        let _ = black_box(comm.commission(peer, 20202021, 0x0000_0000_AABB_CCDD, 0));

        // 駆動データパスを一巡参照(handle_rx / poll / next_deadline / drive)。
        let mut rx = [0u8; MAX_RX_PACKET_SIZE];
        let mut tx = [0u8; MAX_RX_PACKET_SIZE];
        let _ = black_box(stack.handle_rx(black_box(&mut rx), peer, 0, &mut tx));
        let _ = black_box(stack.poll(0, &mut tx));
        let _ = black_box(stack.next_deadline(0));
        let _ = black_box(comm.drive(&mut stack, 0, &mut tx));

        // mDNS クライアント(ブラウズ / 運用解決の builder + parser)。
        let mut q = [0u8; 128];
        let _ = black_box(MdnsClient::build_browse_commissionable(&mut q, true));
        let _ = black_box(MdnsClient::build_browse_discriminator(&mut q, 3840, true));
        let _ = black_box(MdnsClient::build_resolve_operational(
            &mut q,
            black_box(&[0u8; 8]),
            1,
            true,
        ));
        let _ = black_box(MdnsClient::parse_commissionable(black_box(&rx[..64])));
        let _ = black_box(MdnsClient::parse_operational(
            black_box(&rx[..64]),
            black_box(&[0u8; 8]),
            1,
        ));

        loop {
            black_box(&stack);
            black_box(&comm);
        }
    }
}

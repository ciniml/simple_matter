//! RAM 計測(ホスト実行):On/Off ライトのスタック一式をコンポーネント別に
//! `core::mem::size_of` で計測し、表形式で出力する。
//!
//! 実行: `cargo run -p bloat-check --bin ram-report --release`
//!
//! MCU 実機では `.bss` に載る構造体群のサイズがそのまま RAM フットプリントになる。ホストの
//! `size_of` は同じ型レイアウトを測るため、RAM の下限見積りとして妥当(rs-matter の
//! `bloat-check` と同じ発想。実機では `size_of_val` を defmt で出す派生も可能)。
//!
//! 本バイナリは std 前提(ホスト専用)。`no_std` ターゲット向けのワークスペース横断
//! クロス check を壊さないよう、`target_os = "none"` では最小の `no_main` スタブに縮退する。

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
mod report {
    use bloat_check::{default_stack, minimal_stack, Kind, Row, MAX_PACKET_SIZE};

    // 計測レポートは固定ラベルを整形して並べる。print_literal はここでは意図的。
    #[allow(clippy::print_literal)]
    fn print_profile(title: &str, rows: &[Row]) {
        println!("\n=== {title} ===");
        println!("{:<34} {:>10}  {}", "component", "bytes", "group");

        let mut stack_total = 0usize;
        let mut external_total = 0usize;
        let mut stack_reported = 0usize;

        for r in rows {
            let group = match r.kind {
                Kind::StackField => {
                    stack_total += r.bytes;
                    "stack"
                }
                Kind::StackTotal => {
                    stack_reported = r.bytes;
                    "check"
                }
                Kind::Nested => "  (in mgr)",
                Kind::External => {
                    external_total += r.bytes;
                    "external"
                }
            };
            println!("{:<34} {:>10}  {}", r.name, r.bytes, group);
        }

        println!("{:-<56}", "");
        println!("{:<34} {:>10}", "sum(stack fields)", stack_total);
        println!(
            "{:<34} {:>10}  (size_of MatterStack; 検算 {})",
            "MatterStack total",
            stack_reported,
            if stack_reported == stack_total {
                "OK"
            } else {
                "≒ (padding)"
            }
        );
        println!("{:<34} {:>10}", "sum(external)", external_total);
        let device_total = stack_reported + external_total;
        println!("{:<34} {:>10}", "DEVICE RAM TOTAL", device_total);
        println!(
            "  = MatterStack({}) + external({})  ≈ {:.1} KiB",
            stack_reported,
            external_total,
            device_total as f64 / 1024.0
        );
    }

    pub fn run() {
        println!("simple-matter bloat-check: RAM (core::mem::size_of) report");
        println!("On/Off light device (EP0: BasicInfo/GenComm/NetComm/OpCreds/Descriptor, EP1: OnOff/Descriptor)");
        println!("MAX_PACKET_SIZE = {MAX_PACKET_SIZE} B (TX buffers + resp scratch)");

        print_profile(
            "DefaultStack (NF=5 S=4 E=4 TX=3 H=1 R=2 SUB=3 P=8)",
            &default_stack(),
        );
        print_profile(
            "MinimalStack (NF=2 S=3 E=3 TX=2 H=1 R=1 SUB=2 P=4)",
            &minimal_stack(),
        );

        println!("\nreference: rs-matter 公称下限 = 1 MB flash / 256 KB (262144 B) RAM");
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    report::run();
}

// `no_std` クロスターゲットでは RAM レポート(std)は意味を持たない。ワークスペース横断の
// `cargo check --target <MCU>` を通すための最小スタブ。
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

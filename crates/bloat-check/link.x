/* 最小リンカスクリプト(flash 計測専用)。
 *
 * HAL/cortex-m-rt に依存せず、`flash-probe` を単独でリンクしてセクションサイズを測る
 * ためだけのもの。ベクタテーブルや実機ブートは考慮しない(計測のみ)。メモリ量は
 * rs-matter 公称下限(1 MB flash / 256 KB RAM)に合わせた仮想レイアウト。
 */

ENTRY(_start);

MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}

SECTIONS
{
  .text :
  {
    KEEP(*(.text._start))
    *(.text .text.*)
  } > FLASH

  .rodata :
  {
    *(.rodata .rodata.*)
  } > FLASH

  .data :
  {
    *(.data .data.*)
  } > RAM AT> FLASH

  .bss :
  {
    *(.bss .bss.*)
    *(COMMON)
  } > RAM

  /DISCARD/ :
  {
    *(.ARM.exidx*)
    *(.ARM.extab*)
    *(.eh_frame*)
    *(.debug_gdb_scripts)
  }
}

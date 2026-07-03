# simple_matter

小フットプリントの Matter プロトコル実装(Rust / `no_std`、alloc は optional)。

まずは Matter デバイス側(コントローリ/responder)の実装を目標とし、
コントローラ側は将来スコープとする。connectedhomeip の大きさに対処し、
rs-matter の公称下限(1MB flash / 256KB RAM)を下回るターゲットを狙う。

## ドキュメント

- [設計方針](docs/ARCHITECTURE.md) — レイヤ構成・設計原則・ロードマップ
- 既存実装の構造調査:
  - [rs-matter](docs/research/rs-matter.md)
  - [matter.js](docs/research/matter-js.md)
  - [connectedhomeip](docs/research/connectedhomeip.md)

## 構成

- [crates/simple-matter](crates/simple-matter/) — コアクレート(`#![no_std]`、alloc は optional feature)

//! Interaction Model(IM, Protocol ID 0x0001)層。
//!
//! 本モジュールはロードマップ第5段階の最初のピースとして **ワイヤ層(codec)** だけを
//! 提供する。`docs/design/interaction-model.md` §2 の `im/wire` に相当し、IM メッセージ・
//! IB(Information Block)・パス・Status の TLV エンコード/デコードのみを担う。
//! `DataModel`(dm 層)やトランザクション処理(エンジン)は次ピースのスコープであり、
//! 本モジュールはそれらを一切知らない(chip の `protocols/interaction_model` = 定数/語彙のみ、
//! を踏襲した「継ぎ目」)。
//!
//! # 設計ドキュメントからの構成上の乖離
//!
//! 設計 §1 は wire を `im/wire/{mod,path,ib,status}.rs` に細分するが、本ピースの範囲が
//! codec のみであること・タグ番号に敏感なコードを 1 か所で見通し良く保つことを優先し、
//! 単一ファイル [`wire`] に集約した(エンジン実装時に分割可能)。ID 新型
//! ([`wire::EndpointId`] 等)は設計 §7.3 に従い [`crate::dm::meta`] を正典とし、`wire` からは
//! 再エクスポートする(dm 層実装により移設済み)。

pub mod wire;

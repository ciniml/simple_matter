//! 属性値の履歴(設計 doc §9 W5: 時系列グラフ)。
//!
//! コントローラスレッドが `Event::Attr` を流すときに **数値の属性だけ**(クラスタ表の
//! `ValueKind` が整数 / 浮動小数 / Bool。列挙は表では整数型なので index のまま)を
//! 系列 `(node, ep, cluster, attr)` ごとのリングバッファ `(ts_ms, f64)` に積む。
//! 文字列・Raw・ステータス・null は保持しない。
//!
//! REST(`GET /api/nodes/{id}/history`)は `Arc<RwLock<History>>` を読むだけで、
//! コントローラスレッドを待たない(Snapshot と同じ)。
//!
//! 永続化は `<state-dir>/smweb-history.bin`(独自の単純バイナリ、すべてリトルエンディアン):
//!
//! ```text
//! header : magic "SMWH" (4) | version u16 (=1) | reserved u16 (=0) | series u32
//! series : node u64 | ep u16 | cluster u32 | attr u32 | n u32 | n × (ts_ms u64, value f64)
//! ```
//!
//! 長さが合わない・magic / version 違い・末尾に余り → 壊れているとみなし、呼び出し側が
//! `.bad` へ退避して空から始める([`History::load_or_quarantine`])。

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};
use smctl::clusters::{self, ValueKind};
use smctl::simple_matter::dm::meta::{AttributeId, ClusterId};

use crate::model::AttrPath;

/// ファイル名(状態ディレクトリ直下)。
pub const FILE_NAME: &str = "smweb-history.bin";
/// 1 系列あたりの既定点数(10 秒周期で 8 時間、§9.1)。
pub const DEFAULT_POINTS: usize = 2880;
/// `--history-points` の上限(1 系列 16 B/点 → 1M 点で 16 MB)。
pub const MAX_POINTS: usize = 1_000_000;

const MAGIC: &[u8; 4] = b"SMWH";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 12;
const SERIES_HEAD_LEN: usize = 8 + 2 + 4 + 4 + 4;
const POINT_LEN: usize = 16;

/// ファイル書き込みの直列化(コントローラスレッドの定期保存と終了時の保存が重なっても
/// 同じ一時ファイルを奪い合わないように)。
static SAVE_LOCK: Mutex<()> = Mutex::new(());

/// 系列キー。
pub type SeriesKey = (u64, AttrPath);

/// 1 点 `(ts_ms, value)`。
pub type Point = (u64, f64);

/// 系列の要約(`GET /api/nodes/{id}/history` のクエリ無し)。
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesInfo {
    pub path: AttrPath,
    pub count: usize,
    pub first_ts: u64,
    pub last_ts: u64,
}

/// 全系列の履歴。
#[derive(Debug, Clone)]
pub struct History {
    cap: usize,
    series: BTreeMap<SeriesKey, VecDeque<Point>>,
    /// 最後の保存以降に変化があったか。
    dirty: bool,
}

impl Default for History {
    fn default() -> Self {
        Self::new(DEFAULT_POINTS)
    }
}

/// クラスタ表の属性型(表に無ければ `None`)。
pub fn attr_kind(cluster: u32, attr: u32) -> Option<ValueKind> {
    clusters::by_id(ClusterId(cluster))
        .and_then(|c| c.attr_by_id(AttributeId(attr)))
        .map(|a| a.kind)
}

/// 履歴に積める型か(整数 / 浮動小数 / Bool)。
pub fn is_numeric_kind(kind: ValueKind) -> bool {
    matches!(
        kind,
        ValueKind::Bool
            | ValueKind::U8
            | ValueKind::U16
            | ValueKind::U32
            | ValueKind::U64
            | ValueKind::I8
            | ValueKind::I16
            | ValueKind::I32
            | ValueKind::I64
            | ValueKind::F32
            | ValueKind::F64
    )
}

/// §5.3 の JSON 値 → 履歴の数値。数値型でない・null・オブジェクト(raw / status)は `None`。
pub fn numeric_value(kind: Option<ValueKind>, v: &Value) -> Option<f64> {
    if !is_numeric_kind(kind?) {
        return None;
    }
    match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64().filter(|x| x.is_finite()),
        _ => None,
    }
}

impl History {
    /// 1 系列あたり `cap` 点(1 未満は 1)。
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.clamp(1, MAX_POINTS),
            series: BTreeMap::new(),
            dirty: false,
        }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    #[cfg(test)]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 1 点を積む(上限を超えたら古い点から捨てる)。
    pub fn push(&mut self, node_id: u64, path: AttrPath, ts_ms: u64, value: f64) {
        if !value.is_finite() {
            return;
        }
        let q = self.series.entry((node_id, path)).or_default();
        while q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back((ts_ms, value));
        self.dirty = true;
    }

    /// 属性値(§5.3 の JSON)を、数値型なら積む。戻り値 = 積んだか。
    pub fn record(&mut self, node_id: u64, path: AttrPath, ts_ms: u64, value: &Value) -> bool {
        match numeric_value(attr_kind(path.cluster, path.attr), value) {
            Some(x) => {
                self.push(node_id, path, ts_ms, x);
                true
            }
            None => false,
        }
    }

    /// `ts >= since` の点のうち **新しい側から最大 `limit` 点**(時刻昇順で返す)。
    pub fn query(&self, node_id: u64, path: AttrPath, since: u64, limit: usize) -> Vec<Point> {
        let Some(q) = self.series.get(&(node_id, path)) else {
            return Vec::new();
        };
        let matching: Vec<Point> = q.iter().copied().filter(|p| p.0 >= since).collect();
        let skip = matching.len().saturating_sub(limit);
        matching.into_iter().skip(skip).collect()
    }

    /// ノードの系列一覧(パス昇順)。
    pub fn series_list(&self, node_id: u64) -> Vec<SeriesInfo> {
        self.series
            .range(
                (node_id, AttrPath::new(0, 0, 0))
                    ..=(node_id, AttrPath::new(u16::MAX, u32::MAX, u32::MAX)),
            )
            .filter(|(_, q)| !q.is_empty())
            .map(|((_, path), q)| SeriesInfo {
                path: *path,
                count: q.len(),
                first_ts: q.front().map(|p| p.0).unwrap_or(0),
                last_ts: q.back().map(|p| p.0).unwrap_or(0),
            })
            .collect()
    }

    /// ノードの全系列を消す(unpair)。戻り値 = 消した系列数。
    pub fn remove_node(&mut self, node_id: u64) -> usize {
        let before = self.series.len();
        self.series.retain(|(n, _), _| *n != node_id);
        let removed = before - self.series.len();
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }

    /// `keep` に無いノードの系列を消す(起動時: アドレス帳から消えたノードの掃除)。
    pub fn retain_nodes(&mut self, keep: &[u64]) -> usize {
        let before = self.series.len();
        self.series.retain(|(n, _), _| keep.contains(n));
        let removed = before - self.series.len();
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }

    /// 系列数(テスト・ログ用)。
    pub fn len(&self) -> usize {
        self.series.len()
    }

    /// ファイル形式へ直列化する。
    pub fn to_bytes(&self) -> Vec<u8> {
        let points: usize = self.series.values().map(VecDeque::len).sum();
        let mut b = Vec::with_capacity(
            HEADER_LEN + self.series.len() * SERIES_HEAD_LEN + points * POINT_LEN,
        );
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(self.series.len() as u32).to_le_bytes());
        for ((node, p), q) in &self.series {
            b.extend_from_slice(&node.to_le_bytes());
            b.extend_from_slice(&p.ep.to_le_bytes());
            b.extend_from_slice(&p.cluster.to_le_bytes());
            b.extend_from_slice(&p.attr.to_le_bytes());
            b.extend_from_slice(&(q.len() as u32).to_le_bytes());
            for (ts, v) in q {
                b.extend_from_slice(&ts.to_le_bytes());
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
        b
    }

    /// ファイル形式から復元する(系列が `cap` を超えていれば新しい側を残す)。
    pub fn from_bytes(b: &[u8], cap: usize) -> Result<Self, String> {
        let mut r = Rd { b, pos: 0 };
        if r.take(4)? != MAGIC {
            return Err("bad magic".into());
        }
        let ver = r.u16()?;
        if ver != VERSION {
            return Err(format!("unsupported version {ver}"));
        }
        let _reserved = r.u16()?;
        let n_series = r.u32()? as usize;
        let mut h = Self::new(cap);
        for _ in 0..n_series {
            let node = r.u64()?;
            let ep = r.u16()?;
            let cluster = r.u32()?;
            let attr = r.u32()?;
            let n = r.u32()? as usize;
            if n.checked_mul(POINT_LEN)
                .is_none_or(|len| len > r.remaining())
            {
                return Err("truncated series".into());
            }
            let skip = n.saturating_sub(h.cap);
            let mut q = VecDeque::with_capacity(n - skip);
            for i in 0..n {
                let ts = r.u64()?;
                let v = f64::from_le_bytes(r.take(8)?.try_into().expect("8 bytes"));
                if i >= skip && v.is_finite() {
                    q.push_back((ts, v));
                }
            }
            let key = (node, AttrPath::new(ep, cluster, attr));
            if h.series.insert(key, q).is_some() {
                return Err("duplicate series".into());
            }
        }
        if r.remaining() != 0 {
            return Err(format!("{} trailing byte(s)", r.remaining()));
        }
        Ok(h)
    }

    /// 読む。無ければ空。壊れていればエラー。
    pub fn load(path: &Path, cap: usize) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(b) => Self::from_bytes(&b, cap).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new(cap)),
            Err(e) => Err(format!("read {}: {e}", path.display())),
        }
    }

    /// 読む。壊れていれば `<file>.bad` へ退避して空から始める(戻り値の 2 つ目 = 理由)。
    pub fn load_or_quarantine(path: &Path, cap: usize) -> (Self, Option<String>) {
        match Self::load(path, cap) {
            Ok(h) => (h, None),
            Err(e) => {
                let _ = std::fs::rename(path, bad_path(path));
                (Self::new(cap), Some(e))
            }
        }
    }

    /// 書く(一時ファイル + rename)。成功したら dirty を下ろす(本体は [`save_shared`] を使う)。
    #[cfg(test)]
    pub fn save(&mut self, path: &Path) -> Result<(), String> {
        write_file(path, &self.to_bytes())?;
        self.dirty = false;
        Ok(())
    }
}

/// 壊れたファイルの退避先(`smweb-history.bin.bad`)。
pub fn bad_path(path: &Path) -> PathBuf {
    path.with_extension("bin.bad")
}

/// パス(`<state-dir>/smweb-history.bin`)。
pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let _g = SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = path.with_extension("bin.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

/// 共有中の履歴を(変化があれば)保存する。直列化だけロック下で行い、ファイル書き込みは
/// ロックの外(REST の読み取りを塞がない)。戻り値 = 書いたか。
pub fn save_shared(h: &std::sync::RwLock<History>, path: &Path) -> Result<bool, String> {
    let bytes = {
        let mut g = h.write().unwrap_or_else(|p| p.into_inner());
        if !g.dirty {
            return Ok(false);
        }
        g.dirty = false;
        g.to_bytes()
    };
    if let Err(e) = write_file(path, &bytes) {
        // 次の機会に再試行する。
        h.write().unwrap_or_else(|p| p.into_inner()).dirty = true;
        return Err(e);
    }
    Ok(true)
}

/// `GET /api/nodes/{id}/history?ep=&cluster=&attr=` の応答本体。
pub fn query_json(h: &History, node_id: u64, path: AttrPath, since: u64, limit: usize) -> Value {
    let pts = h.query(node_id, path, since, limit);
    let hint = crate::value::display_hint(path.cluster, path.attr);
    let hint_field = |k: &str| hint.as_ref().and_then(|v| v.get(k)).cloned();
    json!({
        "node_id": node_id,
        "ep": path.ep,
        "cluster": path.cluster,
        "attr": path.attr,
        "kind": attr_kind(path.cluster, path.attr).map(|k| k.name()),
        "unit": hint_field("unit"),
        "scale": hint_field("scale"),
        "enum": hint_field("enum"),
        "points": pts.iter().map(|(t, v)| json!([t, v])).collect::<Vec<_>>(),
    })
}

/// `GET /api/nodes/{id}/history`(クエリ無し)の応答本体。
pub fn list_json(h: &History, node_id: u64) -> Value {
    Value::Array(
        h.series_list(node_id)
            .into_iter()
            .map(|s| {
                json!({
                    "ep": s.path.ep,
                    "cluster": s.path.cluster,
                    "attr": s.path.attr,
                    "count": s.count,
                    "first_ts": s.first_ts,
                    "last_ts": s.last_ts,
                })
            })
            .collect(),
    )
}

/// バイト列の読み取り(境界チェック付き)。
struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.remaining() < n {
            return Err("unexpected end of file".into());
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2")))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CO2: AttrPath = AttrPath::new(1, 0x040D, 0);
    const TEMP: AttrPath = AttrPath::new(2, 0x0402, 0);

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("smweb-hist-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ring_buffer_capacity() {
        let mut h = History::new(3);
        for i in 0..5u64 {
            h.push(33, CO2, 1000 + i, i as f64);
        }
        let all = h.query(33, CO2, 0, usize::MAX);
        assert_eq!(all, vec![(1002, 2.0), (1003, 3.0), (1004, 4.0)]);
        assert_eq!(h.cap(), 3);
        // 0 は 1 に丸める。
        let mut h1 = History::new(0);
        h1.push(1, CO2, 1, 1.0);
        h1.push(1, CO2, 2, 2.0);
        assert_eq!(h1.query(1, CO2, 0, 10), vec![(2, 2.0)]);
        // 非有限値は捨てる。
        h1.push(1, CO2, 3, f64::NAN);
        assert_eq!(h1.query(1, CO2, 0, 10).len(), 1);
    }

    #[test]
    fn since_and_limit_filtering() {
        let mut h = History::new(100);
        for i in 0..10u64 {
            h.push(33, CO2, i * 10, i as f64);
        }
        // since は境界を含む。
        let p = h.query(33, CO2, 50, 100);
        assert_eq!(p.first(), Some(&(50, 5.0)));
        assert_eq!(p.len(), 5);
        // limit は新しい側から。
        assert_eq!(
            h.query(33, CO2, 0, 3),
            vec![(70, 7.0), (80, 8.0), (90, 9.0)]
        );
        assert_eq!(h.query(33, CO2, 85, 3), vec![(90, 9.0)]);
        assert!(h.query(33, CO2, 1000, 3).is_empty());
        assert!(h.query(33, CO2, 0, 0).is_empty());
        // 未知の系列・ノードは空。
        assert!(h.query(33, TEMP, 0, 10).is_empty());
        assert!(h.query(34, CO2, 0, 10).is_empty());
    }

    #[test]
    fn numeric_kind_filtering() {
        let mut h = History::new(10);
        // CO2 MeasuredValue(f32)。
        assert!(h.record(33, CO2, 1, &json!(812.5)));
        // Temperature(i16)。
        assert!(h.record(33, TEMP, 1, &json!(2345)));
        // AirQuality(enum = u8)は index のまま。
        let aq = AttrPath::new(1, 0x005B, 0);
        assert!(h.record(33, aq, 1, &json!(3)));
        // OnOff(bool)→ 0/1。
        let onoff = AttrPath::new(1, 0x0006, 0);
        assert!(h.record(33, onoff, 1, &json!(true)));
        assert!(h.record(33, onoff, 2, &json!(false)));
        assert_eq!(h.query(33, onoff, 0, 10), vec![(1, 1.0), (2, 0.0)]);
        // 文字列(BasicInformation.VendorName = utf8)は積まない。
        assert!(!h.record(33, AttrPath::new(0, 0x0028, 1), 3, &json!("Acme")));
        // null / ステータス / raw オブジェクトも積まない。
        assert!(!h.record(33, CO2, 2, &Value::Null));
        assert!(!h.record(33, CO2, 2, &json!({"status": "UnsupportedAttribute"})));
        // 表に無い属性(raw)は積まない。
        assert!(!h.record(33, AttrPath::new(1, 0xFFF1_FC00, 0), 3, &json!(5)));
        assert_eq!(h.len(), 4);
        assert!(numeric_value(Some(ValueKind::Utf8), &json!(1)).is_none());
        assert!(numeric_value(Some(ValueKind::Raw), &json!(1)).is_none());
        assert!(numeric_value(None, &json!(1)).is_none());
        assert_eq!(numeric_value(Some(ValueKind::I8), &json!(-4)), Some(-4.0));
    }

    #[test]
    fn series_list_and_remove_node() {
        let mut h = History::new(10);
        h.push(33, TEMP, 5, 1.0);
        h.push(33, CO2, 1, 1.0);
        h.push(33, CO2, 9, 2.0);
        h.push(34, CO2, 7, 3.0);
        let l = h.series_list(33);
        assert_eq!(
            l,
            vec![
                SeriesInfo {
                    path: CO2,
                    count: 2,
                    first_ts: 1,
                    last_ts: 9
                },
                SeriesInfo {
                    path: TEMP,
                    count: 1,
                    first_ts: 5,
                    last_ts: 5
                },
            ]
        );
        let j = list_json(&h, 33);
        assert_eq!(j[0]["cluster"], 0x040D);
        assert_eq!(j[0]["count"], 2);
        assert_eq!(j[1]["first_ts"], 5);
        // unpair 相当: 33 の系列だけ消える。
        assert_eq!(h.remove_node(33), 2);
        assert!(h.series_list(33).is_empty());
        assert_eq!(h.series_list(34).len(), 1);
        assert_eq!(h.remove_node(33), 0);
        // 起動時の掃除。
        h.push(35, CO2, 1, 1.0);
        assert_eq!(h.retain_nodes(&[35]), 1);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn file_round_trip() {
        let d = tmp_dir("rt");
        let p = path(&d);
        let mut h = History::new(100);
        for i in 0..20u64 {
            h.push(
                33,
                CO2,
                1_700_000_000_000 + i * 10_000,
                400.0 + i as f64 * 0.5,
            );
        }
        h.push(33, TEMP, 1, -12.25);
        h.push(
            u64::MAX,
            AttrPath::new(u16::MAX, u32::MAX, u32::MAX),
            u64::MAX,
            1e300,
        );
        assert!(h.is_dirty());
        h.save(&p).unwrap();
        assert!(!h.is_dirty());
        let back = History::load(&p, 100).unwrap();
        assert_eq!(back.series, h.series);
        assert!(!back.is_dirty());
        // 小さい cap で読むと新しい側が残る。
        let small = History::load(&p, 5).unwrap();
        let q = small.query(33, CO2, 0, usize::MAX);
        assert_eq!(q.len(), 5);
        assert_eq!(q.last(), h.query(33, CO2, 0, usize::MAX).last());
        // 無ければ空。
        let none = History::load(&d.join("missing.bin"), 10).unwrap();
        assert_eq!(none.len(), 0);
        // 共有経路の保存(dirty のときだけ書く)。
        let shared = std::sync::RwLock::new(back);
        assert!(!save_shared(&shared, &p).unwrap());
        shared.write().unwrap().push(33, CO2, 9, 9.0);
        assert!(save_shared(&shared, &p).unwrap());
        assert_eq!(
            History::load(&p, 100).unwrap().query(33, CO2, 9, 1),
            vec![(9, 9.0)]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_file_is_quarantined() {
        let d = tmp_dir("bad");
        let p = path(&d);
        let mut h = History::new(10);
        h.push(33, CO2, 1, 1.0);
        h.push(33, CO2, 2, 2.0);
        let good = h.to_bytes();
        // 途中で切れている / magic 違い / version 違い / 余り / 点数が過大。
        let mut cases: Vec<Vec<u8>> = vec![
            good[..good.len() - 3].to_vec(),
            b"NOPE".iter().chain(&good[4..]).copied().collect(),
            {
                let mut b = good.clone();
                b[4] = 9;
                b
            },
            {
                let mut b = good.clone();
                b.push(0);
                b
            },
            {
                let mut b = good.clone();
                // 系列ヘッダの n(先頭系列: HEADER_LEN + 18)を巨大値に。
                b[HEADER_LEN + 18..HEADER_LEN + 22].copy_from_slice(&u32::MAX.to_le_bytes());
                b
            },
            Vec::new(),
        ];
        for (i, bytes) in cases.drain(..).enumerate() {
            assert!(History::from_bytes(&bytes, 10).is_err(), "case {i}");
            std::fs::write(&p, &bytes).unwrap();
            let (h2, err) = History::load_or_quarantine(&p, 10);
            assert!(err.is_some(), "case {i}");
            assert_eq!(h2.len(), 0);
            assert!(!p.exists(), "case {i}: original moved away");
            assert_eq!(std::fs::read(bad_path(&p)).unwrap(), bytes);
        }
        // 正常なファイルは退避しない。
        std::fs::write(&p, &good).unwrap();
        let (h3, err) = History::load_or_quarantine(&p, 10);
        assert!(err.is_none());
        assert_eq!(h3.query(33, CO2, 0, 10), vec![(1, 1.0), (2, 2.0)]);
        assert!(p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn query_json_shape() {
        let mut h = History::new(10);
        h.push(33, TEMP, 100, 2345.0);
        h.push(33, TEMP, 200, 2350.0);
        let v = query_json(&h, 33, TEMP, 150, 10);
        assert_eq!(v["points"], json!([[200, 2350.0]]));
        assert_eq!(v["unit"], "°C");
        assert_eq!(v["scale"], 0.01);
        assert_eq!(v["kind"], "i16");
        let v = query_json(&h, 33, CO2, 0, 10);
        assert_eq!(v["points"], json!([]));
        assert_eq!(v["unit"], "ppm");
        assert!(v["scale"].is_null());
    }
}

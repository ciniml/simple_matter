// 合成可能クラスタ / デバイスタイプ / ドライバ / プリセットのカタログ。
//
// クラスタの一覧と個数上限は docs/design/generic-firmware.md §9.1(= シムの
// `crates/simple-matter-cffi/src/compose.rs` の static プール)と 1 対 1。
// ドライバの params は §9.2(= `main/bind_tlv.hpp` / `scripts/smgen-tlv.py` の PARAMS)。

/** 合成可能クラスタ(16 種)。`max` は static プールの個数上限。 */
export const CLUSTERS = [
  { id: 0x0003, name: "Identify", max: 8, group: "共通" },
  { id: 0x0004, name: "Groups", max: 8, group: "共通" },
  { id: 0x0006, name: "On/Off", max: 8, group: "アクチュエータ" },
  { id: 0x0008, name: "Level Control", max: 4, group: "アクチュエータ" },
  { id: 0x0300, name: "Color Control", max: 2, group: "アクチュエータ" },
  { id: 0x0202, name: "Fan Control", max: 2, group: "アクチュエータ" },
  { id: 0x0101, name: "Door Lock", max: 1, group: "アクチュエータ" },
  { id: 0x0201, name: "Thermostat", max: 1, group: "アクチュエータ" },
  { id: 0x0045, name: "Boolean State", max: 4, group: "入力" },
  { id: 0x003b, name: "Switch", max: 4, group: "入力" },
  { id: 0x0406, name: "Occupancy Sensing", max: 2, group: "入力" },
  { id: 0x0400, name: "Illuminance Measurement", max: 4, group: "計測" },
  { id: 0x0402, name: "Temperature Measurement", max: 4, group: "計測" },
  { id: 0x0403, name: "Pressure Measurement", max: 4, group: "計測" },
  { id: 0x0404, name: "Flow Measurement", max: 4, group: "計測" },
  { id: 0x0405, name: "Relative Humidity Measurement", max: 4, group: "計測" },
];

export const CLUSTER_BY_ID = new Map(CLUSTERS.map((c) => [c.id, c]));

/** Descriptor は合成器が自動付与するので UI では選ばせない。 */
export const CLUSTER_DESCRIPTOR = 0x001d;

/** エンドポイント数 / EP あたりクラスタ数 / slot 総数の上限(§9.1)。 */
export const LIMITS = { maxEndpoints: 8, clustersPerEndpoint: 12, totalSlots: 40, options: 16 };

/**
 * デバイスタイプの代表マッピング。`clusters` は「そのデバイスタイプで普通に載せる
 * サーバクラスタ」で、UI がプリセット選択時に自動チェックする。
 */
export const DEVICE_TYPES = [
  { id: 0x0100, rev: 2, name: "On/Off Light", clusters: [0x0003, 0x0004, 0x0006] },
  { id: 0x0101, rev: 3, name: "Dimmable Light", clusters: [0x0003, 0x0004, 0x0006, 0x0008] },
  {
    id: 0x010c,
    rev: 4,
    name: "Color Temperature Light",
    clusters: [0x0003, 0x0004, 0x0006, 0x0008, 0x0300],
  },
  {
    id: 0x010d,
    rev: 4,
    name: "Extended Color Light",
    clusters: [0x0003, 0x0004, 0x0006, 0x0008, 0x0300],
  },
  { id: 0x010a, rev: 3, name: "On/Off Plug-in Unit", clusters: [0x0003, 0x0004, 0x0006] },
  { id: 0x010b, rev: 4, name: "Dimmable Plug-in Unit", clusters: [0x0003, 0x0004, 0x0006, 0x0008] },
  { id: 0x002b, rev: 2, name: "Fan", clusters: [0x0003, 0x0004, 0x0202] },
  { id: 0x000a, rev: 3, name: "Door Lock", clusters: [0x0003, 0x0101] },
  { id: 0x0301, rev: 3, name: "Thermostat", clusters: [0x0003, 0x0004, 0x0201] },
  { id: 0x000f, rev: 1, name: "Generic Switch", clusters: [0x0003, 0x003b] },
  { id: 0x0015, rev: 1, name: "Contact Sensor", clusters: [0x0003, 0x0045] },
  { id: 0x0107, rev: 3, name: "Occupancy Sensor", clusters: [0x0003, 0x0406] },
  { id: 0x0302, rev: 2, name: "Temperature Sensor", clusters: [0x0003, 0x0402] },
  { id: 0x0307, rev: 2, name: "Humidity Sensor", clusters: [0x0003, 0x0405] },
  { id: 0x0106, rev: 2, name: "Light Sensor", clusters: [0x0003, 0x0400] },
  { id: 0x0305, rev: 2, name: "Pressure Sensor", clusters: [0x0003, 0x0403] },
  { id: 0x0306, rev: 2, name: "Flow Sensor", clusters: [0x0003, 0x0404] },
];

export const DEVICE_TYPE_BY_ID = new Map(DEVICE_TYPES.map((d) => [d.id, d]));

/**
 * ドライバのパラメータフォーム定義(§9.2)。
 * `targets` は結び付けられる代表クラスタ。
 */
export const DRIVER_FORMS = [
  {
    id: 1,
    name: "gpio_out",
    label: "GPIO 出力",
    targets: [0x0006],
    params: [
      { name: "pin", label: "GPIO 番号", type: "int", min: 0, max: 63, default: 7 },
      { name: "invert", label: "反転(Low=ON)", type: "bool", default: false },
    ],
  },
  {
    id: 2,
    name: "gpio_in",
    label: "GPIO 入力(ポーリング + デバウンス)",
    targets: [0x0045, 0x003b],
    params: [
      { name: "pin", label: "GPIO 番号", type: "int", min: 0, max: 63, default: 9 },
      { name: "invert", label: "反転", type: "bool", default: false },
      { name: "poll_ms", label: "ポーリング周期 (ms)", type: "int", min: 1, max: 65535, default: 50 },
      {
        name: "pull",
        label: "プル",
        type: "enum",
        options: [
          { value: 0, label: "なし" },
          { value: 1, label: "プルアップ(既定)" },
          { value: 2, label: "プルダウン" },
        ],
        default: 1,
      },
    ],
  },
  {
    id: 3,
    name: "ledc",
    label: "LEDC PWM",
    targets: [0x0008],
    params: [
      { name: "ch", label: "LEDC チャネル", type: "int", min: 0, max: 7, default: 0 },
      { name: "pin", label: "GPIO 番号", type: "int", min: 0, max: 63, default: 6 },
      { name: "freq", label: "周波数 (Hz)", type: "int", min: 1, max: 40000000, default: 1000 },
      { name: "invert", label: "反転", type: "bool", default: false },
    ],
  },
  {
    id: 4,
    name: "i2c_sht30",
    label: "I2C SHT30 温湿度センサ",
    targets: [0x0402],
    params: [
      { name: "sda", label: "SDA GPIO", type: "int", min: 0, max: 63, default: 8 },
      { name: "scl", label: "SCL GPIO", type: "int", min: 0, max: 63, default: 9 },
      { name: "poll_ms", label: "測定周期 (ms)", type: "int", min: 1, max: 65535, default: 5000 },
      { name: "port", label: "I2C ポート", type: "int", min: 0, max: 1, default: 0 },
    ],
  },
  {
    id: 5,
    name: "script",
    label: "WASM スクリプト(on_sensor フックへ委譲)",
    targets: [],
    params: [
      {
        name: "poll_ms",
        label: "周期発火 (ms、0 = 属性変化時のみ)",
        type: "int",
        min: 0,
        max: 4294967295,
        default: 0,
      },
    ],
  },
];

export const DRIVER_FORM_BY_NAME = new Map(DRIVER_FORMS.map((d) => [d.name, d]));

/**
 * 既存プリセット 2 種(`scripts/smgen-tlv.py examples` の ① / ② と同一)。
 * 生成される TLV hex も同一になる(test/tlv.test.js が検証)。
 */
export const PRESETS = [
  {
    key: "onoff-light",
    label: "① On/Off ライト(EP1: Identify/Groups/OnOff、GPIO7)",
    comp: [
      { ep: 1, device_type: 0x0100, rev: 2, clusters: [0x0003, 0x0004, 0x0006] },
    ],
    bind: [{ ep: 1, cluster: 0x0006, drv: "gpio_out", params: { pin: 7, invert: false } }],
  },
  {
    key: "dimmer-sensor",
    label: "② 調光ライト + 温湿度計 2EP(EP1: +LevelControl→LEDC、EP2: SHT30)",
    comp: [
      { ep: 1, device_type: 0x0101, rev: 3, clusters: [0x0003, 0x0004, 0x0006, 0x0008] },
      { ep: 2, device_type: 0x0302, rev: 2, clusters: [0x0402, 0x0405] },
    ],
    bind: [
      { ep: 1, cluster: 0x0008, drv: "ledc", params: { ch: 0, pin: 6, freq: 1000 } },
      { ep: 2, cluster: 0x0402, drv: "i2c_sht30", params: { sda: 8, scl: 9, poll_ms: 5000 } },
    ],
  },
];

/**
 * 構成の妥当性検査(§9.1 の上限)。エラー文字列の配列を返す。
 */
export function validateComposition(spec) {
  const errors = [];
  if (spec.length === 0) {
    errors.push("エンドポイントが 1 つも定義されていません。");
  }
  if (spec.length > LIMITS.maxEndpoints) {
    errors.push(`エンドポイントは最大 ${LIMITS.maxEndpoints} 個です(${spec.length} 個)。`);
  }
  const seenEp = new Set();
  const counts = new Map();
  let slots = 0;
  for (const ep of spec) {
    if (ep.ep < 1 || ep.ep > LIMITS.maxEndpoints) {
      errors.push(`エンドポイント ID ${ep.ep} は 1..${LIMITS.maxEndpoints} の範囲外です(0 は予約)。`);
    }
    if (seenEp.has(ep.ep)) {
      errors.push(`エンドポイント ID ${ep.ep} が重複しています。`);
    }
    seenEp.add(ep.ep);
    const clusters = ep.clusters.filter((c) => c !== CLUSTER_DESCRIPTOR);
    if (clusters.length === 0) {
      errors.push(`EP${ep.ep}: クラスタが 1 つも選ばれていません。`);
    }
    if (clusters.length > LIMITS.clustersPerEndpoint) {
      errors.push(`EP${ep.ep}: クラスタは EP あたり最大 ${LIMITS.clustersPerEndpoint} 個です。`);
    }
    for (const c of clusters) {
      if (!CLUSTER_BY_ID.has(c)) {
        errors.push(`EP${ep.ep}: クラスタ 0x${c.toString(16)} は合成可能プールにありません。`);
        continue;
      }
      counts.set(c, (counts.get(c) || 0) + 1);
      slots++;
    }
  }
  for (const [id, n] of counts) {
    const cl = CLUSTER_BY_ID.get(id);
    if (n > cl.max) {
      errors.push(`${cl.name} は最大 ${cl.max} 個までです(${n} 個)。`);
    }
  }
  if (slots > LIMITS.totalSlots) {
    errors.push(`クラスタ slot 総数が上限 ${LIMITS.totalSlots} を超えました(${slots})。`);
  }
  return errors;
}

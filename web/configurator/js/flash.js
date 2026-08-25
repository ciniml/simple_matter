// esptool-js(Web Serial)による書き込みと、パーティションオフセットの定義。
//
// オフセットは `ports/esp-idf/examples/generic_matter_cpp/partitions.csv` と一致させる:
//
//   nvs           0x009000  24 KiB   コア KVS(`smatter`)+ 設定 blob(`smgen`)
//   phy_init      0x00F000   4 KiB
//   factory(app) 0x010000  2.5 MiB  アプリ本体
//   nvs_factory   0x290000  24 KiB   mfg_tool 互換 factory データ
//   smscript      0x296000 256 KiB   スクリプト(slot A / slot B 各 128 KiB)
//
// bootloader のオフセットはチップ依存(ESP-IDF `ESP_BOOTLOADER_OFFSET`)。

/** パーティションテーブル由来の固定オフセット。 */
export const OFFSETS = {
  partitionTable: 0x8000,
  nvs: 0x9000,
  app: 0x10000,
  nvsFactory: 0x290000,
  smscript: 0x296000,
  /** smscript の slot B(slot A + 128 KiB)。 */
  smscriptSlotB: 0x296000 + 0x20000,
};

/** パーティションのサイズ(検証用)。 */
export const SIZES = {
  nvs: 0x6000,
  app: 0x280000,
  nvsFactory: 0x6000,
  smscript: 0x40000,
};

/** チップ名 → bootloader オフセット(ESP-IDF の既定)。 */
export const BOOTLOADER_OFFSET = {
  ESP32: 0x1000,
  "ESP32-S2": 0x1000,
  "ESP32-S3": 0x0,
  "ESP32-C2": 0x0,
  "ESP32-C3": 0x0,
  "ESP32-C5": 0x2000,
  "ESP32-C6": 0x0,
  "ESP32-C61": 0x0,
  "ESP32-H2": 0x0,
  "ESP32-P4": 0x2000,
};

/** チップ名から bootloader オフセットを引く(未知チップは 0)。 */
export function bootloaderOffset(chipName) {
  return BOOTLOADER_OFFSET[chipName] ?? 0x0;
}

/** Web Serial が使えるか。 */
export function webSerialAvailable() {
  return typeof navigator !== "undefined" && "serial" in navigator;
}

/**
 * 書き込み対象の一覧を検証する(領域はみ出し / 重なりを弾く)。
 *
 * @param {{name: string, address: number, data: Uint8Array}[]} files
 * @returns {string[]} エラー文字列(空なら OK)
 */
export function validateFlashPlan(files) {
  const errors = [];
  const limits = [
    ["nvs", OFFSETS.nvs, SIZES.nvs],
    ["app", OFFSETS.app, SIZES.app],
    ["nvs_factory", OFFSETS.nvsFactory, SIZES.nvsFactory],
    ["smscript", OFFSETS.smscript, SIZES.smscript],
  ];
  for (const f of files) {
    for (const [name, start, size] of limits) {
      if (f.address === start && f.data.length > size) {
        errors.push(`${f.name}: ${f.data.length} B は ${name} パーティション(${size} B)に収まりません。`);
      }
    }
  }
  const sorted = [...files].sort((a, b) => a.address - b.address);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    if (prev.address + prev.data.length > sorted[i].address) {
      errors.push(
        `${prev.name}(0x${prev.address.toString(16)})と ${sorted[i].name}` +
          `(0x${sorted[i].address.toString(16)})の領域が重なっています。`
      );
    }
  }
  return errors;
}

/**
 * URL からバイナリを取得する(GitHub Release asset 等)。
 *
 * ブラウザからのクロスオリジン取得は相手サーバの CORS 設定次第で失敗する。
 * GitHub Release の `objects.githubusercontent.com` は現状 CORS 許可が無いため、
 * 失敗したらローカルファイル指定に切り替える旨を UI に出す。
 */
export async function fetchBinary(url) {
  const res = await fetch(url, { mode: "cors" });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * Web Serial ポートを開いて ESPLoader を用意する。
 *
 * @param {object} deps `{ ESPLoader, Transport }`(vendor の esptool-js から渡す)
 */
export async function connect(deps, { baudrate = 921600, romBaudrate = 115200, terminal } = {}) {
  if (!webSerialAvailable()) {
    throw new Error("この環境には Web Serial API がありません(Chrome / Edge 系を使ってください)。");
  }
  const device = await navigator.serial.requestPort({});
  const transport = new deps.Transport(device, true);
  const loader = new deps.ESPLoader({ transport, baudrate, romBaudrate, terminal });
  const chipDescription = await loader.main();
  return { loader, transport, chipDescription, chipName: loader.chip?.CHIP_NAME ?? "" };
}

/**
 * ファイル群を書き込む。
 *
 * @param {object} loader ESPLoader
 * @param {{name: string, address: number, data: Uint8Array}[]} files
 */
export async function writeAll(loader, files, { eraseAll = false, reportProgress } = {}) {
  const errors = validateFlashPlan(files);
  if (errors.length > 0) {
    throw new Error(errors.join("\n"));
  }
  await loader.writeFlash({
    fileArray: files.map((f) => ({ data: f.data, address: f.address })),
    flashSize: "keep",
    flashMode: "keep",
    flashFreq: "keep",
    eraseAll,
    compress: true,
    reportProgress,
  });
}

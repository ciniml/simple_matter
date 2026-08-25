// ESP-IDF NVS パーティションイメージ(平文、version 2)のジェネレータ。
//
// `nvs_partition_gen.py` / `esp-matter-mfg-tool` が出す `*-partition.bin` と同じ
// バイナリを作る。読み手は 2 つ:
//
//   - `crates/simple-matter/src/factory/nvs.rs`(simple-matter の読み取り専用パーサ)
//   - 実機の ESP-IDF `nvs_flash`(CRC を検証する ⇒ CRC を正しく作る必要がある)
//
// フォーマット(docs/design/factory-data.md §1.2 + 実生成物 `tests/fixtures/
// factory-fff1-8001.bin` から裏取り):
//
//   ページ = 4096 B = ヘッダ 32 B + エントリ状態ビットマップ 32 B + 126 × 32 B エントリ
//   ヘッダ: [0..4] state u32 / [4..8] seq u32 / [8] version(0xFE = v2) /
//           [9..28] 0xFF 詰め / [28..32] crc32(header[4..28], 初期値 0xFFFFFFFF)
//   エントリ: [0] ns / [1] type / [2] span / [3] chunkIndex / [4..8] crc32 /
//             [8..24] key(NUL 詰め 16B) / [24..32] data
//   エントリ crc32 = crc32(entry[0..4]) を初期値 0xFFFFFFFF で始め、続けて entry[8..32]
//   可変長型: data = [0..2] size u16 / [2..4] 0xFFFF / [4..8] crc32(本体, 初期値 0xFFFFFFFF)
//             本体は直後のエントリ領域に連続配置(span = 1 + ceil(size / 32))
//   BLOB は BLOB_DATA(0x42、chunkIndex=0)+ BLOB_IDX(0x48)のペア。
//             IDX の data = [0..4] 総サイズ u32 / [4] chunkCount / [5] chunkStart / [6..8] 0xFFFF

import { crc32, utf8, bytesToBase64 } from "./util.js";

export const PAGE_SIZE = 4096;
const PAGE_HEADER_LEN = 32;
const ENTRY_BITMAP_LEN = 32;
const ENTRY_SIZE = 32;
const ENTRIES_PER_PAGE = 126;
const ENTRY_DATA_OFFSET = PAGE_HEADER_LEN + ENTRY_BITMAP_LEN;

const PAGE_STATE_ACTIVE = 0xfffffffe;
const PAGE_VERSION_V2 = 0xfe;

const ENTRY_EMPTY = 0b11;
const ENTRY_WRITTEN = 0b10;

/** NVS エントリ型コード。 */
export const TYPE = {
  U8: 0x01,
  U16: 0x02,
  U32: 0x04,
  U64: 0x08,
  I8: 0x11,
  I16: 0x12,
  I32: 0x14,
  I64: 0x18,
  SZ: 0x21,
  BLOB_DATA: 0x42,
  BLOB_IDX: 0x48,
};

/** キーの最大長(NUL 込みで 16 バイト)。 */
export const MAX_KEY_LEN = 15;

/**
 * NVS パーティションイメージのビルダ。
 *
 * 単一ページに収まる範囲(126 エントリ)のみを扱う。工場データ / 設定 blob は
 * いずれもこの範囲に収まる(はみ出す場合は例外)。
 */
export class NvsBuilder {
  /**
   * @param {number} sizeBytes パーティションサイズ(4096 の倍数、最低 3 ページ)
   */
  constructor(sizeBytes) {
    if (sizeBytes % PAGE_SIZE !== 0 || sizeBytes < PAGE_SIZE * 3) {
      throw new Error(`NVS partition size must be a multiple of 4096 and >= 12288 (got ${sizeBytes})`);
    }
    this.size = sizeBytes;
    this.entries = []; // { ns, type, span, chunkIndex, key, data(8B), body(Uint8Array|null) }
    this.namespaces = new Map();
  }

  /** namespace 名 → インデックス(未登録なら登録する)。 */
  namespace(name) {
    if (this.namespaces.has(name)) {
      return this.namespaces.get(name);
    }
    const index = this.namespaces.size + 1;
    if (index > 254) {
      throw new Error("too many namespaces");
    }
    this.namespaces.set(name, index);
    this._push(0, TYPE.U8, 0xff, name, this._fixedData(BigInt(index), 1), null);
    return index;
  }

  _fixedData(value, width) {
    const d = new Uint8Array(8).fill(0xff);
    let v = BigInt(value);
    if (v < 0n) {
      v += 1n << BigInt(width * 8);
    }
    for (let i = 0; i < width; i++) {
      d[i] = Number((v >> BigInt(i * 8)) & 0xffn);
    }
    return d;
  }

  _push(ns, type, chunkIndex, key, data, body) {
    const keyBytes = utf8(key);
    if (keyBytes.length === 0 || keyBytes.length > MAX_KEY_LEN) {
      throw new Error(`NVS key ${JSON.stringify(key)} must be 1..${MAX_KEY_LEN} bytes`);
    }
    const span = body ? 1 + Math.ceil(body.length / ENTRY_SIZE) : 1;
    this.entries.push({ ns, type, span, chunkIndex, key: keyBytes, data, body });
  }

  /** u32 値を書く。 */
  setU32(namespace, key, value) {
    const ns = this.namespace(namespace);
    this._push(ns, TYPE.U32, 0xff, key, this._fixedData(BigInt(value >>> 0), 4), null);
    return this;
  }

  /** 文字列(SZ)を書く。NVS の文字列は NUL 終端込みで格納される。 */
  setStr(namespace, key, value) {
    const ns = this.namespace(namespace);
    const raw = utf8(value);
    const body = new Uint8Array(raw.length + 1);
    body.set(raw, 0); // 末尾は NUL
    const data = new Uint8Array(8);
    data[0] = body.length & 0xff;
    data[1] = (body.length >> 8) & 0xff;
    data[2] = 0xff;
    data[3] = 0xff;
    const c = crc32(body, 0xffffffff);
    data[4] = c & 0xff;
    data[5] = (c >>> 8) & 0xff;
    data[6] = (c >>> 16) & 0xff;
    data[7] = (c >>> 24) & 0xff;
    this._push(ns, TYPE.SZ, 0xff, key, data, body);
    return this;
  }

  /** BLOB(単一チャンク)を書く。BLOB_DATA + BLOB_IDX のペアを積む。 */
  setBlob(namespace, key, value) {
    const ns = this.namespace(namespace);
    const body = Uint8Array.from(value);
    if (body.length === 0) {
      throw new Error(`blob ${JSON.stringify(key)} must not be empty`);
    }
    if (body.length > (ENTRIES_PER_PAGE - 2) * ENTRY_SIZE) {
      throw new Error(`blob ${JSON.stringify(key)} is too large for a single NVS page`);
    }
    const data = new Uint8Array(8);
    data[0] = body.length & 0xff;
    data[1] = (body.length >> 8) & 0xff;
    data[2] = 0xff;
    data[3] = 0xff;
    const c = crc32(body, 0xffffffff);
    data[4] = c & 0xff;
    data[5] = (c >>> 8) & 0xff;
    data[6] = (c >>> 16) & 0xff;
    data[7] = (c >>> 24) & 0xff;
    this._push(ns, TYPE.BLOB_DATA, 0x00, key, data, body);

    // BLOB_IDX: 総サイズ u32 / chunkCount / chunkStart / reserved。
    const idx = new Uint8Array(8);
    idx[0] = body.length & 0xff;
    idx[1] = (body.length >> 8) & 0xff;
    idx[2] = (body.length >> 16) & 0xff;
    idx[3] = (body.length >> 24) & 0xff;
    idx[4] = 1; // chunkCount
    idx[5] = 0; // chunkStart(VerOffset)
    idx[6] = 0xff;
    idx[7] = 0xff;
    this._push(ns, TYPE.BLOB_IDX, 0xff, key, idx, null);
    return this;
  }

  /** base64 テキストとして格納する(mfg_tool の salt / verifier の形式)。 */
  setBase64Str(namespace, key, bytes) {
    return this.setStr(namespace, key, bytesToBase64(bytes));
  }

  /** パーティションイメージ(Uint8Array)を組み立てる。 */
  build() {
    const img = new Uint8Array(this.size).fill(0xff);
    const page = img.subarray(0, PAGE_SIZE);

    // ページヘッダ。
    const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
    dv.setUint32(0, PAGE_STATE_ACTIVE, true);
    dv.setUint32(4, 0, true); // seq number
    page[8] = PAGE_VERSION_V2;
    // page[9..28] は 0xFF のまま。
    dv.setUint32(28, crc32(page.subarray(4, 28), 0xffffffff), true);

    // エントリ状態ビットマップ(既定 = empty = 0b11)。
    const bitmap = page.subarray(PAGE_HEADER_LEN, PAGE_HEADER_LEN + ENTRY_BITMAP_LEN);
    bitmap.fill(0xff);

    let slot = 0;
    for (const e of this.entries) {
      if (slot + e.span > ENTRIES_PER_PAGE) {
        throw new Error(
          `NVS entries do not fit into a single 4 KiB page (need > ${ENTRIES_PER_PAGE} slots)`
        );
      }
      const off = ENTRY_DATA_OFFSET + slot * ENTRY_SIZE;
      const entry = page.subarray(off, off + ENTRY_SIZE);
      entry[0] = e.ns;
      entry[1] = e.type;
      entry[2] = e.span;
      entry[3] = e.chunkIndex;
      entry.fill(0, 8, 24);
      entry.set(e.key, 8);
      entry.set(e.data, 24);
      let c = crc32(entry.subarray(0, 4), 0xffffffff);
      c = crc32(entry.subarray(8, 32), c);
      entry[4] = c & 0xff;
      entry[5] = (c >>> 8) & 0xff;
      entry[6] = (c >>> 16) & 0xff;
      entry[7] = (c >>> 24) & 0xff;
      if (e.body) {
        page.set(e.body, off + ENTRY_SIZE);
      }
      // span 個ぶんの状態を written にする(本体エントリも written)。
      for (let k = 0; k < e.span; k++) {
        const i = slot + k;
        bitmap[i >> 2] &= ~(ENTRY_EMPTY << ((i % 4) * 2)) & 0xff;
        bitmap[i >> 2] |= ENTRY_WRITTEN << ((i % 4) * 2);
      }
      slot += e.span;
    }
    return img;
  }
}

/**
 * NVS パーティションの読み取り(検算用の最小実装)。
 *
 * `crates/simple-matter/src/factory/nvs.rs` と同じ割り切り(ACTIVE/FULL ページ・
 * written エントリ・単一チャンク BLOB のみ)。
 */
export class NvsReader {
  constructor(data) {
    this.data = data;
  }

  *entries() {
    for (let pageStart = 0; pageStart + PAGE_SIZE <= this.data.length; pageStart += PAGE_SIZE) {
      const page = this.data.subarray(pageStart, pageStart + PAGE_SIZE);
      const state = new DataView(page.buffer, page.byteOffset, 4).getUint32(0, true);
      if (state !== PAGE_STATE_ACTIVE && state !== 0xfffffff8) {
        continue;
      }
      const bitmap = page.subarray(PAGE_HEADER_LEN, PAGE_HEADER_LEN + ENTRY_BITMAP_LEN);
      let i = 0;
      while (i < ENTRIES_PER_PAGE) {
        const st = (bitmap[i >> 2] >> ((i % 4) * 2)) & 0b11;
        if (st !== ENTRY_WRITTEN) {
          i++;
          continue;
        }
        const off = ENTRY_DATA_OFFSET + i * ENTRY_SIZE;
        const e = page.subarray(off, off + ENTRY_SIZE);
        const span = Math.max(e[2], 1);
        const keyEnd = e.subarray(8, 24).indexOf(0);
        const key = new TextDecoder().decode(e.subarray(8, keyEnd < 0 ? 24 : 8 + keyEnd));
        let payload = new Uint8Array(0);
        if (e[1] === TYPE.SZ || e[1] === TYPE.BLOB_DATA) {
          const size = e[24] | (e[25] << 8);
          payload = page.subarray(off + ENTRY_SIZE, off + ENTRY_SIZE + size);
        }
        yield { ns: e[0], type: e[1], span, chunkIndex: e[3], key, data: e.subarray(24, 32), payload };
        i += span;
      }
    }
  }

  namespaceIndex(name) {
    for (const e of this.entries()) {
      if (e.ns === 0 && e.type === TYPE.U8 && e.key === name) {
        return e.data[0];
      }
    }
    return null;
  }

  _find(namespace, key, type) {
    const ns = this.namespaceIndex(namespace);
    if (ns === null) {
      return null;
    }
    for (const e of this.entries()) {
      if (e.ns === ns && e.key === key && e.type === type) {
        return e;
      }
    }
    return null;
  }

  getU32(namespace, key) {
    const e = this._find(namespace, key, TYPE.U32);
    return e ? (e.data[0] | (e.data[1] << 8) | (e.data[2] << 16) | (e.data[3] << 24)) >>> 0 : null;
  }

  /** SZ の値(末尾 NUL を除いた文字列)。 */
  getStr(namespace, key) {
    const e = this._find(namespace, key, TYPE.SZ);
    if (!e) {
      return null;
    }
    const end = e.payload.indexOf(0);
    return new TextDecoder().decode(end < 0 ? e.payload : e.payload.subarray(0, end));
  }

  /** BLOB(単一チャンク)の本体。 */
  getBlob(namespace, key) {
    const e = this._find(namespace, key, TYPE.BLOB_DATA);
    return e ? e.payload : null;
  }
}

/** 工場データの namespace(`esp-matter-mfg-tool` 互換)。 */
export const FACTORY_NS = "chip-factory";

/**
 * mfg_tool 互換の factory NVS パーティションを組み立てる。
 *
 * `salt` / `verifier` は **base64 テキストを SZ 型で**格納する(mfg_tool の仕様。
 * デバイス側がデコードする)。DAC 一式(`dac`)は省略可だが、`generic_matter_cpp` の
 * factory ローダは **DAC/PAI/鍵が揃わないと factory 全体を捨てて dev 資格情報へ
 * フォールバックする**(README の注意書き参照)。
 *
 * @param {object} p
 * @param {number} p.vendorId
 * @param {number} p.productId
 * @param {number} p.discriminator 12 ビット
 * @param {number} p.iterations PBKDF2 反復回数
 * @param {Uint8Array} p.salt
 * @param {Uint8Array} p.verifier w0‖L(97 バイト)
 * @param {string} [p.vendorName]
 * @param {string} [p.productName]
 * @param {number} [p.hardwareVersion]
 * @param {string} [p.hardwareVersionStr]
 * @param {string} [p.serialNumber]
 * @param {{dac: Uint8Array, pai: Uint8Array, key: Uint8Array, pub?: Uint8Array}} [p.dac]
 * @param {Uint8Array} [p.certDeclaration] `cert-dclrn`(任意)
 * @param {number} [p.size] パーティションサイズ(既定 0x6000 = 24 KiB)
 */
export function buildFactoryNvs(p) {
  if (p.verifier.length !== 97) {
    throw new Error(`verifier must be 97 bytes (got ${p.verifier.length})`);
  }
  const b = new NvsBuilder(p.size ?? 0x6000);
  b.setU32(FACTORY_NS, "discriminator", p.discriminator & 0x0fff);
  b.setU32(FACTORY_NS, "iteration-count", p.iterations);
  b.setBase64Str(FACTORY_NS, "salt", p.salt);
  b.setU32(FACTORY_NS, "vendor-id", p.vendorId);
  if (p.vendorName) {
    b.setStr(FACTORY_NS, "vendor-name", p.vendorName);
  }
  b.setU32(FACTORY_NS, "product-id", p.productId);
  if (p.productName) {
    b.setStr(FACTORY_NS, "product-name", p.productName);
  }
  if (p.hardwareVersion !== undefined) {
    b.setU32(FACTORY_NS, "hardware-ver", p.hardwareVersion);
  }
  if (p.hardwareVersionStr) {
    b.setStr(FACTORY_NS, "hw-ver-str", p.hardwareVersionStr);
  }
  if (p.serialNumber) {
    b.setStr(FACTORY_NS, "serial-num", p.serialNumber);
  }
  if (p.dac) {
    b.setBlob(FACTORY_NS, "dac-cert", p.dac.dac);
    b.setBlob(FACTORY_NS, "dac-key", p.dac.key);
    if (p.dac.pub) {
      b.setBlob(FACTORY_NS, "dac-pub-key", p.dac.pub);
    }
    b.setBlob(FACTORY_NS, "pai-cert", p.dac.pai);
  }
  if (p.certDeclaration) {
    b.setBlob(FACTORY_NS, "cert-dclrn", p.certDeclaration);
  }
  b.setBase64Str(FACTORY_NS, "verifier", p.verifier);
  return b.build();
}

/** `generic_matter_cpp` の設定 blob namespace。 */
export const SMGEN_NS = "smgen";

/**
 * composition / binding TLV を収めた `nvs` パーティションイメージを組み立てる。
 *
 * 書き込むと **コア KVS(namespace `smatter`)も消える** = factory reset 相当。
 * 構成変更時はそれが望ましい(docs/design/generic-firmware.md §8 R-G1)。
 */
export function buildSmgenNvs({ comp, bind, size = 0x6000 }) {
  const b = new NvsBuilder(size);
  if (comp) {
    b.setBlob(SMGEN_NS, "comp", comp);
  }
  if (bind) {
    b.setBlob(SMGEN_NS, "bind", bind);
  }
  return b.build();
}

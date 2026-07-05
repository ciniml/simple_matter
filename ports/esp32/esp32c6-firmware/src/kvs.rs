//! flash KVS(コアの [`Kvs`] trait の ESP32-C6 実装)。
//!
//! `docs/design/port-esp32-device.md` §E4.5。esp-storage の [`FlashStorage`] を
//! sequential-storage の map([`MapStorage`]、wear-leveling 付き追記型 KV)で包み、
//! fabric 永続化(`FabricTable::save_to` / `load_from`)のバックエンドにする。
//!
//! # 設計判断(doc §E4.5)
//!
//! - **使用領域はパーティションテーブルの `nvs`(offset 0x9000, len 0x6000)**。
//!   espflash 既定テーブルの nvs と同じ位置で、アプリ/ブートローダ領域と衝突しない。
//!   **フォーマットは sequential-storage の自前形式で、ESP-IDF の NVS とは非互換**
//!   (領域を間借りするだけ。IDF ツールで読み書きしない前提)。
//! - sequential-storage の API は async(embedded-storage-async)だが、下層の
//!   [`FlashStorage`] は blocking。[`AsyncFlash`] で trait を持ち上げ、[`Kvs`] 実装は
//!   `embassy_futures::block_on` で駆動する(future は常に即完了する)。コアの
//!   `Kvs` は同期 API のままで済む。
//! - キーはコア側の短いバイト列(≤ 7 バイト)を「長さタグ付き u64」へパックして
//!   sequential-storage の `Key` 制約を満たす(fabric 永続化のキーは 4 バイト固定)。
//!
//! # 既知の注意点
//!
//! flash の erase/write 中は cache が止まる。BLE(esp-radio)稼働中の保存で
//! タイミング違反が観測された場合は、保存契機を BLE idle 時へ遅延させる(doc §E4.5)。

use embassy_futures::block_on;
use embedded_storage::nor_flash::{
    ErrorType as BlockingErrorType, MultiwriteNorFlash as BlockingMultiwriteNorFlash,
    NorFlash as BlockingNorFlash, ReadNorFlash as BlockingReadNorFlash,
};
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use esp_hal::peripherals::FLASH;
use esp_storage::FlashStorage;
use sequential_storage::cache::NoCache;
use sequential_storage::map::{MapConfig, MapStorage};

use simple_matter::error::{Error, Result};
use simple_matter::fabric::MAX_FABRIC_RECORD_LEN;
use simple_matter::kvs::Kvs;

/// `nvs` パーティション領域(offset 0x9000, len 0x6000 = 4KiB × 6 ページ)。
const NVS_START: u32 = 0x9000;
const NVS_END: u32 = 0xF000;

/// sequential-storage の作業バッファ長。最大レコード + キー/アイテムヘッダ余裕
/// (flash ワード境界へ切り上げ)。
const DATA_BUF_LEN: usize = (MAX_FABRIC_RECORD_LEN + 64).next_multiple_of(4);

/// blocking の [`FlashStorage`] を embedded-storage-async の trait へ持ち上げる
/// 薄いアダプタ(全メソッドが即時完了する)。
struct AsyncFlash(FlashStorage<'static>);

impl ErrorType for AsyncFlash {
    type Error = <FlashStorage<'static> as BlockingErrorType>::Error;
}

impl ReadNorFlash for AsyncFlash {
    const READ_SIZE: usize = <FlashStorage<'static> as BlockingReadNorFlash>::READ_SIZE;

    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        BlockingReadNorFlash::read(&mut self.0, offset, bytes)
    }

    fn capacity(&self) -> usize {
        BlockingReadNorFlash::capacity(&self.0)
    }
}

impl NorFlash for AsyncFlash {
    const WRITE_SIZE: usize = <FlashStorage<'static> as BlockingNorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <FlashStorage<'static> as BlockingNorFlash>::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        BlockingNorFlash::erase(&mut self.0, from, to)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        BlockingNorFlash::write(&mut self.0, offset, bytes)
    }
}

/// remove(既存アイテムの無効化)は「書き込み済みワードへの追い書きで CRC を 0 化する」
/// ため MultiwriteNorFlash が要る。[`FlashStorage`] は blocking 側で実装済みなので
/// そのまま宣言できる。
impl MultiwriteNorFlash for AsyncFlash {}

// FlashStorage が blocking MultiwriteNorFlash であることのコンパイル時確認
// (上の宣言の裏付け。実装が消えたらここでビルドが落ちる)。
const _: () = {
    const fn assert_multiwrite<T: BlockingMultiwriteNorFlash>() {}
    assert_multiwrite::<FlashStorage<'static>>()
};

/// コアの [`Kvs`] trait の flash 実装。
pub struct EspKvs {
    map: MapStorage<u64, AsyncFlash, NoCache>,
    buf: [u8; DATA_BUF_LEN],
}

impl EspKvs {
    /// `nvs` 領域を使う KVS を作る(FLASH ペリフェラルを占有する)。
    pub fn new(flash: FLASH<'static>) -> Self {
        let storage = AsyncFlash(FlashStorage::new(flash));
        Self {
            map: MapStorage::new(storage, MapConfig::new(NVS_START..NVS_END), NoCache::new()),
            buf: [0u8; DATA_BUF_LEN],
        }
    }
}

/// 短いバイト列キー(≤ 7 バイト)を「長さタグ付き u64」へパックする。
///
/// 下位 7 バイトにキー本体(LE、ゼロ詰め)、最上位バイトにキー長を置く。長さを
/// 含めることで「末尾ゼロだけが違うキー」の衝突を避ける。
fn pack_key(key: &[u8]) -> Result<u64> {
    if key.len() > 7 {
        return Err(Error::NoSpace);
    }
    let mut b = [0u8; 8];
    b[..key.len()].copy_from_slice(key);
    b[7] = key.len() as u8;
    Ok(u64::from_le_bytes(b))
}

/// sequential-storage のエラーをコアの [`Error`] へ写像する。
///
/// 容量系は `NoSpace`、それ以外(破損・flash I/O 失敗)は `Decode` に落とす
/// (コアの Error は KVS 専用バリアントを持たない。呼び出し側はいずれも
/// 「復元不能」として扱う)。
fn map_err<E>(e: sequential_storage::Error<E>) -> Error {
    match e {
        sequential_storage::Error::FullStorage | sequential_storage::Error::BufferTooSmall(_) => {
            Error::NoSpace
        }
        _ => Error::Decode,
    }
}

impl Kvs for EspKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
        let k = pack_key(key)?;
        let found: Option<&[u8]> =
            block_on(self.map.fetch_item(&mut self.buf, &k)).map_err(map_err)?;
        match found {
            Some(v) => {
                if buf.len() < v.len() {
                    return Err(Error::NoSpace);
                }
                buf[..v.len()].copy_from_slice(v);
                Ok(Some(v.len()))
            }
            None => Ok(None),
        }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let k = pack_key(key)?;
        block_on(self.map.store_item(&mut self.buf, &k, &value)).map_err(map_err)
    }

    fn remove(&mut self, key: &[u8]) -> Result<()> {
        let k = pack_key(key)?;
        block_on(self.map.remove_item(&mut self.buf, &k)).map_err(map_err)
    }
}

//! 状態ディレクトリ(設計 doc §4)。既定 `~/.smctl/`、`--state-dir` で変更可能。
//!
//! ```text
//! ~/.smctl/
//! ├── state.lock      # プロセス間排他(状態ファイル読み書きの短い区間のみ保持)
//! ├── ca-state.bin    # CA 鍵素材(既存 v1 フォーマット互換、state/ca.rs)
//! └── nodes.tlv       # ノードアドレス帳(state/nodes.rs)
//! ```
//!
//! ロックは**状態ファイルの読み書き区間だけ**保持する(コマンド全体では持たない)。
//! `subscribe` 常駐中に別プロセスの `toggle` が動く、という並行実行を許すため。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub mod ca;
pub mod nodes;

/// ロック獲得の最大待ち時間。
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// 状態ディレクトリ。生成時にディレクトリを作成する。
pub struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    /// ディレクトリを(無ければ作って)開く。
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("create state dir {}: {e}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// `ca-state.bin` のパス。
    pub fn ca_path(&self) -> PathBuf {
        self.dir.join("ca-state.bin")
    }

    /// `nodes.tlv` のパス。
    pub fn nodes_path(&self) -> PathBuf {
        self.dir.join("nodes.tlv")
    }

    /// `state.lock` を獲得する(create_new。既存なら 100ms 間隔で最大 5 秒リトライ)。
    ///
    /// 戻り値の guard を drop するとロックが解放される。
    pub fn lock(&self) -> Result<LockGuard, String> {
        let path = self.dir.join("state.lock");
        let start = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(LockGuard { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if start.elapsed() > LOCK_TIMEOUT {
                        return Err(format!(
                            "state directory is locked by another smctl process \
                             (remove {} if stale)",
                            path.display()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(format!("create lock {}: {e}", path.display())),
            }
        }
    }
}

/// `state.lock` の保持を表す guard。drop で解放。
pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

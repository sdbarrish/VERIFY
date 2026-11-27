//! Durable storage for a validator process.
//!
//! * `chain.bin`: committed blocks, each as a 4-byte length plus its canonical
//!   encoding, appended and synced. A torn final write (power loss mid-append)
//!   is detected on open and trimmed. On restart every block is re-verified
//!   (certificate, links, re-execution) before it is trusted again.
//! * `consensus.bin`: the [`Durable`] consensus state. It is replaced
//!   atomically (write temp, sync, rename, sync directory) *before* any
//!   message produced by the same event leaves the process, so a crash can
//!   never make the validator forget a vote or a lock.

use crate::bft::Durable;
use crate::codec::{Canonical, Decode};
use crate::consensus::Block;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub struct Store {
    dir: PathBuf,
}

const CHAIN: &str = "chain.bin";
const CONSENSUS: &str = "consensus.bin";
/// Largest stored block record.
const MAX_RECORD: usize = 64 * 1024 * 1024;

impl Store {
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Read committed blocks, trimming any torn or undecodable tail.
    pub fn load_blocks(&self) -> io::Result<Vec<Block>> {
        let (blocks, good) = read_chain_file(&self.path(CHAIN))?;
        let p = self.path(CHAIN);
        if p.exists() && fs::metadata(&p)?.len() != good {
            let f = OpenOptions::new().write(true).open(&p)?;
            f.set_len(good)?;
            f.sync_all()?;
        }
        Ok(blocks)
    }

    pub fn append_block(&self, b: &Block) -> io::Result<()> {
        let bytes = b.to_canonical();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(CHAIN))?;
        f.write_all(&(bytes.len() as u32).to_be_bytes())?;
        f.write_all(&bytes)?;
        f.sync_data()
    }

    pub fn load_durable(&self) -> Option<Durable> {
        let b = fs::read(self.path(CONSENSUS)).ok()?;
        Durable::from_canonical(&b).ok()
    }

    pub fn save_durable(&self, d: &Durable) -> io::Result<()> {
        let tmp = self.path("consensus.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&d.to_canonical())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.path(CONSENSUS))?;
        // Make the rename itself durable.
        File::open(&self.dir)?.sync_all()
    }
}

/// Decode a chain file without trusting it. Returns the blocks that decode
/// cleanly and the byte offset where they end.
pub fn read_chain_file(path: &Path) -> io::Result<(Vec<Block>, u64)> {
    let mut data = vec![];
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut data)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((vec![], 0)),
        Err(e) => return Err(e),
    }
    let (mut blocks, mut pos) = (vec![], 0usize);
    while data.len() - pos >= 4 {
        let n = u32::from_be_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        if n > MAX_RECORD || data.len() - pos - 4 < n {
            break;
        }
        match Block::from_canonical(&data[pos + 4..pos + 4 + n]) {
            Ok(b) => blocks.push(b),
            Err(_) => break,
        }
        pos += 4 + n;
    }
    Ok((blocks, pos as u64))
}

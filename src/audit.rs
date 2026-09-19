//! Append-only audit log. Each row commits to the one before it with SHA-256,
//! so editing or deleting a row is detectable by `verify`.
//!
//! Honest limit: this catches tampering by someone who cannot rewrite the whole
//! table. Anyone able to recompute every hash from the start can still forge it.

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: i64,
    pub ts_ms: i64,
    pub actor: String,
    pub kind: String,
    pub detail: String,
}

fn digest(prev: &[u8], ts_ms: i64, actor: &str, kind: &str, detail: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(ts_ms.to_be_bytes());
    for field in [actor, kind, detail] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.finalize().to_vec()
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ms INTEGER NOT NULL,
            actor TEXT NOT NULL,
            kind TEXT NOT NULL,
            detail TEXT NOT NULL,
            prev_hash BLOB NOT NULL,
            hash BLOB NOT NULL
        );",
    )
}

pub fn append(conn: &Connection, ts_ms: i64, actor: &str, kind: &str, detail: &str) -> rusqlite::Result<i64> {
    let prev: Vec<u8> = conn
        .query_row("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
        .unwrap_or_else(|_| GENESIS.to_vec());
    let hash = digest(&prev, ts_ms, actor, kind, detail);
    conn.execute(
        "INSERT INTO audit (ts_ms, actor, kind, detail, prev_hash, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![ts_ms, actor, kind, detail, prev, hash],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Returns the id of the first row that fails verification, or `None` if the chain is intact.
pub fn verify(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    let mut stmt = conn.prepare("SELECT id, ts_ms, actor, kind, detail, prev_hash, hash FROM audit ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut expected_prev = GENESIS.to_vec();
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let (ts, actor, kind, detail): (i64, String, String, String) = (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
        let (prev, hash): (Vec<u8>, Vec<u8>) = (r.get(5)?, r.get(6)?);
        if prev != expected_prev || hash != digest(&prev, ts, &actor, &kind, &detail) {
            return Ok(Some(id));
        }
        expected_prev = hash;
    }
    Ok(None)
}

/// Newest first.
pub fn entries(conn: &Connection, limit: u32) -> rusqlite::Result<Vec<Entry>> {
    let mut stmt = conn.prepare("SELECT id, ts_ms, actor, kind, detail FROM audit ORDER BY id DESC LIMIT ?1")?;
    stmt.query_map([limit], |r| {
        Ok(Entry { id: r.get(0)?, ts_ms: r.get(1)?, actor: r.get(2)?, kind: r.get(3)?, detail: r.get(4)? })
    })?
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    #[test]
    fn intact_chain_verifies() {
        let c = db();
        assert_eq!(verify(&c).unwrap(), None);
        for i in 0..5 {
            append(&c, i, "keyholder", "locked", "{}").unwrap();
        }
        assert_eq!(verify(&c).unwrap(), None);
    }

    #[test]
    fn editing_a_row_is_detected() {
        let c = db();
        for i in 0..5 {
            append(&c, i, "wearer", "unlock_requested", "{}").unwrap();
        }
        c.execute("UPDATE audit SET actor = 'keyholder' WHERE id = 3", []).unwrap();
        assert_eq!(verify(&c).unwrap(), Some(3));
    }

    #[test]
    fn deleting_a_row_is_detected() {
        let c = db();
        for i in 0..5 {
            append(&c, i, "wearer", "unlock_requested", "{}").unwrap();
        }
        c.execute("DELETE FROM audit WHERE id = 2", []).unwrap();
        assert_eq!(verify(&c).unwrap(), Some(3));
    }
}

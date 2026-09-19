//! A command the keyholder wants carried out the next time the pod can be
//! reached: by the server when it is in range, or by the wearer's phone the
//! next time they connect over Bluetooth. At most one is pending at a time.
//! The rules are checked again when it runs, so a queued unlock still cannot
//! happen under a timer.

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Lock,
    Unlock,
}

impl Command {
    pub fn as_str(&self) -> &'static str {
        match self {
            Command::Lock => "lock",
            Command::Unlock => "unlock",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "lock" => Some(Command::Lock),
            "unlock" => Some(Command::Unlock),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub id: i64,
    pub command: Command,
    pub queued_ms: i64,
}

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("a command is already queued; cancel it first")]
    AlreadyPending,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS queued_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT NOT NULL,
            queued_ms INTEGER NOT NULL,
            done_ms INTEGER,
            outcome TEXT
        );",
    )
}

pub fn pending(conn: &Connection) -> rusqlite::Result<Option<Queued>> {
    let row: Option<(i64, String, i64)> = conn
        .query_row("SELECT id, command, queued_ms FROM queued_commands WHERE done_ms IS NULL ORDER BY id LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    Ok(row.and_then(|(id, c, queued_ms)| Command::parse(&c).map(|command| Queued { id, command, queued_ms })))
}

pub fn enqueue(conn: &Connection, command: Command, now_ms: i64) -> Result<i64, QueueError> {
    if pending(conn)?.is_some() {
        return Err(QueueError::AlreadyPending);
    }
    conn.execute("INSERT INTO queued_commands (command, queued_ms) VALUES (?1, ?2)", params![command.as_str(), now_ms])?;
    Ok(conn.last_insert_rowid())
}

/// Close a pending command with a short outcome such as "done via phone" or "cancelled".
pub fn finish(conn: &Connection, id: i64, now_ms: i64, outcome: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE queued_commands SET done_ms = ?1, outcome = ?2 WHERE id = ?3 AND done_ms IS NULL", params![now_ms, outcome, id])?;
    Ok(())
}

pub fn cancel(conn: &Connection, now_ms: i64) -> rusqlite::Result<Option<Queued>> {
    let q = pending(conn)?;
    if let Some(q) = &q {
        finish(conn, q.id, now_ms, "cancelled")?;
    }
    Ok(q)
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
    fn one_pending_command_at_a_time() {
        let c = db();
        assert!(pending(&c).unwrap().is_none());
        let id = enqueue(&c, Command::Lock, 1).unwrap();
        assert_eq!(pending(&c).unwrap(), Some(Queued { id, command: Command::Lock, queued_ms: 1 }));
        assert!(matches!(enqueue(&c, Command::Unlock, 2), Err(QueueError::AlreadyPending)));
    }

    #[test]
    fn finishing_or_cancelling_frees_the_slot() {
        let c = db();
        let id = enqueue(&c, Command::Lock, 1).unwrap();
        finish(&c, id, 2, "done via phone").unwrap();
        assert!(pending(&c).unwrap().is_none());

        enqueue(&c, Command::Unlock, 3).unwrap();
        assert_eq!(cancel(&c, 4).unwrap().unwrap().command, Command::Unlock);
        assert!(cancel(&c, 5).unwrap().is_none());
        enqueue(&c, Command::Lock, 6).unwrap();
    }
}

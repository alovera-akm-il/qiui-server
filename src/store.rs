//! SQLite persistence. `apply` is the only way state changes: it loads the
//! machine, ticks time forward, runs one action, and writes the new state and
//! its audit rows in a single transaction, so state and log cannot drift apart.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::audit;
use crate::machine::{self, Event, LockState, Machine};
use crate::timer::Timer;

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Rule(#[from] machine::Error),
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS lock_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state TEXT NOT NULL,
                approval_expires_ms INTEGER,
                timer_kind TEXT NOT NULL,
                timer_ms INTEGER
            );",
        )?;
        audit::migrate(&conn)?;
        crate::accounts::migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn machine(&self) -> rusqlite::Result<Machine> {
        load(&self.conn)
    }

    /// Record an event that is not a lock-state change (logins, pairing, password resets...).
    pub fn log(&self, now_ms: i64, actor: &str, kind: &str, detail: &serde_json::Value) -> rusqlite::Result<()> {
        audit::append(&self.conn, now_ms, actor, kind, &detail.to_string()).map(|_| ())
    }

    /// Run one action against the current state. Time-driven changes (timer
    /// ended, approval expired) are persisted even if the action is rejected.
    pub fn apply<F>(&mut self, now_ms: i64, action: F) -> Result<Vec<Event>, ApplyError>
    where
        F: FnOnce(&mut Machine) -> machine::Result<Vec<Event>>,
    {
        let tx = self.conn.transaction()?;
        let mut m = load(&tx)?;
        let mut events = m.tick(now_ms);
        let outcome = action(&mut m);
        if let Ok(more) = &outcome {
            events.extend(more.iter().cloned());
        }
        save(&tx, &m)?;
        for e in &events {
            audit::append(&tx, now_ms, e.actor.as_str(), e.kind, &e.detail.to_string())?;
        }
        tx.commit()?;
        // Everything that happened, time-driven events included, or the rule that refused.
        Ok(outcome.map(|_| events)?)
    }
}

fn load(conn: &Connection) -> rusqlite::Result<Machine> {
    let row = conn
        .query_row(
            "SELECT state, approval_expires_ms, timer_kind, timer_ms FROM lock_state WHERE id = 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<i64>>(3)?)),
        )
        .optional()?;
    let Some((state, approval_expires_ms, timer_kind, timer_ms)) = row else {
        return Ok(Machine::default());
    };
    let corrupt = |what: &str| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, format!("bad stored {what}").into());
    Ok(Machine {
        state: LockState::parse(&state).ok_or_else(|| corrupt("lock state"))?,
        approval_expires_ms,
        timer: Timer::from_parts(&timer_kind, timer_ms).ok_or_else(|| corrupt("timer"))?,
    })
}

fn save(conn: &Connection, m: &Machine) -> rusqlite::Result<()> {
    let (kind, ms) = m.timer.to_parts();
    conn.execute(
        "INSERT INTO lock_state (id, state, approval_expires_ms, timer_kind, timer_ms) VALUES (1, ?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET state = ?1, approval_expires_ms = ?2, timer_kind = ?3, timer_ms = ?4",
        params![m.state.as_str(), m.approval_expires_ms, kind, ms],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Actor;

    const M: i64 = 60_000;
    const H: i64 = 60 * M;

    fn kinds(store: &Store) -> Vec<String> {
        let mut k: Vec<String> = audit::entries(store.connection(), 100).unwrap().into_iter().map(|e| e.kind).collect();
        k.reverse();
        k
    }

    #[test]
    fn state_and_audit_persist_together() {
        let mut s = Store::open_in_memory().unwrap();
        s.apply(0, |m| m.request_unlock(Actor::Wearer, 0)).unwrap();
        s.apply(M, |m| m.approve(Actor::Keyholder, M, 15 * M)).unwrap();
        assert_eq!(s.machine().unwrap().state, LockState::Approved);
        assert_eq!(kinds(&s), ["unlock_requested", "unlock_approved"]);
        assert_eq!(audit::verify(s.connection()).unwrap(), None);
    }

    #[test]
    fn rejected_action_writes_nothing_but_time_still_advances() {
        let mut s = Store::open_in_memory().unwrap();
        s.apply(0, |m| m.set_timer(Actor::Keyholder, 0, H)).unwrap();

        // Wearer tries to clear the timer: refused, and not logged as a change.
        let err = s.apply(M, |m| m.clear_timer(Actor::Wearer)).unwrap_err();
        assert!(matches!(err, ApplyError::Rule(machine::Error::NotPermitted)));
        assert_eq!(kinds(&s), ["timer_set"]);

        // A rejected request after the timer ended still persists the timer ending.
        let err = s.apply(H, |m| m.approve(Actor::Keyholder, H, M)).unwrap_err();
        assert!(matches!(err, ApplyError::Rule(machine::Error::WrongState(LockState::Locked))));
        assert_eq!(s.machine().unwrap().timer, Timer::Ended);
        assert_eq!(kinds(&s), ["timer_set", "timer_ended"]);
    }

    #[test]
    fn state_survives_reopening_the_database() {
        let path = std::env::temp_dir().join(format!("qiui-store-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut s = Store::open(&path).unwrap();
            s.apply(0, |m| m.set_timer(Actor::Keyholder, 0, 5 * H)).unwrap();
            s.apply(H, |m| m.pause_timer(Actor::Keyholder, H)).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.machine().unwrap().timer, Timer::Paused { remaining_ms: 4 * H });
        assert_eq!(audit::verify(s.connection()).unwrap(), None);
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }

    #[test]
    fn tampering_with_stored_audit_is_detected() {
        let mut s = Store::open_in_memory().unwrap();
        s.apply(0, |m| m.set_timer(Actor::Keyholder, 0, H)).unwrap();
        s.apply(1, |m| m.pause_timer(Actor::Keyholder, 1)).unwrap();
        s.connection().execute("UPDATE audit SET kind = 'timer_cleared' WHERE id = 1", []).unwrap();
        assert_eq!(audit::verify(s.connection()).unwrap(), Some(1));
    }
}

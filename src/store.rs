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
            );
            CREATE TABLE IF NOT EXISTS pod_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                checked_ms INTEGER NOT NULL,
                via TEXT NOT NULL,
                battery INTEGER
            );",
        )?;
        audit::migrate(&conn)?;
        crate::queue::migrate(&conn)?;
        crate::push::migrate(&conn)?;
        crate::accounts::migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn machine(&self) -> rusqlite::Result<Machine> {
        load(&self.conn)
    }

    /// Record a failed attempt (wrong password, PIN or pairing code). Runs of them are summarised, one
    /// row per 30 s with a count, so guessing cannot flood the log. Nothing here blocks or delays anyone.
    pub fn log_failure(&self, now_ms: i64, actor: &str, kind: &str) -> rusqlite::Result<()> {
        // Counted per actor as well as per kind, so a flood through one route cannot hide the other's first failure.
        match crate::accounts::note_failure(&self.conn, &format!("{actor}:{kind}"), now_ms)? {
            Some(skipped) => self.log(now_ms, actor, kind, &serde_json::json!({ "suppressed": skipped })),
            None => Ok(()),
        }
    }

    /// Write a summary row for every run of folded-in failures whose window has closed. Called by the
    /// server every few seconds, so a burst is recorded even if nothing else fails afterwards.
    pub fn flush_failures(&self, now_ms: i64) -> rusqlite::Result<usize> {
        let due = crate::accounts::take_due_failures(&self.conn, now_ms)?;
        for p in &due {
            self.log(now_ms, &p.actor, &p.kind, &serde_json::json!({ "suppressed": p.count, "summary": true }))?;
        }
        Ok(due.len())
    }

    /// Remember when the pod was last reached, and how. Battery is stored only if the pod reported one.
    pub fn save_pod_status(&self, now_ms: i64, via: &str, battery: Option<i64>) -> rusqlite::Result<()> {
        let battery = battery.filter(|b| *b > 0);
        self.conn.execute(
            "INSERT INTO pod_status (id, checked_ms, via, battery) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET checked_ms = ?1, via = ?2, battery = ?3",
            params![now_ms, via, battery],
        )?;
        Ok(())
    }

    /// (checked_ms, via, battery)
    pub fn pod_status(&self) -> rusqlite::Result<Option<(i64, String, Option<i64>)>> {
        self.conn
            .query_row("SELECT checked_ms, via, battery FROM pod_status WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()
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
    fn failed_attempts_are_summarised_per_route_and_never_block_anything() {
        let s = Store::open_in_memory().unwrap();
        for t in 0..200 {
            s.log_failure(1_000 + t, "system", "login_failed").unwrap();
        }
        // The other route's first failure still gets its own row.
        s.log_failure(1_500, "local-cli", "login_failed").unwrap();
        let rows = audit::entries(s.connection(), 100).unwrap();
        assert_eq!(rows.len(), 2, "200 failures through the API and 1 through the CLI");
        assert!(rows.iter().any(|r| r.actor == "local-cli"));
        assert_eq!(audit::verify(s.connection()).unwrap(), None);
    }

    #[test]
    fn a_burst_of_failures_is_visible_at_once_and_recorded_without_waiting_for_another() {
        let s = Store::open_in_memory().unwrap();
        s.log_failure(1_000, "system", "login_failed").unwrap();
        let rows = |s: &Store| audit::entries(s.connection(), 100).unwrap();
        assert_eq!(rows(&s).len(), 1, "the first failure gets its own row at once");
        assert_eq!(rows(&s)[0].detail, r#"{"suppressed":0}"#);

        for t in 0..50 {
            s.log_failure(2_000 + t, "system", "login_failed").unwrap();
        }
        assert_eq!(rows(&s).len(), 1, "the rest are folded in");
        assert_eq!(crate::accounts::pending_failures(s.connection()).unwrap()[0].count, 50, "but visible immediately");

        // Nothing is written while the window is open; when it closes the worker writes the summary itself.
        assert_eq!(s.flush_failures(20_000).unwrap(), 0);
        assert_eq!(s.flush_failures(31_500).unwrap(), 1);
        let after = rows(&s);
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].detail, r#"{"summary":true,"suppressed":50}"#);
        assert!(crate::accounts::pending_failures(s.connection()).unwrap().is_empty());
        assert_eq!(s.flush_failures(40_000).unwrap(), 0, "and only once");

        // The next failure is a new window's first, and gets its own row.
        s.log_failure(45_000, "system", "login_failed").unwrap();
        assert_eq!(rows(&s).len(), 3);
        assert_eq!(audit::verify(s.connection()).unwrap(), None);
    }

    #[test]
    fn each_route_has_its_own_counter_including_the_command_line_ones() {
        let s = Store::open_in_memory().unwrap();
        // All five ways to fail, all at the same instant, after the API login has been flooded.
        for t in 0..100 {
            s.log_failure(1_000 + t, "system", "login_failed").unwrap();
        }
        for (actor, kind) in [
            ("local-cli", "login_failed"),           // the command line's keyholder password
            ("local-cli", "password_reset_failed"),  // the recovery PIN
            ("system", "pairing_failed"),            // a pairing code
            ("system", "password_change_failed"),    // a wrong current password on the API
        ] {
            s.log_failure(1_500, actor, kind).unwrap();
        }
        let rows = audit::entries(s.connection(), 100).unwrap();
        let mut seen: Vec<(String, String)> = rows.iter().map(|r| (r.actor.clone(), r.kind.clone())).collect();
        seen.sort();
        assert_eq!(seen.len(), 5, "one row for the flooded route and one first row for each of the other four: {seen:?}");
        assert!(seen.contains(&("local-cli".into(), "login_failed".into())), "a CLI failure surfaces even while the API is hammered");
        // The only thing pending is the flood itself.
        let pending = crate::accounts::pending_failures(s.connection()).unwrap();
        assert_eq!((pending.len(), pending[0].count), (1, 99));
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

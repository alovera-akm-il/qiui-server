//! Keyholder credentials, wearer device pairing, sessions, messages and
//! attempt throttling.
//!
//! Nothing secret is stored in a recoverable form. Passwords and the recovery
//! PIN are Argon2id hashes keyed with a server-side pepper that lives outside
//! the database; session tokens and pairing codes are stored only as SHA-256
//! hashes. Someone who copies the database learns none of them.

use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const KEYHOLDER_SESSION_MS: i64 = 8 * 60 * 60 * 1000;
pub const DEVICE_SESSION_MS: i64 = 400 * 24 * 60 * 60 * 1000;
pub const PAIRING_CODE_TTL_MS: i64 = 10 * 60 * 1000;

/// Unambiguous characters only (no 0/O, 1/I/L).
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LEN: usize = 8;

/// Runs of failed attempts are written to the audit log as one row per this long, with a count.
/// Nothing is ever blocked or delayed: this only stops a flood of guesses from filling the disk.
const FAILURE_LOG_WINDOW_MS: i64 = 30_000;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("no keyholder account exists yet")]
    NotInitialised,
    #[error("a keyholder account already exists")]
    AlreadyInitialised,
    #[error("that did not match")]
    Invalid,
    #[error("{0}")]
    Weak(&'static str),
    #[error("a wearer device is already paired; revoke it first")]
    DeviceAlreadyPaired,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("internal error")]
    Internal,
}

pub type Result<T> = std::result::Result<T, AuthError>;

// ---------- hashing and randomness ----------

pub struct Auth {
    pepper: Vec<u8>,
    params: Params,
}

impl Auth {
    pub fn new(pepper: Vec<u8>) -> Self {
        Self { pepper, params: Params::default() }
    }

    /// Cheap parameters so the test suite stays fast. Never used outside tests.
    #[cfg(test)]
    pub fn for_tests(pepper: &[u8]) -> Self {
        Self { pepper: pepper.to_vec(), params: Params::new(8, 1, 1, None).expect("valid test params") }
    }

    fn argon(&self) -> Argon2<'_> {
        Argon2::new_with_secret(&self.pepper, Algorithm::Argon2id, Version::V0x13, self.params.clone())
            .expect("pepper and params are valid")
    }

    pub fn hash_secret(&self, secret: &str) -> Result<String> {
        self.argon().hash_password(secret.as_bytes()).map(|h| h.to_string()).map_err(|_| AuthError::Internal)
    }

    /// A 32-byte key from a secret: Argon2id keyed with the pepper, so a copy of anything sealed with it
    /// is useless without both the password and `pepper.key`.
    pub fn derive_key(&self, secret: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        self.argon().hash_password_into(secret.as_bytes(), salt, &mut key).map_err(|_| AuthError::Internal)?;
        Ok(key)
    }

    pub fn verify_secret(&self, secret: &str, phc: &str) -> bool {
        PasswordVerifier::<str>::verify_password(&self.argon(), secret.as_bytes(), phc).is_ok()
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("operating system randomness is available");
    b
}

/// 256-bit token, hex encoded. Only its SHA-256 is ever stored.
pub fn random_token() -> String {
    hex::encode(random_bytes::<32>())
}

/// Uniform integer in `0..n` by rejection sampling (no modulo bias).
pub fn random_below(n: u64) -> u64 {
    assert!(n > 0);
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64::from_le_bytes(random_bytes::<8>());
        if v < zone {
            return v % n;
        }
    }
}

fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

// ---------- schema ----------

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS keyholder (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            pin_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS failure_log (
            kind TEXT PRIMARY KEY,
            last_logged_ms INTEGER NOT NULL,
            suppressed INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            paired_ms INTEGER NOT NULL,
            last_seen_ms INTEGER,
            revoked_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash BLOB PRIMARY KEY,
            role TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id),
            created_ms INTEGER NOT NULL,
            expires_ms INTEGER NOT NULL,
            revoked_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS pairing_codes (
            code_hash BLOB PRIMARY KEY,
            created_ms INTEGER NOT NULL,
            expires_ms INTEGER NOT NULL,
            used_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ms INTEGER NOT NULL,
            body TEXT NOT NULL,
            read_ms INTEGER
        );",
    )
}

// ---------- failed attempts ----------
//
// A wrong password, PIN or pairing code is never punished: no lockout, no delay. The
// only cost is Argon2's own work per guess. Failures are still recorded.

/// Decide whether this failure gets its own audit row. Returns `Some(n)` (n = failures skipped since the
/// last row) if it should be logged now, or `None` if it is folded into the next row's count.
pub fn note_failure(conn: &Connection, kind: &str, now_ms: i64) -> rusqlite::Result<Option<i64>> {
    let row: Option<(i64, i64)> = conn
        .query_row("SELECT last_logged_ms, suppressed FROM failure_log WHERE kind = ?1", [kind], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    match row {
        Some((last, suppressed)) if now_ms >= last && now_ms - last < FAILURE_LOG_WINDOW_MS => {
            conn.execute("UPDATE failure_log SET suppressed = ?1 WHERE kind = ?2", params![suppressed + 1, kind])?;
            Ok(None)
        }
        other => {
            let carried = other.map_or(0, |(_, n)| n);
            conn.execute(
                "INSERT INTO failure_log (kind, last_logged_ms, suppressed) VALUES (?1, ?2, 0)
                 ON CONFLICT(kind) DO UPDATE SET last_logged_ms = ?2, suppressed = 0",
                params![kind, now_ms],
            )?;
            Ok(Some(carried))
        }
    }
}

// ---------- keyholder ----------

fn check_password(password: &str) -> Result<()> {
    if password.chars().count() < 10 {
        return Err(AuthError::Weak("password must be at least 10 characters"));
    }
    Ok(())
}

fn check_pin(pin: &str) -> Result<()> {
    if !(6..=12).contains(&pin.len()) || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::Weak("recovery PIN must be 6 to 12 digits"));
    }
    Ok(())
}

pub fn is_initialised(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row("SELECT COUNT(*) FROM keyholder", [], |r| r.get::<_, i64>(0))? > 0)
}

pub fn init_keyholder(conn: &Connection, auth: &Auth, password: &str, pin: &str) -> Result<()> {
    if is_initialised(conn)? {
        return Err(AuthError::AlreadyInitialised);
    }
    check_password(password)?;
    check_pin(pin)?;
    conn.execute(
        "INSERT INTO keyholder (id, password_hash, pin_hash) VALUES (1, ?1, ?2)",
        params![auth.hash_secret(password)?, auth.hash_secret(pin)?],
    )?;
    Ok(())
}

fn load_hashes(conn: &Connection) -> Result<(String, String)> {
    conn.query_row("SELECT password_hash, pin_hash FROM keyholder WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or(AuthError::NotInitialised)
}

/// Check the keyholder password. A wrong one is refused, and that is all: there is no lockout.
pub fn verify_password(conn: &Connection, auth: &Auth, password: &str) -> Result<()> {
    let (hash, _) = load_hashes(conn)?;
    if auth.verify_secret(password, &hash) { Ok(()) } else { Err(AuthError::Invalid) }
}

pub fn login(conn: &Connection, auth: &Auth, password: &str, now_ms: i64) -> Result<String> {
    verify_password(conn, auth, password)?;
    create_session(conn, Role::Keyholder, None, now_ms, KEYHOLDER_SESSION_MS)
}

pub fn change_password(conn: &Connection, auth: &Auth, current: &str, new: &str, now_ms: i64) -> Result<()> {
    check_password(new)?;
    verify_password(conn, auth, current)?;
    set_password(conn, auth, new, now_ms)
}

/// Local recovery: the recovery PIN authorises a new password.
pub fn reset_password_with_pin(conn: &Connection, auth: &Auth, pin: &str, new: &str, now_ms: i64) -> Result<()> {
    check_password(new)?;
    let (_, pin_hash) = load_hashes(conn)?;
    if !auth.verify_secret(pin, &pin_hash) {
        return Err(AuthError::Invalid);
    }
    set_password(conn, auth, new, now_ms)
}

fn set_password(conn: &Connection, auth: &Auth, new: &str, now_ms: i64) -> Result<()> {
    conn.execute("UPDATE keyholder SET password_hash = ?1 WHERE id = 1", [auth.hash_secret(new)?])?;
    revoke_sessions(conn, Role::Keyholder, now_ms)
}

// ---------- sessions ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Keyholder,
    Wearer,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Keyholder => "keyholder",
            Role::Wearer => "wearer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Principal {
    pub role: Role,
    pub device_id: Option<i64>,
}

fn create_session(conn: &Connection, role: Role, device_id: Option<i64>, now_ms: i64, ttl_ms: i64) -> Result<String> {
    let token = random_token();
    conn.execute(
        "INSERT INTO sessions (token_hash, role, device_id, created_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![sha256(&token), role.as_str(), device_id, now_ms, now_ms + ttl_ms],
    )?;
    Ok(token)
}

/// Resolve a bearer token. Wearer sessions also die with their device.
pub fn authenticate(conn: &Connection, token: &str, now_ms: i64) -> Result<Option<Principal>> {
    let row: Option<(String, Option<i64>)> = conn
        .query_row(
            "SELECT s.role, s.device_id FROM sessions s
             LEFT JOIN devices d ON d.id = s.device_id
             WHERE s.token_hash = ?1 AND s.revoked_ms IS NULL AND s.expires_ms > ?2
               AND (s.device_id IS NULL OR d.revoked_ms IS NULL)",
            params![sha256(token), now_ms],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((role, device_id)) = row else { return Ok(None) };
    let role = match role.as_str() {
        "keyholder" => Role::Keyholder,
        "wearer" => Role::Wearer,
        _ => return Ok(None),
    };
    if let Some(id) = device_id {
        conn.execute("UPDATE devices SET last_seen_ms = ?1 WHERE id = ?2", params![now_ms, id])?;
    }
    Ok(Some(Principal { role, device_id }))
}

pub fn logout(conn: &Connection, token: &str, now_ms: i64) -> Result<()> {
    conn.execute("UPDATE sessions SET revoked_ms = ?1 WHERE token_hash = ?2", params![now_ms, sha256(token)])?;
    Ok(())
}

pub fn revoke_sessions(conn: &Connection, role: Role, now_ms: i64) -> Result<()> {
    conn.execute(
        "UPDATE sessions SET revoked_ms = ?1 WHERE role = ?2 AND revoked_ms IS NULL",
        params![now_ms, role.as_str()],
    )?;
    Ok(())
}

// ---------- wearer device pairing ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub paired_ms: i64,
    pub last_seen_ms: Option<i64>,
    pub revoked_ms: Option<i64>,
}

fn normalise_code(code: &str) -> Option<String> {
    let c: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect();
    (c.len() == CODE_LEN && c.bytes().all(|b| CODE_ALPHABET.contains(&b))).then_some(c)
}

/// One-time code the keyholder reads out to the wearer. Replaces any unused code.
pub fn create_pairing_code(conn: &Connection, now_ms: i64) -> Result<String> {
    let raw: String = (0..CODE_LEN).map(|_| CODE_ALPHABET[random_below(CODE_ALPHABET.len() as u64) as usize] as char).collect();
    conn.execute("DELETE FROM pairing_codes WHERE used_ms IS NULL", [])?;
    conn.execute(
        "INSERT INTO pairing_codes (code_hash, created_ms, expires_ms) VALUES (?1, ?2, ?3)",
        params![sha256(&raw), now_ms, now_ms + PAIRING_CODE_TTL_MS],
    )?;
    Ok(format!("{}-{}", &raw[..4], &raw[4..]))
}

fn active_device_exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row("SELECT COUNT(*) FROM devices WHERE revoked_ms IS NULL", [], |r| r.get::<_, i64>(0))? > 0)
}

/// Exchange a pairing code for a long-lived device token. One active device at a time.
pub fn pair_device(conn: &Connection, code: &str, device_name: &str, now_ms: i64) -> Result<String> {
    let name = device_name.trim();
    let name = if name.is_empty() { "wearer device" } else { name };
    let name: String = name.chars().take(60).collect();

    let valid = match normalise_code(code) {
        Some(c) => conn
            .query_row(
                "SELECT COUNT(*) FROM pairing_codes WHERE code_hash = ?1 AND used_ms IS NULL AND expires_ms > ?2",
                params![sha256(&c), now_ms],
                |r| r.get::<_, i64>(0),
            )?
            > 0,
        None => false,
    };
    if !valid {
        return Err(AuthError::Invalid);
    }
    if active_device_exists(conn)? {
        return Err(AuthError::DeviceAlreadyPaired);
    }
    let c = normalise_code(code).ok_or(AuthError::Internal)?;
    conn.execute("UPDATE pairing_codes SET used_ms = ?1 WHERE code_hash = ?2", params![now_ms, sha256(&c)])?;
    conn.execute("INSERT INTO devices (name, paired_ms) VALUES (?1, ?2)", params![name, now_ms])?;
    let device_id = conn.last_insert_rowid();
    create_session(conn, Role::Wearer, Some(device_id), now_ms, DEVICE_SESSION_MS)
}

pub fn list_devices(conn: &Connection) -> Result<Vec<Device>> {
    let mut stmt = conn.prepare("SELECT id, name, paired_ms, last_seen_ms, revoked_ms FROM devices ORDER BY id")?;
    let rows = stmt.query_map([], |r| {
        Ok(Device { id: r.get(0)?, name: r.get(1)?, paired_ms: r.get(2)?, last_seen_ms: r.get(3)?, revoked_ms: r.get(4)? })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Returns false if there was no such active device.
pub fn revoke_device(conn: &Connection, id: i64, now_ms: i64) -> Result<bool> {
    let changed = conn.execute("UPDATE devices SET revoked_ms = ?1 WHERE id = ?2 AND revoked_ms IS NULL", params![now_ms, id])?;
    conn.execute("UPDATE sessions SET revoked_ms = ?1 WHERE device_id = ?2 AND revoked_ms IS NULL", params![now_ms, id])?;
    Ok(changed > 0)
}

// ---------- messages ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: i64,
    pub ts_ms: i64,
    pub body: String,
    pub read_ms: Option<i64>,
}

pub fn add_message(conn: &Connection, body: &str, now_ms: i64) -> Result<i64> {
    let body = body.trim();
    if body.is_empty() {
        return Err(AuthError::Weak("message is empty"));
    }
    if body.chars().count() > 1000 {
        return Err(AuthError::Weak("message is longer than 1000 characters"));
    }
    conn.execute("INSERT INTO messages (ts_ms, body) VALUES (?1, ?2)", params![now_ms, body])?;
    Ok(conn.last_insert_rowid())
}

pub fn message_body(conn: &Connection, id: i64) -> Result<Option<String>> {
    Ok(conn.query_row("SELECT body FROM messages WHERE id = ?1", [id], |r| r.get(0)).optional()?)
}

/// Newest first.
pub fn list_messages(conn: &Connection, limit: u32) -> Result<Vec<Message>> {
    let mut stmt = conn.prepare("SELECT id, ts_ms, body, read_ms FROM messages ORDER BY id DESC LIMIT ?1")?;
    let rows = stmt.query_map([limit], |r| Ok(Message { id: r.get(0)?, ts_ms: r.get(1)?, body: r.get(2)?, read_ms: r.get(3)? }))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn unread_count(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM messages WHERE read_ms IS NULL", [], |r| r.get(0))?)
}

pub fn mark_messages_read(conn: &Connection, now_ms: i64) -> Result<()> {
    conn.execute("UPDATE messages SET read_ms = ?1 WHERE read_ms IS NULL", [now_ms])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";
    const PIN: &str = "482913";

    fn setup() -> (Connection, Auth) {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        let auth = Auth::for_tests(b"test pepper");
        init_keyholder(&conn, &auth, PW, PIN).unwrap();
        (conn, auth)
    }

    #[test]
    fn init_happens_once_and_enforces_minimums() {
        let (conn, auth) = setup();
        assert!(matches!(init_keyholder(&conn, &auth, PW, PIN), Err(AuthError::AlreadyInitialised)));
        let fresh = Connection::open_in_memory().unwrap();
        migrate(&fresh).unwrap();
        assert!(matches!(init_keyholder(&fresh, &auth, "short", PIN), Err(AuthError::Weak(_))));
        assert!(matches!(init_keyholder(&fresh, &auth, PW, "12ab56"), Err(AuthError::Weak(_))));
        assert!(matches!(init_keyholder(&fresh, &auth, PW, "12345"), Err(AuthError::Weak(_))));
    }

    #[test]
    fn database_holds_no_recoverable_secrets() {
        let (conn, auth) = setup();
        let token = login(&conn, &auth, PW, 0).unwrap();
        let code = create_pairing_code(&conn, 0).unwrap();
        let wearer = pair_device(&conn, &code, "phone", 0).unwrap();

        // Dump every text and blob column and look for anything we handed out.
        let mut everything = String::new();
        for table in ["keyholder", "sessions", "pairing_codes", "devices", "failure_log"] {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let n = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();
            while let Some(r) = rows.next().unwrap() {
                for i in 0..n {
                    match r.get_ref(i).unwrap() {
                        rusqlite::types::ValueRef::Text(t) => everything.push_str(&String::from_utf8_lossy(t)),
                        rusqlite::types::ValueRef::Blob(b) => everything.push_str(&hex::encode(b)),
                        _ => {}
                    }
                    everything.push('|');
                }
            }
        }
        let raw_code = code.replace('-', "");
        for secret in [PW, PIN, token.as_str(), wearer.as_str(), raw_code.as_str()] {
            assert!(!everything.contains(secret), "found a plaintext secret in the database");
        }
    }

    #[test]
    fn a_different_pepper_cannot_verify_stored_hashes() {
        let (conn, auth) = setup();
        let (hash, _) = load_hashes(&conn).unwrap();
        assert!(auth.verify_secret(PW, &hash));
        assert!(!Auth::for_tests(b"another pepper").verify_secret(PW, &hash));
    }

    #[test]
    fn login_sessions_and_expiry() {
        let (conn, auth) = setup();
        assert!(matches!(login(&conn, &auth, "wrong password!", 0), Err(AuthError::Invalid)));
        let token = login(&conn, &auth, PW, 0).unwrap();
        let p = authenticate(&conn, &token, 1).unwrap().unwrap();
        assert_eq!(p.role, Role::Keyholder);
        assert!(authenticate(&conn, "not a token", 1).unwrap().is_none());
        assert!(authenticate(&conn, &token, KEYHOLDER_SESSION_MS).unwrap().is_none());
        logout(&conn, &token, 2).unwrap();
        assert!(authenticate(&conn, &token, 3).unwrap().is_none());
    }

    #[test]
    fn wrong_passwords_never_lock_anyone_out() {
        let (conn, auth) = setup();
        for _ in 0..60 {
            assert!(matches!(login(&conn, &auth, "nope nope nope", 0), Err(AuthError::Invalid)));
        }
        // Straight after any number of failures, at the same instant, the right password works.
        assert!(login(&conn, &auth, PW, 0).is_ok());
        assert!(verify_password(&conn, &auth, PW).is_ok());
    }

    #[test]
    fn failures_are_summarised_in_the_log_not_punished() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        // The first failure is logged at once, the next ones inside the window are folded in...
        assert_eq!(note_failure(&conn, "login_failed", 1_000).unwrap(), Some(0));
        for t in [2_000, 3_000, 29_999] {
            assert_eq!(note_failure(&conn, "login_failed", t).unwrap(), None);
        }
        // ...and the next row after the window says how many were skipped.
        assert_eq!(note_failure(&conn, "login_failed", 31_000).unwrap(), Some(3));
        assert_eq!(note_failure(&conn, "login_failed", 31_500).unwrap(), None);
        // Different kinds are counted separately, and a clock that went backwards does not silence the log.
        assert_eq!(note_failure(&conn, "pairing_failed", 31_500).unwrap(), Some(0));
        assert_eq!(note_failure(&conn, "login_failed", 5).unwrap(), Some(1));
    }

    #[test]
    fn the_recovery_pin_works_after_any_number_of_wrong_guesses_and_signs_everyone_out() {
        let (conn, auth) = setup();
        let old = create_session(&conn, Role::Keyholder, None, 0, KEYHOLDER_SESSION_MS).unwrap();
        for _ in 0..40 {
            assert!(matches!(reset_password_with_pin(&conn, &auth, "000000", "another good password", 1), Err(AuthError::Invalid)));
        }
        reset_password_with_pin(&conn, &auth, PIN, "another good password", 1).unwrap();
        assert!(authenticate(&conn, &old, 2).unwrap().is_none());
        assert!(login(&conn, &auth, "another good password", 2).is_ok());
    }

    #[test]
    fn changing_password_needs_the_current_one_and_kills_old_sessions() {
        let (conn, auth) = setup();
        let old = login(&conn, &auth, PW, 0).unwrap();
        assert!(matches!(change_password(&conn, &auth, "wrong password!", "a brand new password", 1), Err(AuthError::Invalid)));
        change_password(&conn, &auth, PW, "a brand new password", 2).unwrap();
        assert!(authenticate(&conn, &old, 3).unwrap().is_none());
        assert!(login(&conn, &auth, PW, 4).is_err());
        assert!(login(&conn, &auth, "a brand new password", 5).is_ok());
    }

    #[test]
    fn pairing_code_is_single_use_expires_and_yields_a_wearer_session() {
        let (conn, _) = setup();
        let code = create_pairing_code(&conn, 0).unwrap();
        assert_eq!(code.len(), 9);

        let token = pair_device(&conn, &code.to_lowercase().replace('-', " "), "Pixel", 1).unwrap();
        let p = authenticate(&conn, &token, 2).unwrap().unwrap();
        assert_eq!(p.role, Role::Wearer);
        assert!(p.device_id.is_some());

        // Used codes cannot be reused, even after revoking the device.
        revoke_device(&conn, p.device_id.unwrap(), 3).unwrap();
        assert!(matches!(pair_device(&conn, &code, "again", 4), Err(AuthError::Invalid)));

        // Expired codes are refused.
        let late = create_pairing_code(&conn, 10).unwrap();
        assert!(matches!(pair_device(&conn, &late, "phone", 10 + PAIRING_CODE_TTL_MS), Err(AuthError::Invalid)));
    }

    #[test]
    fn only_one_device_may_be_paired_until_it_is_revoked() {
        let (conn, _) = setup();
        let first = pair_device(&conn, &create_pairing_code(&conn, 0).unwrap(), "phone", 1).unwrap();
        assert!(matches!(
            pair_device(&conn, &create_pairing_code(&conn, 2).unwrap(), "laptop", 3),
            Err(AuthError::DeviceAlreadyPaired)
        ));
        let device = list_devices(&conn).unwrap()[0].id;
        assert!(revoke_device(&conn, device, 4).unwrap());
        assert!(!revoke_device(&conn, device, 5).unwrap());
        assert!(authenticate(&conn, &first, 6).unwrap().is_none(), "a revoked device's token must stop working");
        assert!(pair_device(&conn, &create_pairing_code(&conn, 7).unwrap(), "new phone", 8).is_ok());
    }

    #[test]
    fn wrong_pairing_codes_never_block_the_real_one() {
        let (conn, _) = setup();
        let real = create_pairing_code(&conn, 0).unwrap();
        for _ in 0..40 {
            assert!(matches!(pair_device(&conn, "AAAA-AAAA", "x", 1), Err(AuthError::Invalid)));
        }
        assert!(pair_device(&conn, &real, "phone", 2).is_ok());
    }

    #[test]
    fn generating_a_new_code_invalidates_the_previous_unused_one() {
        let (conn, _) = setup();
        let first = create_pairing_code(&conn, 0).unwrap();
        let _second = create_pairing_code(&conn, 1).unwrap();
        assert!(matches!(pair_device(&conn, &first, "phone", 2), Err(AuthError::Invalid)));
    }

    #[test]
    fn messages_round_trip_and_read_tracking() {
        let (conn, _) = setup();
        assert!(add_message(&conn, "   ", 0).is_err());
        assert!(add_message(&conn, &"x".repeat(1001), 0).is_err());
        add_message(&conn, "  well done  ", 1).unwrap();
        add_message(&conn, "second", 2).unwrap();
        assert_eq!(unread_count(&conn).unwrap(), 2);
        let msgs = list_messages(&conn, 10).unwrap();
        assert_eq!(msgs[0].body, "second");
        assert_eq!(msgs[1].body, "well done");
        mark_messages_read(&conn, 3).unwrap();
        assert_eq!(unread_count(&conn).unwrap(), 0);
    }

    #[test]
    fn random_below_stays_in_range() {
        for _ in 0..1000 {
            assert!(random_below(7) < 7);
        }
        assert_eq!(random_below(1), 0);
    }
}

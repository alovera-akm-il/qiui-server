//! The QIUI credentials, sealed at rest.
//!
//! `config.json` never holds them in the clear. They are encrypted with a key
//! derived from the keyholder's password (and the server's pepper), so a copied
//! file or disk is useless without the password. The server decrypts them in
//! memory the first time the keyholder signs in after a start, and never writes
//! anything decrypted back to disk.

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::accounts::{Auth, KdfParams, random_bytes};

/// Version 2 records the key-derivation settings it was sealed with, so they can be strengthened later.
/// Version 1 predates that and always used `KdfParams::LEGACY`.
const VERSION: u8 = 2;
/// Bound into every sealed blob, so it cannot be swapped for one sealed for another purpose.
const AAD_V1: &[u8] = b"qiui-server config secrets v1";

/// Version 2 also binds its settings, so lowering them in the file to make guessing cheaper breaks the seal.
fn aad_v2(k: KdfParams) -> Vec<u8> {
    format!("qiui-server config secrets v2 m={} t={} p={}", k.m, k.t, k.p).into_bytes()
}

#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("wrong password, or the sealed credentials were altered")]
    Wrong,
    #[error("the sealed credentials are unreadable: {0}")]
    Malformed(&'static str),
    #[error("no QIUI client id is stored")]
    NoClientId,
    #[error("could not derive the encryption key")]
    Kdf,
}

/// What is protected. Plain values exist only in memory, for as long as they are needed.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Secrets {
    pub client_id: Option<String>,
    pub api_key: Option<String>,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.client_id.zeroize();
        self.api_key.zeroize();
    }
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secrets {{ client_id: {}, api_key: {} }}", self.client_id.is_some(), self.api_key.is_some())
    }
}

/// The encrypted form, as stored in `config.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecrets {
    pub v: u8,
    pub kdf: String,
    /// Key-derivation settings (memory in KiB, passes, lanes). Absent in version 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
    pub salt: String,
    pub nonce: String,
    pub ct: String,
}

fn cipher(auth: &Auth, password: &str, salt: &[u8], kdf: KdfParams) -> Result<XChaCha20Poly1305, SecretsError> {
    let key = Zeroizing::new(auth.derive_key_with(password, salt, kdf).map_err(|_| SecretsError::Kdf)?);
    XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| SecretsError::Kdf)
}

impl SealedSecrets {
    /// The settings this was sealed with.
    fn params(&self) -> Result<KdfParams, SecretsError> {
        match (self.v, self.m, self.t, self.p) {
            (1, ..) => Ok(KdfParams::LEGACY),
            (2, Some(m), Some(t), Some(p)) => {
                let k = KdfParams { m, t, p };
                if k.is_reasonable() { Ok(k) } else { Err(SecretsError::Malformed("unreasonable key settings")) }
            }
            _ => Err(SecretsError::Malformed("unknown format")),
        }
    }

    /// True if it was sealed under older or different settings than `auth` uses now.
    pub fn needs_upgrade(&self, auth: &Auth) -> bool {
        self.v != VERSION || self.params().ok() != Some(auth.params())
    }
}

/// Encrypt under a fresh salt and nonce, and the current settings. Sealing the same values twice gives different bytes.
pub fn seal(auth: &Auth, password: &str, secrets: &Secrets) -> Result<SealedSecrets, SecretsError> {
    let kdf = auth.params();
    let salt = random_bytes::<16>();
    let nonce = random_bytes::<24>();
    let plain = Zeroizing::new(serde_json::to_vec(secrets).map_err(|_| SecretsError::Malformed("serialise"))?);
    let ct = cipher(auth, password, &salt, kdf)?
        .encrypt(&XNonce::try_from(&nonce[..]).map_err(|_| SecretsError::Kdf)?, Payload { msg: &plain, aad: &aad_v2(kdf) })
        .map_err(|_| SecretsError::Kdf)?;
    Ok(SealedSecrets {
        v: VERSION,
        kdf: "argon2id".into(),
        m: Some(kdf.m),
        t: Some(kdf.t),
        p: Some(kdf.p),
        salt: Base64UrlUnpadded::encode_string(&salt),
        nonce: Base64UrlUnpadded::encode_string(&nonce),
        ct: Base64UrlUnpadded::encode_string(&ct),
    })
}

/// Decrypt into memory, under the settings recorded with it. A wrong password and tampering look the same, by design.
pub fn open(auth: &Auth, password: &str, sealed: &SealedSecrets) -> Result<Secrets, SecretsError> {
    if sealed.kdf != "argon2id" {
        return Err(SecretsError::Malformed("unknown format"));
    }
    let kdf = sealed.params()?;
    let aad: Vec<u8> = if sealed.v == 1 { AAD_V1.to_vec() } else { aad_v2(kdf) };
    let decode = |s: &str| Base64UrlUnpadded::decode_vec(s).map_err(|_| SecretsError::Malformed("not base64"));
    let (salt, nonce, ct) = (decode(&sealed.salt)?, decode(&sealed.nonce)?, decode(&sealed.ct)?);
    if nonce.len() != 24 {
        return Err(SecretsError::Malformed("bad nonce"));
    }
    let plain = Zeroizing::new(
        cipher(auth, password, &salt, kdf)?
            .decrypt(&XNonce::try_from(&nonce[..]).map_err(|_| SecretsError::Malformed("bad nonce"))?, Payload { msg: &ct, aad: &aad })
            .map_err(|_| SecretsError::Wrong)?,
    );
    serde_json::from_slice(&plain).map_err(|_| SecretsError::Malformed("contents"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::for_tests(b"secrets test pepper")
    }

    fn sample() -> Secrets {
        Secrets { client_id: Some("Client_ABCDEF0123456789".into()), api_key: Some("APIKEY-9876543210".into()) }
    }

    #[test]
    fn sealed_credentials_open_again_with_the_same_password() {
        let sealed = seal(&auth(), "hunter2 hunter2", &sample()).unwrap();
        let back = open(&auth(), "hunter2 hunter2", &sealed).unwrap();
        assert_eq!(back.client_id.as_deref(), Some("Client_ABCDEF0123456789"));
        assert_eq!(back.api_key.as_deref(), Some("APIKEY-9876543210"));
    }

    #[test]
    fn nothing_readable_is_left_in_the_sealed_form() {
        let sealed = seal(&auth(), "hunter2 hunter2", &sample()).unwrap();
        let text = serde_json::to_string(&sealed).unwrap();
        for plain in ["Client_ABCDEF", "APIKEY-9876", "client_id", "api_key"] {
            assert!(!text.contains(plain), "{plain} leaked into {text}");
        }
    }

    #[test]
    fn a_wrong_password_a_different_pepper_or_tampering_all_fail_the_same_way() {
        let sealed = seal(&auth(), "right password", &sample()).unwrap();
        assert!(matches!(open(&auth(), "wrong password", &sealed), Err(SecretsError::Wrong)));
        assert!(matches!(open(&Auth::for_tests(b"another pepper"), "right password", &sealed), Err(SecretsError::Wrong)));

        let mut bytes = Base64UrlUnpadded::decode_vec(&sealed.ct).unwrap();
        bytes[0] ^= 1;
        let tampered = SealedSecrets { ct: Base64UrlUnpadded::encode_string(&bytes), ..sealed.clone() };
        assert!(matches!(open(&auth(), "right password", &tampered), Err(SecretsError::Wrong)));
    }

    #[test]
    fn every_seal_uses_a_fresh_salt_and_nonce() {
        let a = seal(&auth(), "pw pw pw pw pw", &sample()).unwrap();
        let b = seal(&auth(), "pw pw pw pw pw", &sample()).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let good = seal(&auth(), "pw pw pw pw pw", &sample()).unwrap();
        for bad in [
            SealedSecrets { v: 9, ..good.clone() },
            SealedSecrets { kdf: "scrypt".into(), ..good.clone() },
            SealedSecrets { nonce: "AAAA".into(), ..good.clone() },
            SealedSecrets { ct: "!!!".into(), ..good.clone() },
            SealedSecrets { salt: String::new(), ..good.clone() },
        ] {
            assert!(open(&auth(), "pw pw pw pw pw", &bad).is_err());
        }
    }

    /// A blob as an earlier version wrote it: legacy settings, not recorded, and the v1 binding.
    fn legacy_blob(pepper: &[u8], password: &str, secrets: &Secrets) -> SealedSecrets {
        let old = Auth::with_params(pepper.to_vec(), KdfParams::LEGACY);
        let (salt, nonce) = (random_bytes::<16>(), random_bytes::<24>());
        let ct = cipher(&old, password, &salt, KdfParams::LEGACY)
            .unwrap()
            .encrypt(&XNonce::try_from(&nonce[..]).unwrap(), Payload { msg: &serde_json::to_vec(secrets).unwrap(), aad: AAD_V1 })
            .unwrap();
        SealedSecrets {
            v: 1,
            kdf: "argon2id".into(),
            m: None,
            t: None,
            p: None,
            salt: Base64UrlUnpadded::encode_string(&salt),
            nonce: Base64UrlUnpadded::encode_string(&nonce),
            ct: Base64UrlUnpadded::encode_string(&ct),
        }
    }

    #[test]
    fn credentials_sealed_before_the_settings_were_recorded_still_open_and_are_flagged_for_upgrade() {
        let sealed = legacy_blob(b"secrets test pepper", "an old password!!", &sample());
        // The current settings are stronger than the legacy ones, yet the old blob opens: it is read under its own.
        let modern = Auth::with_params(b"secrets test pepper".to_vec(), KdfParams { m: 64, t: 2, p: 1 });
        assert_eq!(open(&modern, "an old password!!", &sealed).unwrap().api_key.as_deref(), Some("APIKEY-9876543210"));
        assert!(sealed.needs_upgrade(&modern));
        // Sealing again records the current settings, and is then up to date.
        let fresh = seal(&modern, "an old password!!", &sample()).unwrap();
        assert!(!fresh.needs_upgrade(&modern));
        assert_eq!((fresh.v, fresh.m, fresh.t, fresh.p), (2, Some(64), Some(2), Some(1)));
    }

    #[test]
    fn credentials_still_open_after_the_current_settings_change() {
        let then = Auth::with_params(b"secrets test pepper".to_vec(), KdfParams { m: 16, t: 1, p: 1 });
        let sealed = seal(&then, "pw pw pw pw pw pw", &sample()).unwrap();
        let now = Auth::with_params(b"secrets test pepper".to_vec(), KdfParams { m: 64, t: 3, p: 1 });
        assert!(open(&now, "pw pw pw pw pw pw", &sealed).is_ok(), "the settings come from the blob, not from today's defaults");
        assert!(sealed.needs_upgrade(&now));
    }

    #[test]
    fn lowering_the_recorded_settings_to_make_guessing_cheaper_breaks_the_seal() {
        let strong = Auth::with_params(b"secrets test pepper".to_vec(), KdfParams { m: 32, t: 2, p: 1 });
        let sealed = seal(&strong, "right password!!!", &sample()).unwrap();
        assert!(open(&strong, "right password!!!", &sealed).is_ok());
        // Someone edits the file to say "m=8, t=1" so a guesser would find it cheaper.
        let cheaper = SealedSecrets { m: Some(8), t: Some(1), ..sealed.clone() };
        assert!(open(&strong, "right password!!!", &cheaper).is_err());
    }

    #[test]
    fn absurd_settings_in_a_file_are_refused_not_allocated() {
        let sealed = seal(&auth(), "right password!!!", &sample()).unwrap();
        for bad in [
            SealedSecrets { m: Some(u32::MAX), ..sealed.clone() },
            SealedSecrets { t: Some(10_000), ..sealed.clone() },
            SealedSecrets { p: Some(0), ..sealed.clone() },
            SealedSecrets { m: None, ..sealed.clone() },
        ] {
            assert!(matches!(open(&auth(), "right password!!!", &bad), Err(SecretsError::Malformed(_))));
        }
    }

    #[test]
    fn debug_output_never_shows_the_values() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("Client_") && !shown.contains("APIKEY"), "{shown}");
    }
}

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

use crate::accounts::{Auth, random_bytes};

const VERSION: u8 = 1;
/// Bound into every sealed blob, so it cannot be swapped for one sealed for another purpose.
const AAD: &[u8] = b"qiui-server config secrets v1";

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
    pub salt: String,
    pub nonce: String,
    pub ct: String,
}

fn cipher(auth: &Auth, password: &str, salt: &[u8]) -> Result<XChaCha20Poly1305, SecretsError> {
    let key = Zeroizing::new(auth.derive_key(password, salt).map_err(|_| SecretsError::Kdf)?);
    XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| SecretsError::Kdf)
}

/// Encrypt under a fresh salt and nonce. Sealing the same values twice gives different bytes.
pub fn seal(auth: &Auth, password: &str, secrets: &Secrets) -> Result<SealedSecrets, SecretsError> {
    let salt = random_bytes::<16>();
    let nonce = random_bytes::<24>();
    let plain = Zeroizing::new(serde_json::to_vec(secrets).map_err(|_| SecretsError::Malformed("serialise"))?);
    let ct = cipher(auth, password, &salt)?
        .encrypt(&XNonce::try_from(&nonce[..]).map_err(|_| SecretsError::Kdf)?, Payload { msg: &plain, aad: AAD })
        .map_err(|_| SecretsError::Kdf)?;
    Ok(SealedSecrets {
        v: VERSION,
        kdf: "argon2id".into(),
        salt: Base64UrlUnpadded::encode_string(&salt),
        nonce: Base64UrlUnpadded::encode_string(&nonce),
        ct: Base64UrlUnpadded::encode_string(&ct),
    })
}

/// Decrypt into memory. A wrong password and tampering look the same, by design.
pub fn open(auth: &Auth, password: &str, sealed: &SealedSecrets) -> Result<Secrets, SecretsError> {
    if sealed.v != VERSION || sealed.kdf != "argon2id" {
        return Err(SecretsError::Malformed("unknown format"));
    }
    let decode = |s: &str| Base64UrlUnpadded::decode_vec(s).map_err(|_| SecretsError::Malformed("not base64"));
    let (salt, nonce, ct) = (decode(&sealed.salt)?, decode(&sealed.nonce)?, decode(&sealed.ct)?);
    if nonce.len() != 24 {
        return Err(SecretsError::Malformed("bad nonce"));
    }
    let plain = Zeroizing::new(
        cipher(auth, password, &salt)?
            .decrypt(&XNonce::try_from(&nonce[..]).map_err(|_| SecretsError::Malformed("bad nonce"))?, Payload { msg: &ct, aad: AAD })
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

    #[test]
    fn debug_output_never_shows_the_values() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("Client_") && !shown.contains("APIKEY"), "{shown}");
    }
}

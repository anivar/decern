// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-crypto — Ed25519 key generation and file handling used by the ledger.
//! Keys are raw 32-byte seeds stored hex-encoded, mode 0600. Key generation
//! avoids the rand-version treadmill by seeding directly from the OS entropy
//! source.
//!
//! **Secret hygiene.** Every transient buffer that ever holds raw private-key
//! seed material or a fresh opaque secret is [`Zeroize`]d before it drops, so a
//! seed does not linger in freed heap/stack pages after the owning [`SigningKey`]
//! has been constructed (the key itself zeroizes on drop via ed25519-dalek's
//! `zeroize` feature). Opaque-secret minting is held to a 128-bit entropy floor.

use std::fs;
use std::path::Path;

pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

/// Minimum bytes of OS entropy behind a minted opaque secret (128 bits). RFC
/// 7591/7592 secrets "MUST contain sufficient entropy to prevent a random
/// guessing attack"; decern refuses to mint anything weaker rather than trust the
/// caller's `n`.
pub const MIN_TOKEN_BYTES: usize = 16;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    #[error("entropy source failed: {0}")]
    Entropy(String),
    #[error("cannot read key file {path}: {err}")]
    Read { path: String, err: String },
    #[error("cannot write key file {path}: {err}")]
    Write { path: String, err: String },
    #[error("malformed key material in {0} (expected 32 bytes hex)")]
    Malformed(String),
    #[error("requested token length {got} bytes is below the {min}-byte entropy floor")]
    WeakToken { got: usize, min: usize },
    #[error("seal secret: {0}")]
    Seal(String),
}

/// Why an [`open_secret`] call failed — kept distinct (not collapsed to one error)
/// because these map to genuinely different SERVER-SIDE incidents that an operator
/// needs to tell apart in a log line, even though every one of them must collapse to
/// the SAME opaque "authentication failed" at the boundary — never let the caller
/// distinguish which case occurred.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenSecretError {
    /// No recognized `decern-sealed-v1:` prefix — most likely a secret stored before
    /// encryption-at-rest existed (a legacy pre-encryption plaintext secret), or
    /// unrecognized/corrupted data. Either way: not decryptable by this code path.
    #[error(
        "value has no recognized sealed-secret envelope (likely a pre-encryption legacy secret)"
    )]
    NotSealed,
    /// The envelope's key-id does not match the loaded key's id — almost certainly
    /// sealed under a DIFFERENT key than the one this process loaded (wrong key
    /// file, or the key was rotated without a documented re-seal).
    #[error("sealed under a different key (key-id mismatch)")]
    KeyIdMismatch,
    /// The envelope parsed and the key-id matched, but AEAD authentication failed —
    /// corruption, or (extremely unlikely) two distinct keys sharing a key-id.
    #[error("AEAD authentication failed")]
    AuthenticationFailed,
    /// The envelope itself could not be parsed (bad base64, wrong length, etc.).
    #[error("malformed sealed-secret envelope: {0}")]
    Malformed(String),
}

pub fn generate() -> Result<SigningKey, KeyError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| KeyError::Entropy(e.to_string()))?;
    let key = SigningKey::from_bytes(&seed);
    // The seed is now inside `key`; wipe our transient copy so it does not linger.
    seed.zeroize();
    Ok(key)
}

/// Write a private key to a file that is 0600 FROM CREATION (no chmod-after-
/// write window in which the seed sits world-readable) and never silently
/// overwrites an existing key. Refuses on platforms without permission
/// control rather than writing an unprotected secret.
pub fn save_signing_key(key: &SigningKey, path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| KeyError::Write {
                path: path.display().to_string(),
                err: format!("{e} (refusing to overwrite an existing key file)"),
            })?;
        file.write_all(hex::encode(key.to_bytes()).as_bytes())
            .map_err(|e| KeyError::Write {
                path: path.display().to_string(),
                err: e.to_string(),
            })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = key;
        Err(KeyError::Write {
            path: path.display().to_string(),
            err: "refusing to write a private key without file-permission control on this platform"
                .into(),
        })
    }
}

pub fn load_signing_key(path: &Path) -> Result<SigningKey, KeyError> {
    // Symmetric with the write side: refuse to load a private key that is readable by
    // group or other. The write path guarantees 0600 from creation, but a key placed
    // by another tool (or a later chmod) could sit world-readable — loading it silently
    // would let a leaked secret keep signing. Fail-closed on the permission bits.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| KeyError::Read {
            path: path.display().to_string(),
            err: e.to_string(),
        })?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::Read {
                path: path.display().to_string(),
                err: format!(
                    "insecure permissions {:o}: a private key must not be readable by group/other (chmod 600)",
                    mode & 0o777
                ),
            });
        }
    }
    let mut raw = fs::read_to_string(path).map_err(|e| KeyError::Read {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    let mut bytes = match hex::decode(raw.trim()) {
        Ok(b) => b,
        Err(_) => {
            raw.zeroize();
            return Err(KeyError::Malformed(path.display().to_string()));
        }
    };
    raw.zeroize();
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(KeyError::Malformed(path.display().to_string()));
    }
    // Copy into a fixed array, then wipe the heap Vec: `try_into()` would move the
    // Vec and free its buffer without clearing the seed bytes it held.
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

pub fn save_verifying_key(key: &VerifyingKey, path: &Path) -> Result<(), KeyError> {
    fs::write(path, hex::encode(key.to_bytes())).map_err(|e| KeyError::Write {
        path: path.display().to_string(),
        err: e.to_string(),
    })
}

pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, KeyError> {
    let raw = fs::read_to_string(path).map_err(|e| KeyError::Read {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    parse_verifying_key(raw.trim()).ok_or_else(|| KeyError::Malformed(path.display().to_string()))
}

pub fn parse_verifying_key(hex_str: &str) -> Option<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Stable revocation identifier for a bearer token: the lowercase hex SHA-256 of
/// the exact token string a client presents. Keys a revocation store without
/// persisting the raw bearer secret, and without requiring the token to carry a
/// `jti` — any presented credential hashes to the same id.
pub fn token_id(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Hex-encoded SHA-256 of arbitrary bytes — the general-purpose primitive
/// `token_id` (above) specializes for a bearer token string. Used wherever a
/// plain content digest is needed without a dedicated purpose-built hash
/// (e.g. a content digest of a loaded model).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// A fresh high-entropy opaque secret: lowercase hex of `n` random bytes from the
/// OS CSPRNG. Used to mint client secrets and registration access tokens (RFC
/// 7591 / 7592), which "MUST contain sufficient entropy to prevent a random
/// guessing attack" — 32 bytes is 256 bits. Refuses `n` below [`MIN_TOKEN_BYTES`]
/// (128 bits) rather than mint a guessable secret. The random buffer is wiped
/// after encoding; only the [`token_id`] digest of the result is ever persisted,
/// and the plaintext is shown to the caller once and dropped.
pub fn random_token(n: usize) -> Result<String, KeyError> {
    if n < MIN_TOKEN_BYTES {
        return Err(KeyError::WeakToken {
            got: n,
            min: MIN_TOKEN_BYTES,
        });
    }
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| KeyError::Entropy(e.to_string()))?;
    let out = hex::encode(&buf);
    buf.zeroize();
    Ok(out)
}

// ============================ symmetric key (secret-at-rest sealing) ============================
//
// A SEPARATE key type from the Ed25519 `SigningKey` above, deliberately — reusing
// asymmetric seed bytes as a symmetric AEAD key (or the reverse) is a key-separation
// violation. The file FORMAT is deliberately made incompatible too: a bare-hex
// Ed25519 seed file has no label, so `load_symmetric_key` refusing anything without
// the `decern-symmetric-key-v1:` prefix means an operator who supplies a bare Ed25519
// signing-key file where a symmetric key is expected (or vice versa) gets a clear
// parse error, never a key silently misused as the wrong type.

const SYMMETRIC_KEY_LABEL: &str = "decern-symmetric-key-v1";
/// AEAD nonce size for [`XChaCha20Poly1305`] (24 bytes / 192 bits) — chosen over
/// plain ChaCha20Poly1305's 12-byte nonce specifically so nonces can be generated
/// FRESH AND RANDOM per seal (never a counter or a value derived from the record's
/// own key, e.g. `(domain, subject)` — the same secret may be re-sealed repeatedly
/// (e.g. on rotation), so a derived nonce would repeat across those seals, which is
/// a genuine keystream-reuse break for a ChaCha-family cipher, not a theoretical
/// one). At 96-bit nonces the birthday-bound collision risk from random generation
/// alone is already negligible at any plausible scale for this use (rare secret
/// enrollments/rotations, not a high-volume message stream) — the 24-byte nonce's
/// real value here is removing that scale argument from the audit entirely, at
/// zero cost, rather than a claim that 96 bits would be unsafe.
const XNONCE_LEN: usize = 24;

/// A 32-byte symmetric key for sealing secrets at rest. Zeroized on drop.
pub struct SymmetricKey([u8; 32]);

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Redacted on purpose — a real `#[derive(Debug)]` would print the raw key bytes,
/// which must never appear in a log line, panic message, or test failure output.
impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey(REDACTED)")
    }
}

/// Short (4-byte / 8 hex char) fingerprint of a key, for SERVER-SIDE diagnostic
/// logging only ("sealed under key ab12cd34, loaded key is ef56..." instead of a
/// mute AEAD failure) — embedded in every sealed envelope so a wrong-key mismatch
/// is a clear, correctly-attributed log line rather than an indistinguishable
/// authentication failure. Not a secret itself (a truncated hash of a 256-bit key
/// reveals nothing about the key), and NEVER appears in any HTTP response.
fn key_id(key: &SymmetricKey) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(key.0)[..4])
}

pub fn generate_symmetric_key() -> Result<SymmetricKey, KeyError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| KeyError::Entropy(e.to_string()))?;
    let key = SymmetricKey(bytes);
    // Wipe our transient copy so it does not linger (same discipline as `generate()`
    // and `load_symmetric_key()` — `SymmetricKey`'s own Drop only covers ITS storage,
    // not this local, and `[u8;32]` being Copy gives no language guarantee the
    // compiler elides the copy into `SymmetricKey(bytes)` above).
    bytes.zeroize();
    Ok(key)
}

/// Reconstruct a [`SymmetricKey`] from raw bytes a caller already holds (e.g. a
/// store that persists a per-subject data-encryption-key, itself sealed at rest
/// under a master key). Same zeroize discipline as [`load_symmetric_key`]: the
/// caller's copy is wiped after the
/// owned `SymmetricKey` is built, so only one live copy of the key material
/// exists past this call. Prefer [`generate_symmetric_key`]/[`load_symmetric_key`]
/// when minting or loading from a file; this exists for callers reconstructing a
/// key from bytes obtained some other way (already-sealed storage, a KMS unwrap).
pub fn symmetric_key_from_bytes(mut bytes: [u8; 32]) -> SymmetricKey {
    let key = SymmetricKey(bytes);
    bytes.zeroize();
    key
}

/// Same file discipline as [`save_signing_key`]: 0600 FROM CREATION, never silently
/// overwrites. Content is `decern-symmetric-key-v1:<hex>` — the label is what makes
/// [`load_symmetric_key`] refuse a bare-hex Ed25519 seed file (see the module note
/// above).
pub fn save_symmetric_key(key: &SymmetricKey, path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| KeyError::Write {
                path: path.display().to_string(),
                err: format!("{e} (refusing to overwrite an existing key file)"),
            })?;
        file.write_all(format!("{SYMMETRIC_KEY_LABEL}:{}", hex::encode(key.0)).as_bytes())
            .map_err(|e| KeyError::Write {
                path: path.display().to_string(),
                err: e.to_string(),
            })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = key;
        Err(KeyError::Write {
            path: path.display().to_string(),
            err: "refusing to write a private key without file-permission control on this platform"
                .into(),
        })
    }
}

/// Same permission-check discipline as [`load_signing_key`] (refuses group/other-
/// readable), PLUS refuses a file that isn't labeled `decern-symmetric-key-v1:` — most
/// importantly, this means an Ed25519 signing-key file (bare hex, no label) is
/// refused here rather than silently reinterpreted as 32 arbitrary key bytes.
pub fn load_symmetric_key(path: &Path) -> Result<SymmetricKey, KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| KeyError::Read {
            path: path.display().to_string(),
            err: e.to_string(),
        })?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::Read {
                path: path.display().to_string(),
                err: format!(
                    "insecure permissions {:o}: a private key must not be readable by group/other (chmod 600)",
                    mode & 0o777
                ),
            });
        }
    }
    let mut raw = fs::read_to_string(path).map_err(|e| KeyError::Read {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    let Some(hex_part) = raw.strip_prefix(&format!("{SYMMETRIC_KEY_LABEL}:")) else {
        raw.zeroize();
        return Err(KeyError::Malformed(format!(
            "{} (missing {SYMMETRIC_KEY_LABEL}: label — not a symmetric key file, e.g. an \
             Ed25519 signing key was given here by mistake)",
            path.display()
        )));
    };
    let mut bytes = match hex::decode(hex_part.trim()) {
        Ok(b) => b,
        Err(_) => {
            raw.zeroize();
            return Err(KeyError::Malformed(path.display().to_string()));
        }
    };
    raw.zeroize();
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(KeyError::Malformed(path.display().to_string()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    let key = SymmetricKey(seed);
    seed.zeroize();
    Ok(key)
}

/// Seal `plaintext` (e.g. a base32 secret) under `key`, bound to `aad`
/// (Additional Authenticated Data — the caller MUST pass the exact same `aad` to
/// [`open_secret`], typically the record's own collision-free composite key, so a
/// ciphertext transplanted between two different records fails to authenticate
/// instead of silently decrypting). Returns
/// `decern-sealed-v1:<key-id>:<base64(nonce || ciphertext || tag)>` — the version
/// label and key-id make a future scheme change or key rotation detectable rather
/// than a mute failure, and distinguish a legacy pre-encryption plaintext value
/// (which has neither) on read.
pub fn seal_secret(key: &SymmetricKey, aad: &[u8], plaintext: &[u8]) -> Result<String, KeyError> {
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    let mut nonce_bytes = [0u8; XNONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|e| KeyError::Entropy(e.to_string()))?;
    let nonce: &XNonce = (&nonce_bytes).into();
    let key_arr: &Key = (&key.0).into();
    let cipher = XChaCha20Poly1305::new(key_arr);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| KeyError::Seal(e.to_string()))?;

    let mut blob = Vec::with_capacity(XNONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    nonce_bytes.zeroize();
    Ok(format!(
        "{SEALED_LABEL}:{}:{}",
        key_id(key),
        base64::engine::general_purpose::STANDARD.encode(blob)
    ))
}

const SEALED_LABEL: &str = "decern-sealed-v1";

/// Open a value produced by [`seal_secret`]. `aad` MUST match exactly what was
/// passed to `seal_secret`, or authentication fails (see its doc). Every failure
/// mode is a distinct [`OpenSecretError`] variant for SERVER-SIDE diagnostics —
/// callers must map ALL of them to the SAME opaque external outcome (never let a
/// caller distinguish "legacy plaintext" from "wrong key" from "corrupted").
/// Generous upper bound on a sealed envelope's total encoded length — sized well
/// above any legitimate payload so a malformed or attacker-influenced oversized
/// value is REJECTED before it pays for a base64 allocation/decode, not because any
/// legitimate envelope is expected to approach it.
const MAX_SEALED_LEN: usize = 65536;

pub fn open_secret(
    key: &SymmetricKey,
    aad: &[u8],
    sealed: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, OpenSecretError> {
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    if sealed.len() > MAX_SEALED_LEN {
        return Err(OpenSecretError::Malformed(
            "envelope exceeds max length".into(),
        ));
    }
    let rest = sealed
        .strip_prefix(&format!("{SEALED_LABEL}:"))
        .ok_or(OpenSecretError::NotSealed)?;
    let (kid, b64) = rest
        .split_once(':')
        .ok_or_else(|| OpenSecretError::Malformed("missing key-id separator".into()))?;
    if kid != key_id(key) {
        return Err(OpenSecretError::KeyIdMismatch);
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| OpenSecretError::Malformed(e.to_string()))?;
    if blob.len() < XNONCE_LEN {
        return Err(OpenSecretError::Malformed(
            "envelope shorter than one nonce".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(XNONCE_LEN);
    // Infallible in practice (the length check above guarantees exactly XNONCE_LEN
    // bytes), but mapped to an error rather than unwrapped/expected — attacker-
    // controlled input must never be able to panic this path.
    let nonce: &XNonce = nonce_bytes
        .try_into()
        .map_err(|_| OpenSecretError::Malformed("bad nonce length".into()))?;
    let key_arr: &Key = (&key.0).into();
    let cipher = XChaCha20Poly1305::new(key_arr);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| OpenSecretError::AuthenticationFailed)?;
    Ok(zeroize::Zeroizing::new(plaintext))
}

/// Seal `subject_key`'s raw bytes under `master`, bound to `aad` — for wrapping a
/// per-subject data-encryption-key at rest under a master key, the same way
/// [`seal_secret`] wraps a secret. Never exposes `subject_key`'s raw bytes to the
/// caller: this function reads the
/// private field directly (same crate) and hands only the sealed envelope back.
pub fn seal_symmetric_key(
    master: &SymmetricKey,
    aad: &[u8],
    subject_key: &SymmetricKey,
) -> Result<String, KeyError> {
    seal_secret(master, aad, &subject_key.0)
}

/// The inverse of [`seal_symmetric_key`]: opens `sealed` under `master` and
/// reconstructs the [`SymmetricKey`] it wraps. Same fail-closed discipline as
/// [`open_secret`] — every failure (wrong key, tampered ciphertext, malformed
/// envelope, wrong length) is a distinct [`OpenSecretError`], never a panic or a
/// silent partial key.
pub fn open_symmetric_key(
    master: &SymmetricKey,
    aad: &[u8],
    sealed: &str,
) -> Result<SymmetricKey, OpenSecretError> {
    let mut bytes = open_secret(master, aad, sealed)?;
    if bytes.len() != 32 {
        return Err(OpenSecretError::Malformed(format!(
            "sealed symmetric key is {} bytes, expected 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    let key = SymmetricKey(seed);
    seed.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let key = generate().unwrap();
        let msg = b"message";
        let sig = key.sign(msg);
        assert!(key.verifying_key().verify(msg, &sig).is_ok());
        assert!(key.verifying_key().verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn key_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("decern-crypto-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.key");
        let key = generate().unwrap();
        save_signing_key(&key, &path).unwrap();
        let loaded = load_signing_key(&path).unwrap();
        assert_eq!(key.to_bytes(), loaded.to_bytes());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("decern-crypto-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("leak.key");
        let key = generate().unwrap();
        save_signing_key(&key, &path).unwrap();
        // Loosen the perms as a stray chmod / foreign tool might.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_signing_key(&path).unwrap_err();
        assert!(
            matches!(err, KeyError::Read { .. }),
            "world-readable key must be refused: {err}"
        );
        // 0600 loads fine.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_signing_key(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn random_token_enforces_the_entropy_floor() {
        // Below the floor is refused rather than minted weak.
        for n in [0, 1, 8, MIN_TOKEN_BYTES - 1] {
            let err = random_token(n).unwrap_err();
            assert!(
                matches!(err, KeyError::WeakToken { got, min } if got == n && min == MIN_TOKEN_BYTES),
                "n={n} must be refused: {err}"
            );
        }
        // At/above the floor mints hex of the requested byte length.
        let at = random_token(MIN_TOKEN_BYTES).unwrap();
        assert_eq!(at.len(), MIN_TOKEN_BYTES * 2, "hex is 2 chars/byte");
        let big = random_token(32).unwrap();
        assert_eq!(big.len(), 64);
        assert_ne!(big, random_token(32).unwrap(), "each token is fresh");
    }

    #[test]
    fn zeroizing_transients_does_not_corrupt_the_key() {
        // The seed-wipe in generate()/load must not disturb the key that already
        // owns its copy: sign/verify and a file roundtrip still succeed.
        let key = generate().unwrap();
        let msg = b"seed wiped, key intact";
        assert!(key.verifying_key().verify(msg, &key.sign(msg)).is_ok());
        let dir = std::env::temp_dir().join(format!("decern-crypto-zt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("z.key");
        std::fs::remove_file(&path).ok();
        save_signing_key(&key, &path).unwrap();
        let loaded = load_signing_key(&path).unwrap();
        assert_eq!(key.to_bytes(), loaded.to_bytes());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_id_is_stable_and_distinct() {
        let a = token_id("eyJ.header.aaa.bbb");
        assert_eq!(a, token_id("eyJ.header.aaa.bbb"), "same token → same id");
        assert_ne!(
            a,
            token_id("eyJ.header.aaa.bbc"),
            "different token → different id"
        );
        assert_eq!(a.len(), 64, "sha-256 hex is 64 chars");
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = generate_symmetric_key().unwrap();
        let sealed = seal_secret(&key, b"acme:alice", b"JBSWY3DPEHPK3PXP").unwrap();
        assert!(
            sealed.starts_with("decern-sealed-v1:"),
            "version-labeled: {sealed}"
        );
        let opened = open_secret(&key, b"acme:alice", &sealed).unwrap();
        assert_eq!(&*opened, b"JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn seal_is_randomized_each_call() {
        // Two seals of the SAME plaintext under the SAME key must differ (fresh
        // random nonce each time) — a fixed/derived nonce would make identical
        // plaintexts produce identical ciphertexts, leaking equality.
        let key = generate_symmetric_key().unwrap();
        let a = seal_secret(&key, b"acme:alice", b"secret").unwrap();
        let b = seal_secret(&key, b"acme:alice", b"secret").unwrap();
        assert_ne!(
            a, b,
            "same plaintext, same key, same AAD — must still differ"
        );
    }

    #[test]
    fn open_rejects_wrong_key() {
        let key_a = generate_symmetric_key().unwrap();
        let key_b = generate_symmetric_key().unwrap();
        let sealed = seal_secret(&key_a, b"acme:alice", b"JBSWY3DPEHPK3PXP").unwrap();
        let err = open_secret(&key_b, b"acme:alice", &sealed).unwrap_err();
        assert!(
            matches!(err, OpenSecretError::KeyIdMismatch),
            "a different key must be caught by key-id, before ever touching AEAD: {err}"
        );
    }

    #[test]
    fn open_rejects_wrong_aad() {
        // A ciphertext transplanted to a DIFFERENT record (different AAD) must fail
        // to authenticate — proves the AAD binding is real, not decorative.
        let key = generate_symmetric_key().unwrap();
        let sealed = seal_secret(&key, b"acme:alice", b"JBSWY3DPEHPK3PXP").unwrap();
        let err = open_secret(&key, b"acme:bob", &sealed).unwrap_err();
        assert!(
            matches!(err, OpenSecretError::AuthenticationFailed),
            "{err}"
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = generate_symmetric_key().unwrap();
        let mut sealed = seal_secret(&key, b"acme:alice", b"JBSWY3DPEHPK3PXP").unwrap();
        // Flip the last base64 character (part of the AEAD tag).
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        sealed = chars.into_iter().collect();
        let err = open_secret(&key, b"acme:alice", &sealed).unwrap_err();
        assert!(
            matches!(
                err,
                OpenSecretError::AuthenticationFailed | OpenSecretError::Malformed(_)
            ),
            "{err}"
        );
    }

    #[test]
    fn open_rejects_legacy_unlabeled_plaintext() {
        // A pre-encryption secret (a bare base32 string, no "decern-sealed-v1:" prefix)
        // must be recognized as NOT SEALED — never silently "decrypted" as garbage,
        // and never confused with a genuine key/AAD mismatch.
        let key = generate_symmetric_key().unwrap();
        let err = open_secret(&key, b"acme:alice", "JBSWY3DPEHPK3PXP").unwrap_err();
        assert!(matches!(err, OpenSecretError::NotSealed), "{err}");
    }

    #[test]
    fn seal_symmetric_key_roundtrip() {
        let master = generate_symmetric_key().unwrap();
        let subject_key = generate_symmetric_key().unwrap();
        let sealed = seal_symmetric_key(&master, b"acme:pseudo-1", &subject_key).unwrap();
        assert!(sealed.starts_with("decern-sealed-v1:"));

        let opened = open_symmetric_key(&master, b"acme:pseudo-1", &sealed).unwrap();
        // Prove it's the SAME key material via seal/open under it, not by comparing
        // raw bytes (SymmetricKey exposes none, by design).
        let payload = seal_secret(&subject_key, b"probe", b"payload").unwrap();
        assert_eq!(
            &*open_secret(&opened, b"probe", &payload).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn open_symmetric_key_rejects_wrong_master_or_aad() {
        let master_a = generate_symmetric_key().unwrap();
        let master_b = generate_symmetric_key().unwrap();
        let subject_key = generate_symmetric_key().unwrap();
        let sealed = seal_symmetric_key(&master_a, b"acme:pseudo-1", &subject_key).unwrap();

        let err = open_symmetric_key(&master_b, b"acme:pseudo-1", &sealed).unwrap_err();
        assert!(matches!(err, OpenSecretError::KeyIdMismatch), "{err}");

        let err = open_symmetric_key(&master_a, b"acme:pseudo-2", &sealed).unwrap_err();
        assert!(
            matches!(err, OpenSecretError::AuthenticationFailed),
            "{err}"
        );
    }

    #[test]
    fn symmetric_key_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("decern-crypto-sym-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cred.key");
        std::fs::remove_file(&path).ok();
        let key = generate_symmetric_key().unwrap();
        save_symmetric_key(&key, &path).unwrap();
        let loaded = load_symmetric_key(&path).unwrap();
        // Roundtrip via seal/open rather than comparing raw bytes (SymmetricKey
        // exposes none): what was sealed under the original loads and opens under
        // the reloaded key.
        let sealed = seal_secret(&key, b"aad", b"payload").unwrap();
        assert_eq!(&*open_secret(&loaded, b"aad", &sealed).unwrap(), b"payload");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_symmetric_key_refuses_an_ed25519_signing_key_file() {
        // Cross-type confusion guard: a bare-hex Ed25519 seed file has no
        // "decern-symmetric-key-v1:" label, so it must be refused here, not silently
        // reinterpreted as 32 arbitrary AEAD key bytes.
        let dir =
            std::env::temp_dir().join(format!("decern-crypto-xtype-a-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("issuer.key");
        std::fs::remove_file(&path).ok();
        save_signing_key(&generate().unwrap(), &path).unwrap();
        let err = load_symmetric_key(&path).unwrap_err();
        assert!(matches!(err, KeyError::Malformed(_)), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_signing_key_refuses_a_symmetric_key_file() {
        // The reverse direction: a labeled symmetric key file must not parse as an
        // Ed25519 seed either (the label prefix breaks hex decoding, which is
        // exactly the point — it's a hard parse failure, not a coincidence).
        let dir =
            std::env::temp_dir().join(format!("decern-crypto-xtype-b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cred.key");
        std::fs::remove_file(&path).ok();
        save_symmetric_key(&generate_symmetric_key().unwrap(), &path).unwrap();
        let err = load_signing_key(&path).unwrap_err();
        assert!(matches!(err, KeyError::Malformed(_)), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_symmetric_key_refuses_a_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("decern-crypto-sym-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("leak.key");
        std::fs::remove_file(&path).ok();
        let key = generate_symmetric_key().unwrap();
        save_symmetric_key(&key, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_symmetric_key(&path).unwrap_err();
        assert!(matches!(err, KeyError::Read { .. }), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_symmetric_key(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}

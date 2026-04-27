/*
    WSNTP (What's Signed On The Picture?) is a picture signing tool running in the cmd lines.
    Copyright (C) 2026  LLLichlet

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

//! Local key store in `~/.wsntp/`.
//!
//! Keys are stored as base64-encoded 32-byte seeds under
//! `~/.wsntp/keys/<alias>.pub` and `~/.wsntp/keys/<alias>.secret`.
//! A default key alias can be configured in `~/.wsntp/config.toml`.
//!
//! Secret key files are created atomically (write to temp file, rename)
//! and locked down to `0o600` on Unix.

use crate::crypto::Keypair;
use crate::error::WsntpError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const FORBIDDEN_CHARS: &[char] = &['/', '\\', '.', ' '];

/// Manages keys under `~/.wsntp/keys/` and a default alias in
/// `~/.wsntp/config.toml`.
pub(crate) struct KeyStore {
    keys_dir: PathBuf,
    config_path: PathBuf,
}

/// Write `contents` to `path`, failing if the file already exists.
fn write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(contents)
}

impl KeyStore {
    /// Open (or create) the key store at `~/.wsntp/`.
    pub fn new() -> Result<Self, WsntpError> {
        let base_dir = dirs::home_dir()
            .ok_or_else(|| WsntpError::cli("could not determine home directory"))?
            .join(".wsntp");
        let keys_dir = base_dir.join("keys");
        let config_path = base_dir.join("config.toml");
        fs::create_dir_all(&keys_dir)?;
        Ok(Self {
            keys_dir,
            config_path,
        })
    }

    /// Persist a key pair under `alias`.
    ///
    /// The alias must not contain `/`, `\`, `.`, or spaces, and must not
    /// already exist in the store.
    pub fn save(&self, alias: &str, keypair: &Keypair) -> Result<(), WsntpError> {
        if alias.is_empty() || alias.contains(FORBIDDEN_CHARS) {
            return Err(WsntpError::cli(format!(
                "invalid key alias: '{alias}' (must not contain {FORBIDDEN_CHARS:?})"
            )));
        }

        let pub_path = self.keys_dir.join(format!("{alias}.pub"));
        let sec_path = self.keys_dir.join(format!("{alias}.secret"));

        if pub_path.exists() || sec_path.exists() {
            return Err(WsntpError::cli(format!("key alias '{alias}' already exists")));
        }

        let pub_tmp = self.keys_dir.join(format!(".{alias}.pub.tmp"));
        let sec_tmp = self.keys_dir.join(format!(".{alias}.secret.tmp"));

        let pub_data = [BASE64.encode(keypair.public).as_bytes(), b"\n"].concat();
        let sec_data = [BASE64.encode(keypair.secret).as_bytes(), b"\n"].concat();

        // Write to temp files, then rename — prevents partial writes if
        // the process crashes mid-write. TOCTOU between exists() and here
        // is acceptable for a single-user CLI tool.
        if let Err(e) = write_new(&pub_tmp, &pub_data) {
            let _ = fs::remove_file(&pub_tmp);
            let _ = fs::remove_file(&sec_tmp);
            return Err(WsntpError::Io(e));
        }
        if let Err(e) = write_new(&sec_tmp, &sec_data) {
            let _ = fs::remove_file(&pub_tmp);
            let _ = fs::remove_file(&sec_tmp);
            return Err(WsntpError::Io(e));
        }

        fs::rename(&pub_tmp, &pub_path)?;
        if let Err(e) = fs::rename(&sec_tmp, &sec_path) {
            let _ = fs::rename(&pub_path, &pub_tmp);
            let _ = fs::remove_file(&pub_tmp);
            let _ = fs::remove_file(&sec_tmp);
            return Err(WsntpError::Io(e));
        }

        // Restrict secret file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sec_path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load a public key by alias.
    pub fn load_public(&self, alias: &str) -> Result<[u8; 32], WsntpError> {
        let path = self.keys_dir.join(format!("{alias}.pub"));
        let b64 = fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                WsntpError::KeyNotFound(format!("public key '{alias}' not found"))
            }
            _ => WsntpError::Io(e),
        })?;
        let bytes = BASE64
            .decode(b64.trim())
            .map_err(|_| WsntpError::cli(format!("corrupt public key file for '{alias}'")))?;
        bytes
            .try_into()
            .map_err(|_| WsntpError::cli(format!("public key for '{alias}' has wrong length")))
    }

    /// Load a secret key by alias.
    pub fn load_secret(&self, alias: &str) -> Result<[u8; 32], WsntpError> {
        let path = self.keys_dir.join(format!("{alias}.secret"));
        let b64 = fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                WsntpError::KeyNotFound(format!("secret key '{alias}' not found"))
            }
            _ => WsntpError::Io(e),
        })?;
        let bytes = BASE64
            .decode(b64.trim())
            .map_err(|_| WsntpError::cli(format!("corrupt secret key file for '{alias}'")))?;
        bytes
            .try_into()
            .map_err(|_| WsntpError::cli(format!("secret key for '{alias}' has wrong length")))
    }

    /// List all key aliases in the store (sorted).
    pub fn list(&self) -> Result<Vec<String>, WsntpError> {
        let mut aliases = Vec::new();
        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(alias) = name_str.strip_suffix(".pub") {
                aliases.push(alias.to_string());
            }
        }
        aliases.sort();
        Ok(aliases)
    }

    /// Read the default key alias from `config.toml`, if present.
    pub fn default_alias(&self) -> Result<Option<String>, WsntpError> {
        let content = match fs::read_to_string(&self.config_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(WsntpError::Io(e)),
        };
        let config: toml::Value = content.parse().map_err(|e| {
            WsntpError::cli(format!("malformed config.toml: {e}"))
        })?;
        Ok(config
            .get("default_key")
            .and_then(|v| v.as_str())
            .map(String::from))
    }

    /// Persist a new default key alias to `config.toml`.
    pub fn set_default_alias(&self, alias: &str) -> Result<(), WsntpError> {
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &self.config_path,
            format!("default_key = \"{alias}\"\n"),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn temp_keystore() -> (KeyStore, TestDir) {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "wsntp-test-{}-{id}",
            std::process::id(),
        ));
        let keys_dir = tmp.join("keys");
        let config_path = tmp.join("config.toml");
        fs::create_dir_all(&keys_dir).unwrap();
        (
            KeyStore {
                keys_dir,
                config_path,
            },
            TestDir { path: tmp },
        )
    }

    #[test]
    fn save_and_load_roundtrip() {
        let (store, _cleanup) = temp_keystore();
        let keypair = crypto::generate_keypair();
        store.save("test-key", &keypair).unwrap();

        let loaded_pub = store.load_public("test-key").unwrap();
        let loaded_sec = store.load_secret("test-key").unwrap();

        assert_eq!(keypair.public, loaded_pub);
        assert_eq!(keypair.secret, loaded_sec);
    }

    #[test]
    fn list_keys() {
        let (store, _cleanup) = temp_keystore();
        store
            .save("alice", &crypto::generate_keypair())
            .unwrap();
        store
            .save("bob", &crypto::generate_keypair())
            .unwrap();

        let aliases = store.list().unwrap();
        assert!(aliases.contains(&"alice".to_string()));
        assert!(aliases.contains(&"bob".to_string()));
    }

    #[test]
    fn list_empty_keystore() {
        let (store, _cleanup) = temp_keystore();
        let aliases = store.list().unwrap();
        assert!(aliases.is_empty());
    }

    #[test]
    fn load_nonexistent_fails() {
        let (store, _cleanup) = temp_keystore();
        let err = store.load_public("nobody").unwrap_err();
        assert!(matches!(err, WsntpError::KeyNotFound(_)));
        let err = store.load_secret("nobody").unwrap_err();
        assert!(matches!(err, WsntpError::KeyNotFound(_)));
    }

    #[test]
    fn duplicate_alias_rejected() {
        let (store, _cleanup) = temp_keystore();
        let keypair = crypto::generate_keypair();
        store.save("dup", &keypair).unwrap();
        assert!(store.save("dup", &keypair).is_err());
    }

    #[test]
    fn invalid_alias_rejected() {
        let (store, _cleanup) = temp_keystore();
        let keypair = crypto::generate_keypair();
        assert!(store.save("bad/name", &keypair).is_err());
        assert!(store.save("bad name", &keypair).is_err());
        assert!(store.save("bad.name", &keypair).is_err());
        assert!(store.save("", &keypair).is_err());
    }

    #[test]
    fn default_alias_roundtrip() {
        let (store, _cleanup) = temp_keystore();
        assert!(store.default_alias().unwrap().is_none());
        store.set_default_alias("primary").unwrap();
        assert_eq!(store.default_alias().unwrap().unwrap(), "primary");
    }

    #[test]
    fn corrupt_public_key_file() {
        let (store, _cleanup) = temp_keystore();
        let path = store.keys_dir.join("bad.pub");
        fs::write(&path, "not valid base64!!!\n").unwrap();
        assert!(store.load_public("bad").is_err());
    }

    #[test]
    fn wrong_length_key_file() {
        let (store, _cleanup) = temp_keystore();
        let path = store.keys_dir.join("short.pub");
        fs::write(&path, "AAAA\n").unwrap();
        assert!(store.load_public("short").is_err());
    }
}

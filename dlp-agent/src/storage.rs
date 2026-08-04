//! Protected on-disk state. The agent's private key never touches disk in the
//! clear: on Windows it is sealed with DPAPI (machine scope), so the blob is
//! decryptable only on this machine. Mirrors the production requirement that a
//! stolen agent identity cannot be replayed from another PC.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const IDENTITY_FILE: &str = "identity.sealed"; // DPAPI-sealed (key PEM + cert PEM)
const CA_FILE: &str = "ca.pem"; // trust anchor confirmed at enrollment
const META_FILE: &str = "agent.json";
const POLICY_FILE: &str = "cached-policy.json";
const INDEX_FILE: &str = "index.dlpx"; // latest VERIFIED detection index bundle

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentMeta {
    pub agent_id: String,
    pub checkin_interval_seconds: u64,
}

pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: PathBuf) -> Self {
        Storage { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn has_identity(&self) -> bool {
        self.path(IDENTITY_FILE).exists()
    }

    /// Persist the enrolled identity. `identity_pem` = private key PEM followed
    /// by the certificate PEM (the bundle reqwest loads for mTLS).
    pub fn save_identity(&self, identity_pem: &str, ca_pem: &str, meta: &AgentMeta) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating state dir {}", self.dir.display()))?;
        let sealed = seal(identity_pem.as_bytes()).context("sealing identity")?;
        write_private(&self.path(IDENTITY_FILE), &sealed)?;
        std::fs::write(self.path(CA_FILE), ca_pem).context("writing CA")?;
        std::fs::write(self.path(META_FILE), serde_json::to_vec_pretty(meta)?)
            .context("writing meta")?;
        Ok(())
    }

    /// Load the identity bundle (key+cert PEM) and the pinned CA PEM.
    pub fn load_identity(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.has_identity() {
            bail!("not enrolled — no stored identity");
        }
        let sealed = std::fs::read(self.path(IDENTITY_FILE)).context("reading identity")?;
        let identity_pem = unseal(&sealed).context("unsealing identity")?;
        let ca_pem = std::fs::read(self.path(CA_FILE)).context("reading CA")?;
        Ok((identity_pem, ca_pem))
    }

    pub fn load_meta(&self) -> Result<AgentMeta> {
        let bytes = std::fs::read(self.path(META_FILE)).context("reading meta")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Cache the latest policy bundle for fail-secure enforcement while the
    /// server is unreachable. (Phase 2: bundle is null; this is the hook.)
    pub fn cache_policy(&self, policy_json: &str) -> Result<()> {
        std::fs::write(self.path(POLICY_FILE), policy_json).context("caching policy")?;
        Ok(())
    }

    /// Raw bytes of the cached detection index bundle, or None if the agent
    /// has never downloaded one. Callers MUST verify the signature before
    /// trusting the content (the file could have been tampered at rest).
    pub fn load_index_bundle(&self) -> Option<Vec<u8>> {
        std::fs::read(self.path(INDEX_FILE)).ok()
    }

    /// Replace the cached index bundle. Callers must have VERIFIED the bytes
    /// first — this writes to a temp file and swaps, so the previous verified
    /// bundle survives a crash mid-write (fail secure).
    pub fn store_index_bundle(&self, bytes: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating state dir {}", self.dir.display()))?;
        let tmp = self.path("index.dlpx.tmp");
        let dest = self.path(INDEX_FILE);
        std::fs::write(&tmp, bytes).context("writing index bundle (temp)")?;
        // Windows rename does not overwrite; the destination is removed only
        // AFTER the new verified bytes are fully on disk.
        if dest.exists() {
            std::fs::remove_file(&dest).context("removing previous index bundle")?;
        }
        std::fs::rename(&tmp, &dest).context("swapping index bundle into place")?;
        Ok(())
    }
}

/// Write with owner-only permissions where the platform supports it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// DPAPI sealing (Windows). Elsewhere, store as-is (dev/test only).
// ---------------------------------------------------------------------
#[cfg(windows)]
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    dpapi::protect(plain)
}
#[cfg(windows)]
fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    dpapi::unprotect(sealed)
}
#[cfg(not(windows))]
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    // Dev/test platforms have no DPAPI; the real target is Windows.
    Ok(plain.to_vec())
}
#[cfg(not(windows))]
fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    Ok(sealed.to_vec())
}

#[cfg(windows)]
mod dpapi {
    use anyhow::{bail, Result};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    fn take_and_free(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe {
            let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        }
        v
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let mut input = blob(plain);
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok.is_err() {
            bail!("CryptProtectData failed: {ok:?}");
        }
        Ok(take_and_free(output))
    }

    pub fn unprotect(sealed: &[u8]) -> Result<Vec<u8>> {
        let mut input = blob(sealed);
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok.is_err() {
            bail!("CryptUnprotectData failed: {ok:?}");
        }
        Ok(take_and_free(output))
    }
}

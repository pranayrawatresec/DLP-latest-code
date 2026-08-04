//! Local key-pair and CSR generation. The private key is created ON THE PC and
//! never leaves it — only the CSR (which carries the public key) is sent to the
//! server. This is the core property that makes enrollment safe.
use anyhow::{Context, Result};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use std::str::FromStr;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::EncodePem;
use x509_cert::name::Name;

/// The server requires RSA >= 2048.
const KEY_BITS: usize = 2048;

pub struct NewKey {
    /// PKCS#8 PEM of the freshly generated private key (stays local, protected).
    pub private_key_pem: String,
    /// PKCS#10 CSR PEM to send to the server for signing.
    pub csr_pem: String,
}

/// Generate a new RSA key pair and a CSR bound to it. `common_name` is only a
/// hint — the server ignores it and assigns the real identity (`dlp-agent-<id>`).
pub fn generate(common_name: &str) -> Result<NewKey> {
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, KEY_BITS).context("RSA key generation")?;

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("encoding private key")?
        .to_string();

    let signing_key = SigningKey::<Sha256>::new(private_key);
    // Sanitize the CN into a valid RDN value.
    let safe_cn = common_name.replace(['=', ',', '+'], "-");
    let subject = Name::from_str(&format!("CN={safe_cn}")).context("building CSR subject")?;
    let builder = RequestBuilder::new(subject, &signing_key).context("CSR builder")?;
    let csr = builder
        .build::<rsa::pkcs1v15::Signature>()
        .context("signing CSR")?;
    let csr_pem = csr.to_pem(LineEnding::LF).context("encoding CSR")?;

    Ok(NewKey {
        private_key_pem,
        csr_pem,
    })
}

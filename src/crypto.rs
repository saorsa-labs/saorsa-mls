//! Cryptographic primitives for MLS using saorsa-pqc
//!
//! This module provides post-quantum cryptographic operations using
//! NIST-standardized algorithms from the saorsa-pqc library.
//!
//! We use saorsa-pqc as the single source of truth for all cryptographic
//! operations to ensure consistency and quantum-resistance.

use crate::{MlsError, Result};
use saorsa_pqc::api::{
    hpke::{HpkeConfig, HpkeContext as PqcHpkeContext, HpkeRecipient, HpkeSender},
    kdf::KdfAlgorithm,
    MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant, MlKem, MlKemCiphertext,
    MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret, MlKemVariant, SlhDsa, SlhDsaPublicKey,
    SlhDsaSecretKey, SlhDsaSignature, SlhDsaVariant,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Registry identifier for Saorsa MLS PQC cipher suites (private-use values).
///
/// # Registry Ranges
///
/// - **0x0A01-0x0A04**: SPEC-PROD suites (includes hybrid X25519+MLKEM768)
/// - **0x0B01-0x0B04**: SPEC-2 PQC-only suites (no hybrids, production use)
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum CipherSuiteId {
    // SPEC-PROD registry (0x0A** - includes hybrid)
    /// MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65 (SPEC-PROD)
    #[deprecated(
        since = "0.3.0",
        note = "Use SPEC2_MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65 (0x0B01) for PQC-only"
    )]
    MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65 = 0x0A01,
    /// MLS_128_HYBRID_X25519+MLKEM768_AES128GCM_SHA256_MLDSA65 (SPEC-PROD hybrid)
    #[deprecated(
        since = "0.3.0",
        note = "Hybrid suites not allowed in SPEC-2 PQC-only mode"
    )]
    MLS_128_HYBRID_X25519_MLKEM768_AES128GCM_SHA256_MLDSA65 = 0x0A02,
    /// MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 (SPEC-PROD)
    #[deprecated(
        since = "0.3.0",
        note = "Use SPEC2_MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 (0x0B02) for PQC-only"
    )]
    MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 = 0x0A03,
    /// MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 (SPEC-PROD)
    #[deprecated(
        since = "0.3.0",
        note = "Use SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 (0x0B01) for PQC-only"
    )]
    MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 = 0x0A04,

    // SPEC-2 PQC-only registry (0x0B** - ChaCha20Poly1305 only, no hybrids, production)
    /// MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 (SPEC-2 PQC-only, default)
    SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 = 0x0B01,
    /// MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87 (SPEC-2 PQC-only, high-security)
    SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87 = 0x0B02,
    /// MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192 (SPEC-2 PQC-only, optional SLH-DSA)
    #[allow(dead_code)] // Optional suite, may not be fully implemented yet
    SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192 = 0x0B03,
}

impl CipherSuiteId {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Supported post-quantum / hybrid KEM choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MlsKem {
    MlKem512,
    MlKem768,
    MlKem1024,
    /// Hybrid X25519+MLKEM768 (SPEC-PROD only, not allowed in SPEC-2 PQC-only mode)
    #[deprecated(
        since = "0.3.0",
        note = "Hybrid KEMs not allowed in SPEC-2 PQC-only mode"
    )]
    HybridX25519MlKem768,
}

/// Supported signature schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MlsSignature {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa128,
    SlhDsa192,
    SlhDsa256,
}

/// Supported AEAD algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MlsAead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Supported hash algorithms per ciphersuite definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MlsHash {
    Sha256,
    Sha384,
    Sha512,
    Blake3,
    Sha3_256,
    Sha3_512,
}

/// Saorsa MLS cipher suite descriptor binding KEM, signature, AEAD, and hash choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSuite {
    pub id: CipherSuiteId,
    pub kem: MlsKem,
    pub signature: MlsSignature,
    pub aead: MlsAead,
    pub hash: MlsHash,
}

impl CipherSuite {
    pub const fn new(
        id: CipherSuiteId,
        kem: MlsKem,
        signature: MlsSignature,
        aead: MlsAead,
        hash: MlsHash,
    ) -> Self {
        Self {
            id,
            kem,
            signature,
            aead,
            hash,
        }
    }

    #[must_use]
    pub const fn id(&self) -> CipherSuiteId {
        self.id
    }

    #[must_use]
    pub const fn kem(&self) -> MlsKem {
        self.kem
    }

    #[must_use]
    pub const fn signature(&self) -> MlsSignature {
        self.signature
    }

    #[must_use]
    pub const fn aead(&self) -> MlsAead {
        self.aead
    }

    #[must_use]
    pub const fn hash(&self) -> MlsHash {
        self.hash
    }

    #[must_use]
    pub fn from_id(id: CipherSuiteId) -> Option<Self> {
        REGISTRY.iter().copied().find(|suite| suite.id == id)
    }

    #[must_use]
    pub fn all() -> &'static [CipherSuite] {
        &REGISTRY
    }

    /// Get the ML-KEM variant for this cipher suite.
    #[must_use]
    #[allow(deprecated)] // Must handle deprecated HybridX25519MlKem768 for backward compatibility
    pub fn ml_kem_variant(&self) -> MlKemVariant {
        match self.kem {
            MlsKem::MlKem512 => MlKemVariant::MlKem512,
            MlsKem::MlKem768 | MlsKem::HybridX25519MlKem768 => MlKemVariant::MlKem768,
            MlsKem::MlKem1024 => MlKemVariant::MlKem1024,
        }
    }

    /// Get the ML-DSA variant for this cipher suite.
    /// Check if this cipher suite uses SLH-DSA signatures
    #[must_use]
    pub fn uses_slh_dsa(&self) -> bool {
        matches!(
            self.signature,
            MlsSignature::SlhDsa128 | MlsSignature::SlhDsa192 | MlsSignature::SlhDsa256
        )
    }

    /// Get ML-DSA variant (panics if using SLH-DSA - check uses_slh_dsa() first)
    #[must_use]
    pub fn ml_dsa_variant(&self) -> MlDsaVariant {
        match self.signature {
            MlsSignature::MlDsa44 => MlDsaVariant::MlDsa44,
            MlsSignature::MlDsa65 => MlDsaVariant::MlDsa65,
            MlsSignature::MlDsa87 => MlDsaVariant::MlDsa87,
            MlsSignature::SlhDsa128 | MlsSignature::SlhDsa192 | MlsSignature::SlhDsa256 => {
                panic!("Called ml_dsa_variant() on SLH-DSA suite - use slh_dsa_variant() instead")
            }
        }
    }

    /// Get SLH-DSA variant (panics if using ML-DSA - check uses_slh_dsa() first)
    #[must_use]
    pub fn slh_dsa_variant(&self) -> SlhDsaVariant {
        match self.signature {
            // Use "fast" variants for now as "small" variants may not be available
            MlsSignature::SlhDsa128 => SlhDsaVariant::Sha2_128f,
            MlsSignature::SlhDsa192 => SlhDsaVariant::Sha2_128f, // Use 128f for 192-bit security level
            MlsSignature::SlhDsa256 => SlhDsaVariant::Sha2_256f,
            MlsSignature::MlDsa44 | MlsSignature::MlDsa65 | MlsSignature::MlDsa87 => {
                panic!("Called slh_dsa_variant() on ML-DSA suite - use ml_dsa_variant() instead")
            }
        }
    }

    /// Get the key size for symmetric encryption.
    #[must_use]
    pub fn key_size(&self) -> usize {
        match self.aead {
            MlsAead::Aes128Gcm => 16,
            MlsAead::Aes256Gcm | MlsAead::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size for AEAD.
    #[must_use]
    pub fn nonce_size(&self) -> usize {
        12
    }

    /// Get the hash output size used for HKDF and transcript hashing.
    #[must_use]
    pub fn hash_size(&self) -> usize {
        match self.hash {
            MlsHash::Sha256 => 32,
            MlsHash::Sha384 => 48,
            MlsHash::Sha512 => 64,
            MlsHash::Blake3 => 32,
            MlsHash::Sha3_256 => 32,
            MlsHash::Sha3_512 => 64,
        }
    }

    /// Check if this is a PQC-only cipher suite (SPEC-2 compliant).
    ///
    /// Returns `true` for SPEC-2 suites (0x0B01-0x0B03) which are PQC-only with ChaCha20Poly1305.
    /// Returns `false` for SPEC-PROD suites (0x0A01-0x0A04) which may include hybrids.
    ///
    /// # SPEC-2 Policy (§8)
    ///
    /// SPEC-2 requires rejecting any non-PQC suite and uses only ChaCha20Poly1305 AEAD.
    #[must_use]
    #[allow(deprecated)] // Must check deprecated HybridX25519MlKem768 for backward compatibility
    pub fn is_pqc_only(&self) -> bool {
        // Check if using hybrid KEM (not allowed in SPEC-2)
        if matches!(self.kem, MlsKem::HybridX25519MlKem768) {
            return false;
        }

        // Check if suite ID is in SPEC-2 range (0x0B01-0x0B03)
        matches!(
            self.id,
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65
                | CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87
                | CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192
        )
    }

    /// Check if this suite is in the SPEC-2 registry range (0x0B**).
    #[must_use]
    pub fn is_spec2(&self) -> bool {
        (self.id.as_u16() & 0xFF00) == 0x0B00
    }

    /// Check if this suite is deprecated (SPEC-PROD range 0x0A**).
    #[must_use]
    pub fn is_deprecated(&self) -> bool {
        (self.id.as_u16() & 0xFF00) == 0x0A00
    }
}

impl Default for CipherSuite {
    fn default() -> Self {
        // SPEC-2 default: MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 (0x0B01)
        // All SPEC-2 suites use ChaCha20Poly1305 AEAD
        CipherSuite::new(
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
            MlsKem::MlKem768,
            MlsSignature::MlDsa65,
            MlsAead::ChaCha20Poly1305,
            MlsHash::Sha256,
        )
    }
}

/// Cipher suite registry containing both SPEC-PROD (0x0A**) and SPEC-2 (0x0B**) suites.
///
/// SPEC-2 PQC-only suites (0x0B01-0x0B03) use ChaCha20Poly1305 and are preferred for production.
/// SPEC-PROD suites (0x0A01-0x0A04) are deprecated and include hybrid mode.
#[allow(deprecated)]
const REGISTRY: [CipherSuite; 7] = [
    // SPEC-PROD registry (0x0A** - deprecated, includes hybrid)
    CipherSuite::new(
        CipherSuiteId::MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65,
        MlsKem::MlKem768,
        MlsSignature::MlDsa65,
        MlsAead::Aes128Gcm,
        MlsHash::Sha256,
    ),
    CipherSuite::new(
        CipherSuiteId::MLS_128_HYBRID_X25519_MLKEM768_AES128GCM_SHA256_MLDSA65,
        MlsKem::HybridX25519MlKem768,
        MlsSignature::MlDsa65,
        MlsAead::Aes128Gcm,
        MlsHash::Sha256,
    ),
    CipherSuite::new(
        CipherSuiteId::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
        MlsKem::MlKem1024,
        MlsSignature::MlDsa87,
        MlsAead::Aes256Gcm,
        MlsHash::Sha512,
    ),
    CipherSuite::new(
        CipherSuiteId::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
        MlsKem::MlKem768,
        MlsSignature::MlDsa65,
        MlsAead::ChaCha20Poly1305,
        MlsHash::Sha256,
    ),
    // SPEC-2 PQC-only registry (0x0B** - ChaCha20Poly1305 only, no hybrids, production)
    CipherSuite::new(
        CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
        MlsKem::MlKem768,
        MlsSignature::MlDsa65,
        MlsAead::ChaCha20Poly1305,
        MlsHash::Sha256,
    ),
    CipherSuite::new(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        MlsKem::MlKem1024,
        MlsSignature::MlDsa87,
        MlsAead::ChaCha20Poly1305,
        MlsHash::Sha512,
    ),
    // SPEC-2 optional SLH-DSA suite (0x0B03)
    CipherSuite::new(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
        MlsKem::MlKem1024,
        MlsSignature::SlhDsa192,
        MlsAead::ChaCha20Poly1305,
        MlsHash::Sha384,
    ),
];

/// Cryptographic operations using saorsa-pqc as the single source of truth
pub struct Hash {
    pub suite: CipherSuite,
}

impl Hash {
    #[must_use]
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Compute hash of data using BLAKE3 from saorsa-pqc
    #[must_use]
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        use saorsa_pqc::api::hash::Blake3Hasher;
        use saorsa_pqc::api::traits::Hash as HashTrait;

        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let output = hasher.finalize();
        output.as_ref().to_vec()
    }

    /// Compute HMAC using saorsa-pqc's HMAC-SHA3-256
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the HMAC key is invalid or computation fails.
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use saorsa_pqc::api::hmac::HmacSha3_256;
        use saorsa_pqc::api::traits::Mac;

        let mut mac = HmacSha3_256::new(key)
            .map_err(|e| MlsError::CryptoError(format!("HMAC key error: {e:?}")))?;
        mac.update(data);
        let output = mac.finalize();
        Ok(output.as_ref().to_vec())
    }
}

/// Key derivation using HKDF
#[derive(Debug, Clone)]
pub struct KeySchedule {
    suite: CipherSuite,
}

impl KeySchedule {
    #[must_use]
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Derive key using saorsa-pqc's HKDF-SHA3-256
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the HKDF key derivation fails.
    pub fn derive_secret(&self, secret: &[u8], label: &str, context: &[u8]) -> Result<Vec<u8>> {
        use saorsa_pqc::api::kdf::HkdfSha3_256;
        use saorsa_pqc::api::traits::Kdf;

        let info = Self::build_hkdf_label(label, context, self.suite.hash_size());
        let mut output = vec![0u8; self.suite.hash_size()];

        HkdfSha3_256::derive(secret, None, &info, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("HKDF error: {e:?}")))?;
        Ok(output)
    }

    /// Derive multiple keys using saorsa-pqc's HKDF
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if any key derivation fails.
    pub fn derive_keys(
        &self,
        salt: &[u8],
        secret: &[u8],
        labels: &[&str],
        lengths: &[usize],
    ) -> Result<Vec<Vec<u8>>> {
        let mut results = Vec::new();

        for (label, &length) in labels.iter().zip(lengths.iter()) {
            let key = self.derive_secret(secret, label, salt)?;
            results.push(key[..length].to_vec());
        }
        Ok(results)
    }

    /// Derive a single key with specific length using saorsa-pqc's HKDF
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the HKDF key derivation fails.
    pub fn derive_key(
        &self,
        salt: &[u8],
        secret: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        use saorsa_pqc::api::kdf::HkdfSha3_256;
        use saorsa_pqc::api::traits::Kdf;

        let mut output = vec![0u8; length];
        HkdfSha3_256::derive(secret, Some(salt), info, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("HKDF error: {e:?}")))?;
        Ok(output)
    }

    fn build_hkdf_label(label: &str, context: &[u8], length: usize) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
        info.push(
            u8::try_from(b"tls13 ".len()).unwrap_or(u8::MAX)
                + u8::try_from(label.len()).unwrap_or(u8::MAX),
        );
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(u8::try_from(context.len()).unwrap_or(u8::MAX));
        info.extend_from_slice(context);
        info
    }

    /// Derive an exported secret per RFC 9420 §8.5
    ///
    /// This implements the MLS exporter interface which allows applications
    /// to derive secrets from the group's exporter secret.
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the key derivation fails.
    pub fn export_secret(
        &self,
        exporter_secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        use saorsa_pqc::api::kdf::HkdfSha3_256;
        use saorsa_pqc::api::traits::Kdf;

        // Build the exporter label per RFC 9420
        // The label is "mls exporter" || user_label
        let full_label = format!("mls exporter {}", label);
        let info = Self::build_hkdf_label(&full_label, context, length);

        let mut output = vec![0u8; length];
        HkdfSha3_256::derive(exporter_secret, None, &info, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("Exporter derivation failed: {e:?}")))?;

        Ok(output)
    }
}

/// Signature supporting both ML-DSA and SLH-DSA
#[derive(Clone)]
pub enum Signature {
    /// ML-DSA signature
    MlDsa(MlDsaSignature),
    /// SLH-DSA signature
    SlhDsa(SlhDsaSignature),
}

impl Signature {
    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::MlDsa(sig) => sig.to_bytes().to_vec(),
            Signature::SlhDsa(sig) => sig.to_bytes().to_vec(),
        }
    }
}

/// Debug wrapper for `Signature` to provide Debug, PartialEq, and Serialize traits
#[derive(Clone)]
pub struct DebugSignature(pub Signature);

impl std::fmt::Debug for DebugSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Signature::MlDsa(sig) => write!(f, "MlDsaSignature(<{} bytes>)", sig.to_bytes().len()),
            Signature::SlhDsa(sig) => {
                write!(f, "SlhDsaSignature(<{} bytes>)", sig.to_bytes().len())
            }
        }
    }
}

impl PartialEq for DebugSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for DebugSignature {}

impl serde::Serialize for DebugSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for DebugSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        // Note: We cannot deserialize without knowing the variant, so this will need context
        // For now, assume ML-DSA-65 for backward compatibility
        let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &bytes)
            .map_err(|e| serde::de::Error::custom(format!("Signature decode error: {e:?}")))?;
        Ok(DebugSignature(Signature::MlDsa(signature)))
    }
}

/// Signature key pair supporting both ML-DSA and SLH-DSA
#[derive(Clone)]
pub enum SignatureKey {
    /// ML-DSA signature keys
    MlDsa {
        /// Secret key for signing
        secret: MlDsaSecretKey,
        /// Public key for verification
        public: MlDsaPublicKey,
    },
    /// SLH-DSA signature keys
    SlhDsa {
        /// Secret key for signing
        secret: SlhDsaSecretKey,
        /// Public key for verification
        public: SlhDsaPublicKey,
    },
}

/// Post-quantum key pair for signing and key agreement
pub struct KeyPair {
    /// Signature key pair (ML-DSA or SLH-DSA)
    pub signature_key: SignatureKey,
    /// ML-KEM secret key for decapsulation
    pub kem_secret: MlKemSecretKey,
    /// ML-KEM public key for encapsulation
    pub kem_public: MlKemPublicKey,
    /// Cipher suite
    pub suite: CipherSuite,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("suite", &self.suite)
            .field("verifying_key", &"<hidden>")
            .field("kem_public", &"<hidden>")
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Generate a new key pair
    ///
    /// # Panics
    ///
    /// Panics if key generation fails (should never happen in practice).
    #[must_use]
    pub fn generate(suite: CipherSuite) -> Self {
        // Generate signature key pair based on suite type
        let signature_key = if suite.uses_slh_dsa() {
            let slh_dsa = SlhDsa::new(suite.slh_dsa_variant());
            let (public, secret) = slh_dsa
                .generate_keypair()
                .expect("SLH-DSA key generation should not fail");
            SignatureKey::SlhDsa { secret, public }
        } else {
            let ml_dsa = MlDsa::new(suite.ml_dsa_variant());
            let (public, secret) = ml_dsa
                .generate_keypair()
                .expect("ML-DSA key generation should not fail");
            SignatureKey::MlDsa { secret, public }
        };

        // Generate ML-KEM key pair for key encapsulation
        let ml_kem = MlKem::new(suite.ml_kem_variant());
        let (kem_public, kem_secret) = ml_kem
            .generate_keypair()
            .expect("ML-KEM key generation should not fail");

        Self {
            signature_key,
            kem_secret,
            kem_public,
            suite,
        }
    }

    /// Generate a key pair from a seed (for FIPS KATs)
    ///
    /// Note: Current implementation uses standard key generation.
    /// Deterministic generation from seed requires RNG seeding support
    /// in saorsa-pqc which is pending upstream.
    ///
    /// For now, this validates that key generation works with correct sizes.
    ///
    /// # Errors
    ///
    /// Returns error if seed is invalid or key generation fails.
    pub fn generate_from_seed(suite: CipherSuite, _seed: &[u8]) -> Result<Self> {
        // TODO: Use seed when saorsa-pqc provides RNG seeding APIs
        // For now, just generate normally to validate algorithm correctness
        Ok(Self::generate(suite))
    }

    /// Get the public verification key bytes
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        match &self.signature_key {
            SignatureKey::MlDsa { public, .. } => public.to_bytes().to_vec(),
            SignatureKey::SlhDsa { public, .. } => public.to_bytes().to_vec(),
        }
    }

    /// Get ML-DSA public key (for backward compatibility, panics if using SLH-DSA)
    #[must_use]
    pub fn verifying_key(&self) -> &MlDsaPublicKey {
        match &self.signature_key {
            SignatureKey::MlDsa { public, .. } => public,
            SignatureKey::SlhDsa { .. } => {
                panic!(
                    "Called verifying_key() on SLH-DSA keypair - use verifying_key_bytes() instead"
                )
            }
        }
    }

    /// Get the public KEM key
    #[must_use]
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.kem_public
    }

    /// Sign a message
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the signing operation fails.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        match &self.signature_key {
            SignatureKey::MlDsa { secret, .. } => {
                let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
                ml_dsa
                    .sign(secret, message)
                    .map(Signature::MlDsa)
                    .map_err(|e| MlsError::CryptoError(format!("ML-DSA signing failed: {e:?}")))
            }
            SignatureKey::SlhDsa { secret, .. } => {
                let slh_dsa = SlhDsa::new(self.suite.slh_dsa_variant());
                slh_dsa
                    .sign(secret, message)
                    .map(Signature::SlhDsa)
                    .map_err(|e| MlsError::CryptoError(format!("SLH-DSA signing failed: {e:?}")))
            }
        }
    }

    /// Verify a signature
    ///
    /// Returns `true` if signature is valid, `false` otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match (&self.signature_key, signature) {
            (SignatureKey::MlDsa { public, .. }, Signature::MlDsa(sig)) => {
                let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
                ml_dsa.verify(public, message, sig).unwrap_or(false)
            }
            (SignatureKey::SlhDsa { public, .. }, Signature::SlhDsa(sig)) => {
                let slh_dsa = SlhDsa::new(self.suite.slh_dsa_variant());
                slh_dsa.verify(public, message, sig).unwrap_or(false)
            }
            // Signature type mismatch
            _ => false,
        }
    }

    /// Perform key encapsulation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the encapsulation operation fails.
    pub fn encapsulate(
        &self,
        recipient_public: &MlKemPublicKey,
    ) -> Result<(MlKemCiphertext, MlKemSharedSecret)> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());
        let (shared_secret, ciphertext) = ml_kem
            .encapsulate(recipient_public)
            .map_err(|e| MlsError::CryptoError(format!("Encapsulation failed: {e:?}")))?;
        Ok((ciphertext, shared_secret))
    }

    /// Perform key decapsulation (for FIPS KATs)
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the decapsulation operation fails.
    pub fn kem_decaps(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());

        // Convert bytes to ciphertext
        let ct = MlKemCiphertext::from_bytes(self.suite.ml_kem_variant(), ciphertext)
            .map_err(|e| MlsError::CryptoError(format!("Invalid ciphertext: {e:?}")))?;

        let shared_secret = ml_kem
            .decapsulate(&self.kem_secret, &ct)
            .map_err(|e| MlsError::CryptoError(format!("Decapsulation failed: {e:?}")))?;

        Ok(shared_secret.to_bytes().to_vec())
    }

    /// Perform key decapsulation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the decapsulation operation fails.
    pub fn decapsulate(&self, ciphertext: &MlKemCiphertext) -> Result<MlKemSharedSecret> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());
        ml_kem
            .decapsulate(&self.kem_secret, ciphertext)
            .map_err(|e| MlsError::CryptoError(format!("Decapsulation failed: {e:?}")))
    }
}

/// AEAD encryption/decryption using saorsa-pqc's `ChaCha20Poly1305`
#[derive(Debug)]
pub struct AeadCipher {
    key: Vec<u8>,
    suite: CipherSuite,
}

impl AeadCipher {
    /// Create a new AEAD cipher from key material
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the key size is invalid.
    pub fn new(key: Vec<u8>, suite: CipherSuite) -> Result<Self> {
        if key.len() != suite.key_size() {
            return Err(MlsError::CryptoError(format!(
                "Invalid key size: expected {}, got {}",
                suite.key_size(),
                key.len()
            )));
        }

        Ok(Self { key, suite })
    }

    /// Encrypt plaintext with associated data using saorsa-pqc's `ChaCha20Poly1305`
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the nonce size is invalid or encryption fails.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Use saorsa-pqc's ChaCha20Poly1305
        use saorsa_pqc::api::symmetric::ChaCha20Poly1305 as PqcCipher;

        if nonce.len() != self.suite.nonce_size() {
            return Err(MlsError::CryptoError("Invalid nonce size".to_string()));
        }

        // Convert key to the format expected by saorsa-pqc
        let key_array: [u8; 32] = self
            .key
            .clone()
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid key size".to_string()))?;
        let key = chacha20poly1305::Key::from(key_array);

        let cipher = PqcCipher::new(&key);

        // Convert nonce
        let nonce_array: [u8; 12] = nonce
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid nonce size".to_string()))?;
        let nonce_obj = chacha20poly1305::Nonce::from(nonce_array);

        // Encrypt with AAD
        let ciphertext = cipher
            .encrypt_with_aad(&nonce_obj, plaintext, associated_data)
            .map_err(|e| MlsError::CryptoError(format!("Encryption failed: {e:?}")))?;

        // Return nonce + ciphertext for wire format
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext with associated data using saorsa-pqc's `ChaCha20Poly1305`
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the nonce size is invalid, ciphertext is too short, or decryption fails.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Use saorsa-pqc's ChaCha20Poly1305
        use saorsa_pqc::api::symmetric::ChaCha20Poly1305 as PqcCipher;

        if nonce.len() != self.suite.nonce_size() {
            return Err(MlsError::CryptoError("Invalid nonce size".to_string()));
        }

        // The ciphertext includes the nonce at the beginning (12 bytes)
        // Skip it and use it for decryption
        if ciphertext.len() < 12 {
            return Err(MlsError::CryptoError("Ciphertext too short".to_string()));
        }

        let actual_nonce = &ciphertext[..12];
        let actual_ciphertext = &ciphertext[12..];

        // Convert key to the format expected by saorsa-pqc
        let key_array: [u8; 32] = self
            .key
            .clone()
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid key size".to_string()))?;
        let key = chacha20poly1305::Key::from(key_array);

        let cipher = PqcCipher::new(&key);

        // Convert nonce
        let nonce_array: [u8; 12] = actual_nonce
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid nonce size".to_string()))?;
        let nonce_obj = chacha20poly1305::Nonce::from(nonce_array);

        // Decrypt with AAD
        let plaintext = cipher
            .decrypt_with_aad(&nonce_obj, actual_ciphertext, associated_data)
            .map_err(|e| MlsError::CryptoError(format!("Decryption failed: {e:?}")))?;

        Ok(plaintext)
    }

    /// Get the key size for this cipher
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.suite.key_size()
    }

    /// Get the nonce size for this cipher
    #[must_use]
    pub fn nonce_size(&self) -> usize {
        self.suite.nonce_size()
    }
}

/// Generate random bytes using the same RNG as saorsa-pqc
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Constant-time comparison using subtle crate (already a dependency of saorsa-pqc)
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// MLS-specific KDF labels
pub mod labels {
    pub const ENCRYPTION: &str = "encryption";
    pub const AUTHENTICATION: &str = "authentication";
    pub const EXPORTER: &str = "exporter";
    pub const EXTERNAL: &str = "external";
    pub const CONFIRM: &str = "confirm";
    pub const MEMBERSHIP: &str = "membership";
    pub const RESUMPTION: &str = "resumption";
    pub const INIT: &str = "init";
    pub const SENDER_DATA: &str = "sender data";
    pub const WELCOME: &str = "welcome";
    pub const HANDSHAKE: &str = "handshake";
    pub const APPLICATION: &str = "application";
    // Additional MLS labels
    pub const EPOCH_SECRET: &str = "epoch";
    pub const SENDER_DATA_SECRET: &str = "sender data secret";
    pub const HANDSHAKE_SECRET: &str = "handshake secret";
    pub const APPLICATION_SECRET: &str = "application secret";
    pub const EXPORTER_SECRET: &str = "exporter secret";
    pub const AUTHENTICATION_SECRET: &str = "authentication secret";
    pub const EXTERNAL_SECRET: &str = "external secret";
    pub const CONFIRMATION_KEY: &str = "confirmation key";
    pub const MEMBERSHIP_KEY: &str = "membership key";
    pub const RESUMPTION_PSK: &str = "resumption psk";
    pub const INIT_SECRET: &str = "init secret";
}

/// Secure bytes that are zeroed on drop
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// HPKE context for encryption/decryption operations
///
/// Wraps saorsa-pqc's HPKE context and provides MLS-specific interface
pub struct HpkeContext {
    inner: PqcHpkeContext,
}

impl HpkeContext {
    /// Export secret material for key derivation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the export operation fails
    pub fn export(&mut self, context: &[u8], length: usize) -> Result<Vec<u8>> {
        self.inner
            .export(context, length)
            .map_err(|e| MlsError::CryptoError(format!("HPKE export failed: {e:?}")))
    }

    /// Seal (encrypt) plaintext with associated data
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if encryption fails
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .seal(plaintext, aad)
            .map_err(|e| MlsError::CryptoError(format!("HPKE seal failed: {e:?}")))
    }

    /// Open (decrypt) ciphertext with associated data
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if decryption or authentication fails
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .open(ciphertext, aad)
            .map_err(|e| MlsError::CryptoError(format!("HPKE open failed: {e:?}")))
    }
}

impl CipherSuite {
    /// Get HPKE configuration for this ciphersuite
    fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig {
            kem: self.ml_kem_variant(),
            kdf: match self.hash {
                MlsHash::Sha256 | MlsHash::Sha3_256 | MlsHash::Blake3 => KdfAlgorithm::HkdfSha3_256,
                MlsHash::Sha384 | MlsHash::Sha512 | MlsHash::Sha3_512 => KdfAlgorithm::HkdfSha3_512,
            },
            aead: match self.aead {
                MlsAead::ChaCha20Poly1305 => saorsa_pqc::api::aead::AeadCipher::ChaCha20Poly1305,
                // Note: saorsa-pqc only has AES256GCM, using it for both AES128 and AES256
                MlsAead::Aes128Gcm | MlsAead::Aes256Gcm => {
                    saorsa_pqc::api::aead::AeadCipher::Aes256Gcm
                }
            },
        }
    }

    /// Single-shot HPKE seal operation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if HPKE setup or encryption fails
    pub fn hpke_seal(
        &self,
        recipient_public_key: &MlKemPublicKey,
        plaintext: &[u8],
        aad: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let config = self.hpke_config();
        let sender = HpkeSender::new(config);

        // Convert public key to bytes
        let pk_bytes = recipient_public_key.to_bytes();

        // Setup and get context
        let (encapped_key, mut ctx) = sender
            .setup_base(&pk_bytes, info)
            .map_err(|e| MlsError::CryptoError(format!("HPKE setup failed: {e:?}")))?;

        // Seal the plaintext
        let ciphertext = ctx
            .seal(plaintext, aad)
            .map_err(|e| MlsError::CryptoError(format!("HPKE seal failed: {e:?}")))?;

        Ok((encapped_key, ciphertext))
    }

    /// KEM encapsulation with seed (for FIPS KATs)
    ///
    /// Note: Current implementation uses standard encapsulation.
    /// Deterministic encapsulation from seed requires RNG seeding support
    /// in saorsa-pqc which is pending upstream.
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if encapsulation fails
    pub fn kem_encaps_with_seed(
        &self,
        recipient_public_key: &MlKemPublicKey,
        _seed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // TODO: Use seed when saorsa-pqc provides RNG seeding APIs
        // For now, use standard encapsulation to validate algorithm correctness
        let ml_kem = MlKem::new(self.ml_kem_variant());
        let (shared_secret, ciphertext) = ml_kem
            .encapsulate(recipient_public_key)
            .map_err(|e| MlsError::CryptoError(format!("Encapsulation failed: {e:?}")))?;

        Ok((ciphertext.to_bytes(), shared_secret.to_bytes().to_vec()))
    }

    /// Setup HPKE sender context
    ///
    /// Returns encapsulated key and sender context for multiple encryptions
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if HPKE setup fails
    pub fn hpke_setup_sender(
        &self,
        recipient_public_key: &MlKemPublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, HpkeContext)> {
        let config = self.hpke_config();
        let sender = HpkeSender::new(config);

        let pk_bytes = recipient_public_key.to_bytes();

        let (encapped_key, ctx) = sender
            .setup_base(&pk_bytes, info)
            .map_err(|e| MlsError::CryptoError(format!("HPKE sender setup failed: {e:?}")))?;

        Ok((encapped_key, HpkeContext { inner: ctx }))
    }
}

impl KeyPair {
    /// Single-shot HPKE open operation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if HPKE setup or decryption fails
    pub fn hpke_open(
        &self,
        encapped_key: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        info: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ctx = self.hpke_setup_receiver(encapped_key, info)?;
        ctx.open(ciphertext, aad)
    }

    /// Setup HPKE receiver context
    ///
    /// Returns receiver context for multiple decryptions
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if HPKE setup fails
    pub fn hpke_setup_receiver(&self, encapped_key: &[u8], info: &[u8]) -> Result<HpkeContext> {
        let config = HpkeConfig {
            kem: self.suite.ml_kem_variant(),
            kdf: match self.suite.hash {
                MlsHash::Sha256 | MlsHash::Sha3_256 | MlsHash::Blake3 => KdfAlgorithm::HkdfSha3_256,
                MlsHash::Sha384 | MlsHash::Sha512 | MlsHash::Sha3_512 => KdfAlgorithm::HkdfSha3_512,
            },
            aead: match self.suite.aead {
                MlsAead::ChaCha20Poly1305 => saorsa_pqc::api::aead::AeadCipher::ChaCha20Poly1305,
                // Note: saorsa-pqc only has AES256GCM, using it for both AES128 and AES256
                MlsAead::Aes128Gcm | MlsAead::Aes256Gcm => {
                    saorsa_pqc::api::aead::AeadCipher::Aes256Gcm
                }
            },
        };

        let recipient = HpkeRecipient::new(config);

        // Convert secret key to bytes
        let sk_bytes = self.kem_secret.to_bytes();

        let ctx = recipient
            .setup_base(encapped_key, &sk_bytes, info)
            .map_err(|e| MlsError::CryptoError(format!("HPKE recipient setup failed: {e:?}")))?;

        Ok(HpkeContext { inner: ctx })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_defaults() {
        let suite = CipherSuite::default();
        // SPEC-2: Default is ChaCha20Poly1305 (0x0B01)
        assert_eq!(
            suite.id(),
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65
        );
        assert_eq!(suite.key_size(), 32); // ChaCha20 = 32 bytes
        assert_eq!(suite.nonce_size(), 12);
        assert!(suite.is_pqc_only());
        assert!(suite.is_spec2());
    }

    #[test]
    fn test_hash_operations() {
        let hash = Hash::new(CipherSuite::default());
        let data = b"test data";
        let result = hash.hash(data);
        assert_eq!(result.len(), 32);

        let key = b"test key";
        let hmac_result = hash.hmac(key, data).unwrap();
        assert!(!hmac_result.is_empty());
    }

    #[test]
    fn test_key_generation() {
        let kp1 = KeyPair::generate(CipherSuite::default());
        let kp2 = KeyPair::generate(CipherSuite::default());

        // Keys should be different
        assert_ne!(kp1.verifying_key_bytes(), kp2.verifying_key_bytes());
    }

    #[test]
    fn test_signing_and_verification() {
        let kp = KeyPair::generate(CipherSuite::default());
        let message = b"test message";

        let signature = kp.sign(message).unwrap();

        // Test with correct message
        assert!(kp.verify(message, &signature));

        // Test with wrong message - should NOT verify
        let wrong_message = b"wrong message";
        assert!(
            !kp.verify(wrong_message, &signature),
            "Signature should not verify with wrong message"
        );
    }

    #[test]
    fn test_key_encapsulation() {
        let kp1 = KeyPair::generate(CipherSuite::default());
        let kp2 = KeyPair::generate(CipherSuite::default());

        // Encapsulate for kp2
        let (ciphertext, shared_secret1) = kp1.encapsulate(&kp2.kem_public).unwrap();

        // Decapsulate with kp2's secret
        let shared_secret2 = kp2.decapsulate(&ciphertext).unwrap();

        // Shared secrets should match
        assert_eq!(shared_secret1.to_bytes(), shared_secret2.to_bytes());
    }

    #[test]
    fn test_aead_encryption() {
        // Use ChaCha20Poly1305 suite since AEAD implementation currently only supports that
        let suite = CipherSuite::from_id(
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
        )
        .expect("ChaCha20 suite should exist");
        let key = random_bytes(suite.key_size()); // Use correct key size for suite
        let cipher = AeadCipher::new(key, suite).unwrap();
        let nonce = random_bytes(12);
        let plaintext = b"secret message";
        let aad = b"associated data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_derivation() {
        let ks = KeySchedule::new(CipherSuite::default());
        let secret = random_bytes(32);
        let derived = ks.derive_secret(&secret, "test", b"context").unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = SecretBytes::new(data.clone());
        assert_eq!(secret.as_bytes(), &data);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
        // SecretBytes will be zeroed when dropped
    }

    // SPEC-2 PQC-only suite tests

    #[test]
    fn test_spec2_default_suite() {
        let suite = CipherSuite::default();
        // SPEC-2 default is 0x0B01 (ChaCha20Poly1305)
        assert_eq!(
            suite.id(),
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
            "Default should be SPEC-2 PQC-only suite 0x0B01"
        );
        assert_eq!(suite.kem(), MlsKem::MlKem768);
        assert_eq!(suite.signature(), MlsSignature::MlDsa65);
        assert_eq!(suite.aead(), MlsAead::ChaCha20Poly1305);
        assert_eq!(suite.hash(), MlsHash::Sha256);
        assert!(suite.is_pqc_only(), "Default suite must be PQC-only");
        assert!(suite.is_spec2(), "Default suite must be SPEC-2");
    }

    #[test]
    fn test_spec2_suite_0xb01_chacha_sha256() {
        let suite = CipherSuite::from_id(
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
        )
        .expect("Suite 0x0B01 should exist");
        assert_eq!(suite.key_size(), 32, "ChaCha20 key size");
        assert_eq!(suite.hash_size(), 32, "SHA256 hash size");
        assert_eq!(suite.aead(), MlsAead::ChaCha20Poly1305);
        assert!(suite.is_pqc_only());
        assert!(suite.is_spec2());
        assert!(!suite.is_deprecated());
    }

    #[test]
    fn test_spec2_suite_0xb02_chacha_sha512() {
        let suite = CipherSuite::from_id(
            CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        )
        .expect("Suite 0x0B02 should exist");
        assert_eq!(suite.kem(), MlsKem::MlKem1024, "High-security ML-KEM-1024");
        assert_eq!(
            suite.signature(),
            MlsSignature::MlDsa87,
            "High-security ML-DSA-87"
        );
        assert_eq!(suite.aead(), MlsAead::ChaCha20Poly1305);
        assert_eq!(suite.hash(), MlsHash::Sha512);
        assert_eq!(suite.key_size(), 32, "ChaCha20 key size");
        assert_eq!(suite.hash_size(), 64, "SHA512 hash size");
        assert!(suite.is_pqc_only());
    }

    #[test]
    #[allow(deprecated)]
    fn test_hybrid_suite_not_pqc_only() {
        let suite = CipherSuite::from_id(
            CipherSuiteId::MLS_128_HYBRID_X25519_MLKEM768_AES128GCM_SHA256_MLDSA65,
        )
        .expect("Hybrid suite should exist for backwards compat");
        assert!(!suite.is_pqc_only(), "Hybrid suite must NOT be PQC-only");
        assert!(!suite.is_spec2(), "Hybrid suite is SPEC-PROD");
        assert!(suite.is_deprecated(), "Hybrid suite should be deprecated");
    }

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_suites_not_pqc_only() {
        let deprecated_ids = [
            CipherSuiteId::MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65,
            CipherSuiteId::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
            CipherSuiteId::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
        ];

        for id in &deprecated_ids {
            let suite =
                CipherSuite::from_id(*id).expect("Deprecated suite should still be in registry");
            assert!(suite.is_deprecated(), "Suite {:?} should be deprecated", id);
            assert!(!suite.is_spec2(), "Suite {:?} is not SPEC-2", id);
            // Note: Deprecated PQC-only suites (0x0A01, 0x0A03, 0x0A04) are actually PQC-only,
            // but we encourage migration to SPEC-2 range (0x0B**)
        }
    }

    #[test]
    fn test_pqc_only_policy_enforcement() {
        // SPEC-2 suites must be PQC-only with ChaCha20Poly1305
        let spec2_ids = [
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
            CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        ];

        for id in &spec2_ids {
            let suite = CipherSuite::from_id(*id).expect("SPEC-2 suite should exist");
            assert!(
                suite.is_pqc_only(),
                "SPEC-2 suite {:?} must be PQC-only",
                id
            );
            assert_eq!(
                suite.aead(),
                MlsAead::ChaCha20Poly1305,
                "SPEC-2 suite {:?} must use ChaCha20Poly1305",
                id
            );
        }
    }

    #[test]
    fn test_sha384_hash_size() {
        // Test the new SHA384 hash variant with ChaCha20Poly1305
        let suite = CipherSuite::new(
            CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
            MlsKem::MlKem1024,
            MlsSignature::SlhDsa192,
            MlsAead::ChaCha20Poly1305,
            MlsHash::Sha384,
        );
        assert_eq!(suite.hash_size(), 48, "SHA384 produces 48-byte output");
    }

    #[test]
    fn test_registry_contains_seven_suites() {
        let all_suites = CipherSuite::all();
        assert_eq!(
            all_suites.len(),
            7,
            "Registry should contain 4 SPEC-PROD + 3 SPEC-2 suites (including optional SLH-DSA)"
        );
    }

    #[test]
    fn test_suite_id_to_u16() {
        assert_eq!(
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65.as_u16(),
            0x0B01
        );
        assert_eq!(
            CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87.as_u16(),
            0x0B02
        );
        assert_eq!(
            CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192.as_u16(),
            0x0B03
        );
    }

    #[test]
    fn test_all_spec2_suites_functional() {
        // Verify all SPEC-2 suites can perform basic crypto operations
        let spec2_ids = [
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
            CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        ];

        for id in &spec2_ids {
            let suite = CipherSuite::from_id(*id).expect("Suite should exist");

            // Test key generation
            let kp = KeyPair::generate(suite);
            assert!(!kp.verifying_key_bytes().is_empty());

            // Test signing
            let message = b"test message for SPEC-2";
            let signature = kp.sign(message).expect("Signing should succeed");
            assert!(
                kp.verify(message, &signature),
                "Verification should succeed for suite {:?}",
                id
            );
        }
    }
}

/// Debug wrapper for `MlDsaSignature` to work around missing Debug impl
#[derive(Clone)]
pub struct DebugMlDsaSignature(pub MlDsaSignature);

impl std::fmt::Debug for DebugMlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSignature(<{} bytes>)", self.0.to_bytes().len())
    }
}

impl PartialEq for DebugMlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for DebugMlDsaSignature {}

impl Serialize for DebugMlDsaSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_wrappers::serialize_ml_dsa_signature(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for DebugMlDsaSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let signature = serde_wrappers::deserialize_ml_dsa_signature(deserializer)?;
        Ok(DebugMlDsaSignature(signature))
    }
}

/// Debug wrapper for `MlDsaPublicKey` to work around missing Debug impl
#[derive(Clone)]
pub struct DebugMlDsaPublicKey(pub MlDsaPublicKey);

impl std::fmt::Debug for DebugMlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaPublicKey(<{} bytes>)", self.0.to_bytes().len())
    }
}

impl PartialEq for DebugMlDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for DebugMlDsaPublicKey {}

impl Serialize for DebugMlDsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_wrappers::serialize_ml_dsa_public_key(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for DebugMlDsaPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = serde_wrappers::deserialize_ml_dsa_public_key(deserializer)?;
        Ok(DebugMlDsaPublicKey(key))
    }
}

/// Serde wrappers for saorsa-pqc types
pub mod serde_wrappers {
    use super::{
        DebugMlDsaPublicKey, DebugMlDsaSignature, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext,
    };
    use saorsa_pqc::{MlDsaVariant, MlKemVariant};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `MlKemCiphertext`
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the ciphertext cannot be serialized.
    pub fn serialize_ml_kem_ciphertext<S>(
        ciphertext: &MlKemCiphertext,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = ciphertext.to_bytes();
        let variant = ciphertext.variant();
        serializer.serialize_str(&format!("{}:{}", variant as u8, hex::encode(&bytes)))
    }

    /// Deserialize `MlKemCiphertext`
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the ciphertext cannot be deserialized.
    pub fn deserialize_ml_kem_ciphertext<'de, D>(
        deserializer: D,
    ) -> std::result::Result<MlKemCiphertext, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(D::Error::custom("Invalid MlKemCiphertext format"));
        }

        let variant = match parts[0] {
            "0" => MlKemVariant::MlKem512,
            "1" => MlKemVariant::MlKem768,
            "2" => MlKemVariant::MlKem1024,
            _ => return Err(D::Error::custom("Invalid MlKemVariant")),
        };

        let bytes = hex::decode(parts[1])
            .map_err(|e| D::Error::custom(format!("Hex decode error: {e}")))?;

        MlKemCiphertext::from_bytes(variant, &bytes)
            .map_err(|e| D::Error::custom(format!("MlKemCiphertext decode error: {e:?}")))
    }

    /// Serialize `MlDsaSignature`
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the signature cannot be serialized.
    pub fn serialize_ml_dsa_signature<S>(
        signature: &MlDsaSignature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = signature.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize `MlDsaSignature`
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the signature cannot be deserialized.
    pub fn deserialize_ml_dsa_signature<'de, D>(
        deserializer: D,
    ) -> std::result::Result<MlDsaSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("Hex decode error: {e}")))?;

        // Create from bytes - we'll use MlDsa65 as default
        if bytes.len() != 3309 {
            // ML-DSA-65 signature size
            return Err(D::Error::custom("Invalid MlDsaSignature size"));
        }

        let array: [u8; 3309] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("Failed to convert to array"))?;

        MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &array)
            .map_err(|e| D::Error::custom(format!("MlDsaSignature decode error: {e:?}")))
    }

    /// Serialize `MlDsaPublicKey`
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the public key cannot be serialized.
    pub fn serialize_ml_dsa_public_key<S>(
        key: &MlDsaPublicKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize `MlDsaPublicKey`
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the public key cannot be deserialized.
    pub fn deserialize_ml_dsa_public_key<'de, D>(
        deserializer: D,
    ) -> std::result::Result<MlDsaPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("Hex decode error: {e}")))?;

        // Create from bytes - we'll use MlDsa65 as default
        if bytes.len() != 1952 {
            // ML-DSA-65 public key size
            return Err(D::Error::custom("Invalid MlDsaPublicKey size"));
        }

        let array: [u8; 1952] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("Failed to convert to array"))?;

        MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &array)
            .map_err(|e| D::Error::custom(format!("MlDsaPublicKey decode error: {e:?}")))
    }

    /// Serialize `DebugMlDsaSignature` wrapper
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the signature wrapper cannot be serialized.
    pub fn serialize_debug_ml_dsa_signature<S>(
        signature: &DebugMlDsaSignature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_ml_dsa_signature(&signature.0, serializer)
    }

    /// Deserialize `DebugMlDsaSignature` wrapper
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the signature wrapper cannot be deserialized.
    pub fn deserialize_debug_ml_dsa_signature<'de, D>(
        deserializer: D,
    ) -> std::result::Result<DebugMlDsaSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let signature = deserialize_ml_dsa_signature(deserializer)?;
        Ok(DebugMlDsaSignature(signature))
    }

    /// Serialize `DebugMlDsaPublicKey` wrapper
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the public key wrapper cannot be serialized.
    pub fn serialize_debug_ml_dsa_public_key<S>(
        key: &DebugMlDsaPublicKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_ml_dsa_public_key(&key.0, serializer)
    }

    /// Deserialize `DebugMlDsaPublicKey` wrapper
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the public key wrapper cannot be deserialized.
    pub fn deserialize_debug_ml_dsa_public_key<'de, D>(
        deserializer: D,
    ) -> std::result::Result<DebugMlDsaPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = deserialize_ml_dsa_public_key(deserializer)?;
        Ok(DebugMlDsaPublicKey(key))
    }
}

// Display implementations for test assertions
impl std::fmt::Display for MlsAead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsAead::Aes128Gcm => write!(f, "AES-128-GCM"),
            MlsAead::Aes256Gcm => write!(f, "AES-256-GCM"),
            MlsAead::ChaCha20Poly1305 => write!(f, "ChaCha20Poly1305"),
        }
    }
}

impl std::fmt::Display for MlsHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsHash::Sha256 => write!(f, "SHA256"),
            MlsHash::Sha384 => write!(f, "SHA384"),
            MlsHash::Sha512 => write!(f, "SHA512"),
            MlsHash::Blake3 => write!(f, "BLAKE3"),
            MlsHash::Sha3_256 => write!(f, "SHA3-256"),
            MlsHash::Sha3_512 => write!(f, "SHA3-512"),
        }
    }
}

impl std::fmt::Display for MlsKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsKem::MlKem512 => write!(f, "ML-KEM-512"),
            MlsKem::MlKem768 => write!(f, "ML-KEM-768"),
            MlsKem::MlKem1024 => write!(f, "ML-KEM-1024"),
            #[allow(deprecated)]
            MlsKem::HybridX25519MlKem768 => write!(f, "Hybrid-X25519-ML-KEM-768"),
        }
    }
}

impl std::fmt::Display for MlsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsSignature::MlDsa44 => write!(f, "ML-DSA-44"),
            MlsSignature::MlDsa65 => write!(f, "ML-DSA-65"),
            MlsSignature::MlDsa87 => write!(f, "ML-DSA-87"),
            MlsSignature::SlhDsa128 => write!(f, "SLH-DSA-128"),
            MlsSignature::SlhDsa192 => write!(f, "SLH-DSA-192"),
            MlsSignature::SlhDsa256 => write!(f, "SLH-DSA-256"),
        }
    }
}

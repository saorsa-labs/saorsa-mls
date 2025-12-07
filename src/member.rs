//! Member identity and key management for MLS groups

use crate::{
    crypto::{CipherSuite, DebugSignature, KeyPair},
    MlsError, Result,
};
use bincode::Options;
use saorsa_pqc::api::{MlDsaSecretKey, MlKemSecretKey, SlhDsaSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Secret signature key supporting both ML-DSA and SLH-DSA
#[derive(Clone)]
enum SecretSignatureKey {
    MlDsa(MlDsaSecretKey),
    SlhDsa(SlhDsaSecretKey),
}

/// Unique identifier for a group member
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberId(pub Uuid);

impl MemberId {
    /// Generate a new random member ID
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identity information for a group member
#[derive(Serialize, Deserialize)]
pub struct MemberIdentity {
    pub id: MemberId,
    pub name: Option<String>,
    pub credential: Credential,
    pub key_package: KeyPackage,
    #[serde(skip)]
    signing_key: Option<Arc<SecretSignatureKey>>,
    #[serde(skip)]
    kem_secret: Option<Arc<MlKemSecretKey>>,
}

impl Clone for MemberIdentity {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            name: self.name.clone(),
            credential: self.credential.clone(),
            key_package: self.key_package.clone(),
            signing_key: self.signing_key.clone(),
            kem_secret: self.kem_secret.clone(),
        }
    }
}

impl PartialEq for MemberIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.name == other.name
            && self.credential == other.credential
            && self.key_package == other.key_package
    }
}

impl Eq for MemberIdentity {}

impl fmt::Debug for MemberIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberIdentity")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("credential", &self.credential)
            .field("key_package", &self.key_package)
            .finish_non_exhaustive()
    }
}

impl MemberIdentity {
    /// Create a new member identity
    pub fn generate(id: MemberId) -> Result<Self> {
        Self::generate_with_suite(id, CipherSuite::default())
    }

    /// Create a new member identity using the provided cipher suite
    pub fn generate_with_suite(id: MemberId, suite: CipherSuite) -> Result<Self> {
        let keypair = KeyPair::generate(suite);
        let signing_key = Arc::new(match &keypair.signature_key {
            crate::crypto::SignatureKey::MlDsa { secret, .. } => {
                SecretSignatureKey::MlDsa(secret.clone())
            }
            crate::crypto::SignatureKey::SlhDsa { secret, .. } => {
                SecretSignatureKey::SlhDsa(secret.clone())
            }
        });
        let kem_secret = Arc::new(keypair.kem_secret.clone());
        let credential = Credential::new_basic(id, None, &keypair, keypair.suite)?;
        let key_package = KeyPackage::new(keypair, credential.clone())?;

        Ok(Self {
            id,
            name: None,
            credential,
            key_package,
            signing_key: Some(signing_key),
            kem_secret: Some(kem_secret),
        })
    }

    /// Create a member identity with a name
    pub fn with_name(name: String) -> Result<Self> {
        let id = MemberId::generate();
        let mut identity = Self::generate(id)?;

        // Update credential with name using the existing cipher suite
        let suite = identity.key_package.cipher_suite;
        let keypair = KeyPair::generate(suite);
        let signing_key = Arc::new(match &keypair.signature_key {
            crate::crypto::SignatureKey::MlDsa { secret, .. } => {
                SecretSignatureKey::MlDsa(secret.clone())
            }
            crate::crypto::SignatureKey::SlhDsa { secret, .. } => {
                SecretSignatureKey::SlhDsa(secret.clone())
            }
        });
        let kem_secret = Arc::new(keypair.kem_secret.clone());
        identity.name = Some(name.clone());
        identity.credential = Credential::new_basic(id, Some(name), &keypair, suite)?;
        identity.key_package = KeyPackage::new(keypair, identity.credential.clone())?;
        identity.signing_key = Some(signing_key);
        identity.kem_secret = Some(kem_secret);

        Ok(identity)
    }

    /// Get the member's cipher suite
    pub fn cipher_suite(&self) -> CipherSuite {
        self.key_package.cipher_suite
    }

    /// Get a reference to the ML-DSA signing key if available (panics for SLH-DSA)
    pub fn signing_key(&self) -> Option<&MlDsaSecretKey> {
        self.signing_key.as_deref().map(|key| match key {
            SecretSignatureKey::MlDsa(k) => k,
            SecretSignatureKey::SlhDsa(_) => panic!("Called signing_key() on SLH-DSA identity"),
        })
    }

    /// Get a reference to the KEM secret if available
    pub fn kem_secret(&self) -> Option<&MlKemSecretKey> {
        self.kem_secret.as_deref()
    }

    /// Verify this identity's signature on data
    ///
    /// Supports both ML-DSA and SLH-DSA signatures.
    pub fn verify_signature(&self, data: &[u8], signature: &crate::crypto::Signature) -> bool {
        self.key_package
            .verify_signature(data, signature)
            .unwrap_or(false)
    }

    /// Sign data with this identity's signing key
    ///
    /// Supports both ML-DSA and SLH-DSA signatures based on the cipher suite.
    ///
    /// # Errors
    ///
    /// Returns error if signing key is not available or signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<crate::crypto::Signature> {
        use saorsa_pqc::api::{MlDsa, SlhDsa};

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| MlsError::InvalidGroupState("No signing key available".to_string()))?;

        match signing_key.as_ref() {
            SecretSignatureKey::MlDsa(secret) => {
                let ml_dsa = MlDsa::new(self.key_package.cipher_suite.ml_dsa_variant());
                let signature = ml_dsa
                    .sign(secret, data)
                    .map_err(|e| MlsError::CryptoError(format!("ML-DSA signing failed: {e:?}")))?;
                Ok(crate::crypto::Signature::MlDsa(signature))
            }
            SecretSignatureKey::SlhDsa(secret) => {
                let slh_dsa = SlhDsa::new(self.key_package.cipher_suite.slh_dsa_variant());
                let signature = slh_dsa
                    .sign(secret, data)
                    .map_err(|e| MlsError::CryptoError(format!("SLH-DSA signing failed: {e:?}")))?;
                Ok(crate::crypto::Signature::SlhDsa(signature))
            }
        }
    }

    /// Get the member's public key bytes
    pub fn verifying_key_bytes(&self) -> &[u8] {
        &self.key_package.verifying_key
    }
}

/// Member credential type
///
/// Per RFC 9420, MLS supports multiple credential types. This implementation
/// uses Basic credentials with ML-DSA signatures, which is sufficient for
/// post-quantum MLS and matches SPEC-PROD.md requirements.
///
/// X.509 certificates are optional per RFC 9420 and not required for this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    /// Basic credential with ML-DSA identity binding
    Basic = 1,
}

/// Member credential with PQC signature (ML-DSA or SLH-DSA)
///
/// Implements Basic credential type from RFC 9420 with post-quantum signatures.
/// The credential binds a member's identity to their public key through a signature
/// over the identity data, which includes the public key itself for security.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Credential {
    /// Basic credential with PQC signed identity
    Basic {
        credential_type: CredentialType,
        identity: Vec<u8>,
        signature: DebugSignature,
    },
}

impl Credential {
    /// Create a new basic credential
    pub fn new_basic(
        member_id: MemberId,
        name: Option<String>,
        keypair: &KeyPair,
        suite: CipherSuite,
    ) -> Result<Self> {
        // Canonicalized identity for signing
        let mut identity = Vec::new();
        identity.extend_from_slice(b"MLS 1.0 Credential");
        identity.extend_from_slice(member_id.as_bytes());

        if let Some(ref name) = name {
            identity.extend_from_slice(name.as_bytes());
        }

        // Add cipher suite information
        let suite_bytes = bincode::DefaultOptions::new()
            .serialize(&suite)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        identity.extend_from_slice(&suite_bytes);

        // SECURITY FIX: Include public key in signed data to bind credential to specific keypair
        // This prevents signature from being valid with a different public key
        identity.extend_from_slice(&keypair.verifying_key_bytes());

        let signature = keypair.sign(&identity)?;

        Ok(Self::Basic {
            credential_type: CredentialType::Basic,
            identity,
            signature: DebugSignature(signature),
        })
    }

    /// Get the credential type (always Basic in this implementation)
    pub fn credential_type(&self) -> CredentialType {
        match self {
            Self::Basic {
                credential_type, ..
            } => *credential_type,
        }
    }

    /// Verify the credential is valid
    ///
    /// Verifies that the PQC signature was created by the private key corresponding
    /// to the provided keypair's public key. The signature covers the identity data which includes
    /// the public key itself, binding the credential to that specific key.
    ///
    /// Security property: Prevents credential forgery by ensuring the public key in the
    /// credential matches the verifying key and that the signature is valid.
    pub fn verify(&self, keypair: &KeyPair) -> bool {
        match self {
            Self::Basic {
                identity,
                signature,
                ..
            } => {
                // Verify that:
                // 1. The provided public key matches the one in the identity data
                // 2. The PQC signature is valid for the identity data

                let key_bytes = keypair.verifying_key_bytes();
                let key_len = key_bytes.len();

                // Identity should end with the public key
                if identity.len() < key_len {
                    return false;
                }

                let identity_key = &identity[identity.len() - key_len..];
                if identity_key != key_bytes.as_slice() {
                    // Public key mismatch - credential not bound to this key
                    return false;
                }

                // Verify PQC signature using the keypair
                keypair.verify(identity, &signature.0)
            }
        }
    }
}

/// Key package containing public keys and credentials
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackage {
    /// Protocol version
    pub version: u16,
    /// Cipher suite for this key package
    pub cipher_suite: CipherSuite,
    /// Public key for message signing (serialized as bytes)
    pub verifying_key: Vec<u8>,
    /// Public key for key agreement (serialized as bytes)
    pub agreement_key: Vec<u8>,
    /// Member credential
    pub credential: Credential,
    /// Extensions (reserved for future use)
    pub extensions: Vec<Extension>,
    /// Signature over the key package
    pub signature: DebugSignature,
}

impl KeyPackage {
    /// Create a new key package
    pub fn new(keypair: KeyPair, credential: Credential) -> Result<Self> {
        // Verify the credential against the provided keypair
        if !credential.verify(&keypair) {
            return Err(MlsError::InvalidGroupState(
                "invalid credential signature".to_string(),
            ));
        }

        let mut package = Self {
            version: 1,
            cipher_suite: keypair.suite,
            verifying_key: keypair.verifying_key_bytes(),
            agreement_key: keypair.public_key().to_bytes().to_vec(),
            credential,
            extensions: Vec::new(),
            signature: DebugSignature(keypair.sign(&[])?), // Placeholder, will be replaced
        };

        // Sign the key package
        let tbs = package.to_be_signed()?;
        package.signature = DebugSignature(keypair.sign(&tbs)?);

        Ok(package)
    }

    /// Verify a signature against this key package's public key
    ///
    /// Supports both ML-DSA and SLH-DSA signatures through unified Signature enum.
    ///
    /// # Errors
    ///
    /// Returns error if public key parsing or signature verification fails.
    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &crate::crypto::Signature,
    ) -> Result<bool> {
        match signature {
            crate::crypto::Signature::MlDsa(sig) => {
                use saorsa_pqc::api::{MlDsa, MlDsaPublicKey};

                let ml_dsa = MlDsa::new(self.cipher_suite.ml_dsa_variant());
                let public_key = MlDsaPublicKey::from_bytes(
                    self.cipher_suite.ml_dsa_variant(),
                    &self.verifying_key,
                )
                .map_err(|e| MlsError::CryptoError(format!("Invalid ML-DSA public key: {e:?}")))?;

                ml_dsa.verify(&public_key, data, sig).map_err(|e| {
                    MlsError::CryptoError(format!("ML-DSA verification failed: {e:?}"))
                })
            }
            crate::crypto::Signature::SlhDsa(sig) => {
                use saorsa_pqc::api::{SlhDsa, SlhDsaPublicKey};

                let slh_dsa = SlhDsa::new(self.cipher_suite.slh_dsa_variant());
                let public_key = SlhDsaPublicKey::from_bytes(
                    self.cipher_suite.slh_dsa_variant(),
                    &self.verifying_key,
                )
                .map_err(|e| MlsError::CryptoError(format!("Invalid SLH-DSA public key: {e:?}")))?;

                slh_dsa.verify(&public_key, data, sig).map_err(|e| {
                    MlsError::CryptoError(format!("SLH-DSA verification failed: {e:?}"))
                })
            }
        }
    }

    /// Verify the key package is self-consistent
    ///
    /// Verifies that the signature over the key package data is valid.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or verification fails.
    pub fn verify(&self) -> Result<bool> {
        let tbs = self.to_be_signed()?;
        self.verify_signature(&tbs, &self.signature.0)
    }

    /// Get the data to be signed for this key package
    fn to_be_signed(&self) -> Result<Vec<u8>> {
        // Simplified serialization for signing
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_be_bytes());

        let suite_bytes = bincode::DefaultOptions::new()
            .serialize(&self.cipher_suite)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&suite_bytes);

        // Include public keys
        data.extend_from_slice(&self.verifying_key);
        data.extend_from_slice(&self.agreement_key);

        // Include credential
        let cred_bytes = bincode::DefaultOptions::new()
            .serialize(&self.credential)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&cred_bytes);

        Ok(data)
    }
}

/// Extension types for key packages and messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Extension {
    /// Application-specific extension
    ApplicationId(Vec<u8>),
    /// Ratchet tree extension
    RatchetTree(Vec<u8>),
    /// External public key
    ExternalPub(Vec<u8>),
    /// External senders
    ExternalSenders(Vec<u8>),
}

/// Collection of member identities in a group
#[derive(Debug, Clone)]
pub struct MemberList {
    members: HashMap<MemberId, MemberIdentity>,
}

impl MemberList {
    /// Create a new empty member list
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    /// Add a member to the list
    pub fn add(&mut self, member: MemberIdentity) {
        self.members.insert(member.id, member);
    }

    /// Remove a member from the list
    pub fn remove(&mut self, id: &MemberId) -> Option<MemberIdentity> {
        self.members.remove(id)
    }

    /// Get a member by ID
    pub fn get(&self, id: &MemberId) -> Option<&MemberIdentity> {
        self.members.get(id)
    }

    /// Get a mutable reference to a member
    pub fn get_mut(&mut self, id: &MemberId) -> Option<&mut MemberIdentity> {
        self.members.get_mut(id)
    }

    /// Check if a member exists
    pub fn contains(&self, id: &MemberId) -> bool {
        self.members.contains_key(id)
    }

    /// Get the number of members
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Iterate over all members
    pub fn iter(&self) -> impl Iterator<Item = (&MemberId, &MemberIdentity)> {
        self.members.iter()
    }

    /// Get all member IDs
    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members.keys().copied().collect()
    }
}

impl Default for MemberList {
    fn default() -> Self {
        Self::new()
    }
}

/// Member state in the group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberState {
    /// Member identity
    pub identity: MemberIdentity,
    /// Leaf index in the ratchet tree
    pub leaf_index: usize,
    /// Generation for epoch tracking
    pub generation: u32,
    /// Last update time
    pub last_update: u64,
}

impl MemberState {
    /// Create a new member state
    pub fn new(identity: MemberIdentity, leaf_index: usize) -> Self {
        Self {
            identity,
            leaf_index,
            generation: 0,
            last_update: 0,
        }
    }

    /// Update the generation counter
    pub fn increment_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

/// Lifetime bounds for credentials and key packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifetimeExtension {
    /// Not valid before timestamp
    pub not_before: u64,
    /// Not valid after timestamp
    pub not_after: u64,
}

impl LifetimeExtension {
    /// Create a new lifetime extension valid for the specified duration
    pub fn new(duration: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            not_before: now,
            not_after: now + duration.as_secs(),
        }
    }

    /// Check if the lifetime is currently valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now >= self.not_before && now <= self.not_after
    }
}

/// Represents a member in an MLS group
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's unique identity
    pub identity: MemberIdentity,
    /// Member's index in the group
    pub index: u32,
    /// Whether the member is active
    pub active: bool,
    /// Schema version for forward compatibility
    pub schema_version: u8,
}

impl GroupMember {
    /// Create a new group member
    pub fn new(identity: MemberIdentity, index: u32) -> Self {
        Self {
            identity,
            index,
            active: true,
            schema_version: 1,
        }
    }

    /// Mark member as inactive
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Check if member is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get member index
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get member identity
    pub fn identity(&self) -> &MemberIdentity {
        &self.identity
    }
}

/// Registry for managing group members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRegistry {
    /// Members by their index
    members: HashMap<u32, GroupMember>,
    /// Next available index
    next_index: u32,
    /// Schema version for forward compatibility
    pub schema_version: u8,
}

impl MemberRegistry {
    /// Create a new member registry
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            next_index: 0,
            schema_version: 1,
        }
    }

    /// Add a new member to the registry
    pub fn add_member(&mut self, identity: MemberIdentity) -> Result<u32> {
        let index = self.next_index;
        let member = GroupMember::new(identity, index);

        if self.members.insert(index, member).is_some() {
            return Err(MlsError::InvalidGroupState(format!(
                "Member index {} already exists",
                index
            )));
        }

        self.next_index += 1;
        Ok(index)
    }

    /// Remove a member from the registry
    pub fn remove_member(&mut self, index: u32) -> Result<GroupMember> {
        self.members.remove(&index).ok_or_else(|| {
            // Create a dummy MemberId for the error - this is just for error reporting
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes[0..4].copy_from_slice(&index.to_be_bytes());
            MlsError::MemberNotFound(MemberId::from_bytes(uuid_bytes))
        })
    }

    /// Get a member by index
    pub fn get_member(&self, index: u32) -> Option<&GroupMember> {
        self.members.get(&index)
    }

    /// Get a mutable reference to a member
    pub fn get_member_mut(&mut self, index: u32) -> Option<&mut GroupMember> {
        self.members.get_mut(&index)
    }

    /// Get all active members
    pub fn active_members(&self) -> impl Iterator<Item = &GroupMember> {
        self.members.values().filter(|m| m.is_active())
    }

    /// Get total number of members (including inactive)
    pub fn total_members(&self) -> usize {
        self.members.len()
    }

    /// Get number of active members
    pub fn active_member_count(&self) -> usize {
        self.members.values().filter(|m| m.is_active()).count()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Get all member indices
    pub fn member_indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.members.keys().copied()
    }

    /// Find member index by MemberId
    pub fn find_member_index(&self, member_id: &MemberId) -> Option<u32> {
        self.members
            .iter()
            .find(|(_, member)| member.identity.id == *member_id)
            .map(|(index, _)| *index)
    }
}

impl Default for MemberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Trust store for managing trusted public keys
///
/// For Basic credentials with ML-DSA signatures, the trust store maintains
/// trusted ML-DSA public keys. This is simpler than X.509 PKI and sufficient
/// for post-quantum MLS per RFC 9420.
///
/// Note: X.509 certificate chain validation is optional per RFC 9420 and not
/// implemented in this library.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    /// Trusted ML-DSA public keys (identity anchors)
    pub trusted_keys: Vec<Vec<u8>>,
}

impl TrustStore {
    /// Create a new empty trust store
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted ML-DSA public key to the trust store
    pub fn add_trusted_key(&mut self, public_key: Vec<u8>) {
        self.trusted_keys.push(public_key);
    }

    /// Remove a trusted key by exact match
    pub fn remove_trusted_key(&mut self, public_key: &[u8]) {
        self.trusted_keys.retain(|key| key.as_slice() != public_key);
    }

    /// Get number of trusted keys
    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    /// Check if a public key is trusted
    pub fn is_trusted(&self, public_key: &[u8]) -> bool {
        self.trusted_keys
            .iter()
            .any(|key| key.as_slice() == public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_member_id_generation() {
        let id1 = MemberId::generate();
        let id2 = MemberId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_member_identity_creation() {
        let identity = MemberIdentity::generate(MemberId::generate()).unwrap();
        assert!(identity.name.is_none());
        assert_eq!(identity.cipher_suite(), CipherSuite::default());
    }

    #[test]
    fn test_member_identity_with_name() {
        let name = "Alice".to_string();
        let identity = MemberIdentity::with_name(name.clone()).unwrap();
        assert_eq!(identity.name, Some(name));
    }

    #[test]
    fn test_member_list_operations() {
        let mut list = MemberList::new();
        assert!(list.is_empty());

        let id = MemberId::generate();
        let member = MemberIdentity::generate(id).unwrap();
        list.add(member.clone());

        assert_eq!(list.len(), 1);
        assert!(list.contains(&id));
        assert!(list.get(&id).is_some());

        list.remove(&id);
        assert!(list.is_empty());
    }

    #[test]
    fn test_credential_verification() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential = Credential::new_basic(
            MemberId::generate(),
            Some("Test".to_string()),
            &keypair,
            keypair.suite,
        )
        .unwrap();

        assert!(credential.verify(&keypair));
    }

    #[test]
    fn test_key_package_creation_and_verification() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential =
            Credential::new_basic(MemberId::generate(), None, &keypair, keypair.suite).unwrap();
        let key_package = KeyPackage::new(keypair, credential).unwrap();

        assert!(key_package.verify().unwrap());
    }

    #[test]
    fn test_member_state() {
        let identity = MemberIdentity::generate(MemberId::generate()).unwrap();
        let mut state = MemberState::new(identity, 0);

        assert_eq!(state.generation, 0);
        state.increment_generation();
        assert_eq!(state.generation, 1);
    }

    #[test]
    fn test_extension_serialization() {
        let ext = Extension::ApplicationId(vec![1, 2, 3]);
        let serialized = bincode::DefaultOptions::new().serialize(&ext).unwrap();
        let deserialized: Extension = bincode::DefaultOptions::new()
            .deserialize(&serialized)
            .unwrap();

        match deserialized {
            Extension::ApplicationId(data) => assert_eq!(data, vec![1, 2, 3]),
            _ => panic!("Wrong extension type"),
        }
    }

    #[test]
    fn test_lifetime_extension() {
        let lifetime = LifetimeExtension::new(Duration::from_secs(3600));
        assert!(lifetime.is_valid());

        // Test expired lifetime
        let expired = LifetimeExtension {
            not_before: 0,
            not_after: 1,
        };
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_member_identity_update_name() {
        let identity1 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let identity2 = MemberIdentity::with_name("Bob".to_string()).unwrap();

        assert!(identity1.name.is_none());
        assert_eq!(identity2.name, Some("Bob".to_string()));

        // Verify keys are different between identities
        assert_ne!(
            identity1.key_package.verifying_key,
            identity2.key_package.verifying_key
        );
    }

    #[test]
    fn test_member_list_iteration() {
        let mut list = MemberList::new();
        let id1 = MemberId::generate();
        let id2 = MemberId::generate();

        list.add(MemberIdentity::generate(id1).unwrap());
        list.add(MemberIdentity::generate(id2).unwrap());

        let member_ids_list: Vec<MemberId> = list.member_ids();
        assert_eq!(member_ids_list.len(), 2);
        assert!(member_ids_list.contains(&id1));
        assert!(member_ids_list.contains(&id2));
    }
}

//! MLS protocol messages and state machine

use crate::{
    crypto::{AeadCipher, CipherSuite, CipherSuiteId, DebugMlDsaSignature, Hash},
    member::*,
    EpochNumber, MessageSequence, MlsError, Result,
};
// postcard serialization (bincode removed)
use saorsa_pqc::api::{
    MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlKem, MlKemCiphertext, MlKemSecretKey,
};
use serde::{Deserialize, Serialize};

/// MLS message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlsMessage {
    /// Handshake message for group operations
    Handshake(HandshakeMessage),
    /// Application message with encrypted content
    Application(ApplicationMessage),
    /// Welcome message for new members
    Welcome(WelcomeMessage),
}

impl MlsMessage {
    /// Get the epoch number for this message
    pub fn epoch(&self) -> EpochNumber {
        match self {
            Self::Handshake(msg) => msg.epoch,
            Self::Application(msg) => msg.epoch,
            Self::Welcome(msg) => msg.epoch,
        }
    }

    /// Get the sender of this message
    pub fn sender(&self) -> MemberId {
        match self {
            Self::Handshake(msg) => msg.sender,
            Self::Application(msg) => msg.sender,
            Self::Welcome(msg) => msg.sender,
        }
    }

    /// Verify the message signature
    pub fn verify_signature(
        &self,
        verifying_key: &MlDsaPublicKey,
        suite: CipherSuite,
    ) -> Result<bool> {
        let (data, signature, suite_for_message) = match self {
            Self::Handshake(msg) => (&msg.content, &msg.signature.0, suite),
            Self::Application(msg) => (&msg.ciphertext, &msg.signature.0, suite),
            Self::Welcome(msg) => (&msg.group_info, &msg.signature.0, msg.cipher_suite),
        };

        let ml_dsa = MlDsa::new(suite_for_message.ml_dsa_variant());
        ml_dsa
            .verify(verifying_key, data, signature)
            .map_err(|e| MlsError::InvalidMessage(format!("invalid signature: {e:?}")))
    }
}

/// Handshake message content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeContent {
    /// Add a new member to the group
    Add(AddProposal),
    /// Remove a member from the group
    Remove(RemoveProposal),
    /// Update member's key material
    Update(UpdateProposal),
    /// Commit pending proposals
    Commit(CommitMessage),
}

/// Handshake message for group operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub content: Vec<u8>,
    pub signature: DebugMlDsaSignature,
}

impl HandshakeMessage {
    /// Create a signed handshake message for the given content
    pub fn new_signed(
        epoch: EpochNumber,
        sender: MemberId,
        content: Vec<u8>,
        signing_key: &MlDsaSecretKey,
        suite: CipherSuite,
    ) -> Result<Self> {
        let ml_dsa = MlDsa::new(suite.ml_dsa_variant());
        let signature = ml_dsa
            .sign(signing_key, &content)
            .map_err(|e| MlsError::CryptoError(format!("Signing failed: {e:?}")))?;

        Ok(Self {
            epoch,
            sender,
            content,
            signature: DebugMlDsaSignature(signature),
        })
    }

    /// Verify the handshake message signature using the provided suite
    pub fn verify_signature(
        &self,
        verifying_key: &MlDsaPublicKey,
        suite: CipherSuite,
    ) -> Result<bool> {
        let ml_dsa = MlDsa::new(suite.ml_dsa_variant());
        ml_dsa
            .verify(verifying_key, &self.content, &self.signature.0)
            .map_err(|e| MlsError::InvalidMessage(format!("invalid signature: {e:?}")))
    }
}

/// Application message with encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMessage {
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub generation: u32,
    pub sequence: MessageSequence,
    pub ciphertext: Vec<u8>,
    pub signature: DebugMlDsaSignature,
}

/// Welcome message for new members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMessage {
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub cipher_suite: CipherSuite,
    pub group_info: Vec<u8>,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub signature: DebugMlDsaSignature,
}

/// Proposal to add a new member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

/// Proposal to remove a member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveProposal {
    pub removed: MemberId,
}

/// Proposal to update member's keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProposal {
    pub key_package: KeyPackage,
    pub signature: DebugMlDsaSignature,
}

/// Commit message containing proposals and path updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMessage {
    pub proposals: Vec<ProposalRef>,
    pub path: Option<UpdatePath>,
}

/// Reference to a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalRef {
    /// Reference to a proposal by hash
    Reference(Vec<u8>),
    /// Inline proposal
    Inline(ProposalContent),
}

/// Proposal content wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalContent {
    Add(AddProposal),
    Remove(RemoveProposal),
    Update(UpdateProposal),
}

/// Update path for tree operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

/// Node in an update path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub public_key: Vec<u8>,
    pub encrypted_path_secret: Vec<EncryptedPathSecret>,
}

/// Encrypted group secrets for welcome messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGroupSecrets {
    pub recipient_key_package_hash: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_path_secret: Vec<u8>,
}

/// Message framing with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFrame {
    pub schema_version: u8,
    pub message_type: MessageType,
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub authenticated_data: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: DebugMlDsaSignature,
}

/// Message types in the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Handshake = 1,
    Application = 2,
    Welcome = 3,
    GroupInfo = 4,
    KeyPackage = 5,
}

/// Group information for synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: Vec<u8>,
    pub epoch: EpochNumber,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Vec<u8>,
    pub signer: MemberId,
}

/// Tree structure for key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeKemState {
    pub nodes: Vec<TreeNode>,
    pub epoch: EpochNumber,
}

/// Node in the TreeKEM structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeNode {
    Leaf(LeafNode),
    Parent(ParentNode),
}

/// Leaf node containing member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    pub key_package: Option<KeyPackage>,
    pub unmerged_leaves: Vec<MemberId>,
}

/// Parent node in the tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    pub public_key: Option<Vec<u8>>,
    pub unmerged_leaves: Vec<MemberId>,
}

/// Encrypted path secret for tree operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPathSecret {
    /// Recipient of this encrypted secret
    pub recipient: MemberId,
    /// Encrypted path secret using ML-KEM (serialized as bytes)
    pub ciphertext: Vec<u8>,
}

/// Protocol constants
pub mod constants {
    /// Maximum group size
    pub const MAX_GROUP_SIZE: usize = 1000;
    /// Maximum message size in bytes
    pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB
    /// Default epoch lifetime in seconds
    pub const EPOCH_LIFETIME: u64 = 86400; // 24 hours
}

/// Validation functions for protocol messages
impl HandshakeMessage {
    /// Validate the handshake message
    pub fn validate(&self) -> Result<()> {
        if self.content.is_empty() {
            return Err(MlsError::InvalidMessage(
                "Empty handshake content".to_string(),
            ));
        }
        if self.content.len() > constants::MAX_MESSAGE_SIZE {
            return Err(MlsError::InvalidMessage("Message too large".to_string()));
        }
        Ok(())
    }
}

impl ApplicationMessage {
    /// Validate the application message
    pub fn validate(&self) -> Result<()> {
        if self.ciphertext.is_empty() {
            return Err(MlsError::InvalidMessage("Empty ciphertext".to_string()));
        }
        if self.ciphertext.len() > constants::MAX_MESSAGE_SIZE {
            return Err(MlsError::InvalidMessage("Message too large".to_string()));
        }
        Ok(())
    }
}

impl WelcomeMessage {
    /// Validate the welcome message
    pub fn validate(&self) -> Result<()> {
        if self.group_info.is_empty() {
            return Err(MlsError::InvalidMessage("Empty group info".to_string()));
        }
        if self.secrets.is_empty() {
            return Err(MlsError::InvalidMessage("No encrypted secrets".to_string()));
        }
        Ok(())
    }

    /// Verify the welcome message signature against the creator's public key
    pub fn verify_signature(&self, verifying_key: &MlDsaPublicKey) -> Result<bool> {
        let ml_dsa = MlDsa::new(self.cipher_suite.ml_dsa_variant());
        ml_dsa
            .verify(verifying_key, &self.group_info, &self.signature.0)
            .map_err(|e| MlsError::InvalidMessage(format!("invalid signature: {e:?}")))
    }
}

impl EncryptedGroupSecrets {
    /// Return the ML-KEM ciphertext for this recipient
    pub fn ciphertext(&self, suite: &CipherSuite) -> Result<MlKemCiphertext> {
        MlKemCiphertext::from_bytes(suite.ml_kem_variant(), &self.kem_ciphertext)
            .map_err(|e| MlsError::CryptoError(format!("Invalid ML-KEM ciphertext: {e:?}")))
    }

    fn hkdf_expand(shared_secret_bytes: &[u8], label: &[u8], length: usize) -> Result<Vec<u8>> {
        use saorsa_pqc::api::{kdf::HkdfSha3_256, traits::Kdf};

        let mut output = vec![0u8; length];
        HkdfSha3_256::derive(shared_secret_bytes, None, label, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("HKDF error: {e:?}")))?;
        Ok(output)
    }

    fn encrypt_application_secret(
        suite: CipherSuite,
        shared_secret_bytes: &[u8],
        application_secret: &[u8],
    ) -> Result<Vec<u8>> {
        let key = Self::hkdf_expand(shared_secret_bytes, b"saorsa aead key", suite.key_size())?;
        let nonce = Self::hkdf_expand(
            shared_secret_bytes,
            b"saorsa aead nonce",
            suite.nonce_size(),
        )?;
        let cipher = AeadCipher::new(key, suite)?;
        cipher
            .encrypt(&nonce, application_secret, &[])
            .map_err(|e| MlsError::CryptoError(format!("Path secret encrypt failed: {e:?}")))
    }

    fn decapsulate_shared_bytes(
        &self,
        suite: &CipherSuite,
        kem_secret: &MlKemSecretKey,
    ) -> Result<Vec<u8>> {
        let ciphertext = self.ciphertext(suite)?;
        let ml_kem = MlKem::new(suite.ml_kem_variant());
        let shared = ml_kem
            .decapsulate(kem_secret, &ciphertext)
            .map_err(|e| MlsError::CryptoError(format!("Decapsulation failed: {e:?}")))?;
        Ok(shared.to_bytes().to_vec())
    }

    /// Decapsulate the path secret using the recipient's private key
    pub fn decapsulate_path_secret(
        &self,
        suite: &CipherSuite,
        kem_secret: &MlKemSecretKey,
    ) -> Result<Vec<u8>> {
        let shared_bytes = self.decapsulate_shared_bytes(suite, kem_secret)?;
        let key = Self::hkdf_expand(&shared_bytes, b"saorsa aead key", suite.key_size())?;
        let expected_nonce =
            Self::hkdf_expand(&shared_bytes, b"saorsa aead nonce", suite.nonce_size())?;

        if self.encrypted_path_secret.len() < suite.nonce_size() {
            return Err(MlsError::InvalidMessage(
                "Invalid encrypted path secret".to_string(),
            ));
        }

        let stored_nonce = &self.encrypted_path_secret[..suite.nonce_size()];

        if stored_nonce != expected_nonce.as_slice() {
            return Err(MlsError::InvalidMessage(
                "Encrypted path secret nonce mismatch".to_string(),
            ));
        }

        let cipher = AeadCipher::new(key, *suite)?;
        cipher
            .decrypt(&expected_nonce, &self.encrypted_path_secret, &[])
            .map_err(|e| MlsError::CryptoError(format!("Path secret decrypt failed: {e:?}")))
    }

    pub(crate) fn encrypt_for_recipient(
        suite: CipherSuite,
        shared_secret_bytes: &[u8],
        application_secret: &[u8],
    ) -> Result<Vec<u8>> {
        Self::encrypt_application_secret(suite, shared_secret_bytes, application_secret)
    }
}

/// State machine for protocol message processing
#[derive(Debug, Clone)]
pub struct ProtocolSessionState {
    pub epoch: EpochNumber,
    pub pending_proposals: Vec<ProposalContent>,
    pub confirmed_transcript_hash: Vec<u8>,
}

impl ProtocolSessionState {
    /// Create a new protocol state
    pub fn new(epoch: EpochNumber) -> Self {
        Self {
            epoch,
            pending_proposals: Vec::new(),
            confirmed_transcript_hash: Vec::new(),
        }
    }

    /// Add a proposal to pending list
    pub fn add_proposal(&mut self, proposal: ProposalContent) {
        self.pending_proposals.push(proposal);
    }

    /// Clear pending proposals after commit
    pub fn clear_proposals(&mut self) {
        self.pending_proposals.clear();
    }

    /// Update transcript hash
    pub fn update_transcript(&mut self, data: &[u8]) {
        let hasher = Hash::new(CipherSuite::default());
        let mut input = self.confirmed_transcript_hash.clone();
        input.extend_from_slice(data);
        self.confirmed_transcript_hash = hasher.hash(&input);
    }
}

/// Serialization helpers
impl MlsMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self).map_err(|e| MlsError::SerializationError(e.to_string()))
    }

    /// Deserialize message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data).map_err(|e| MlsError::DeserializationError(e.to_string()))
    }
}

/// Configuration for an MLS group
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupConfig {
    /// Protocol version
    pub protocol_version: u16,
    /// Cipher suite identifier
    pub cipher_suite: crate::crypto::CipherSuiteId,
    /// Maximum number of members
    pub max_members: Option<u32>,
    /// Group lifetime in seconds
    pub lifetime: Option<u64>,
    /// Maximum epoch age in milliseconds (SPEC-2 §3: default 24 hours)
    pub max_epoch_age_millis: u64,
    /// Maximum messages per epoch (SPEC-2 §3: default 10,000)
    pub max_messages_per_epoch: u64,
    /// Schema version for forward compatibility
    pub schema_version: u8,
}

impl GroupConfig {
    /// Create a new group configuration
    pub fn new(protocol_version: u16, cipher_suite: CipherSuiteId) -> Self {
        Self {
            protocol_version,
            cipher_suite,
            max_members: None,
            lifetime: None,
            max_epoch_age_millis: 24 * 3600 * 1000, // 24 hours in milliseconds per SPEC-2 §3
            max_messages_per_epoch: 10_000,         // 10,000 messages per SPEC-2 §3
            schema_version: 1,
        }
    }

    /// Set cipher suite identifier
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuiteId) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    /// Set maximum number of members
    pub fn with_max_members(mut self, max_members: u32) -> Self {
        self.max_members = Some(max_members);
        self
    }

    /// Set group lifetime
    pub fn with_lifetime(mut self, lifetime: u64) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Set maximum epoch age (SPEC-2 §3 requirement)
    pub fn with_max_epoch_age(mut self, duration: std::time::Duration) -> Self {
        self.max_epoch_age_millis = duration.as_millis() as u64;
        self
    }

    /// Set maximum messages per epoch (SPEC-2 §3 requirement)
    pub fn with_max_messages_per_epoch(mut self, count: u64) -> Self {
        self.max_messages_per_epoch = count;
        self
    }

    /// Get maximum epoch age as Duration
    pub fn max_epoch_age(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.max_epoch_age_millis)
    }

    /// Get maximum messages per epoch
    pub fn max_messages_per_epoch(&self) -> u64 {
        self.max_messages_per_epoch
    }
}

impl Default for GroupConfig {
    fn default() -> Self {
        // SPEC-2 default: ChaCha20Poly1305 + SHA256 + ML-DSA-65 (0x0B01)
        Self::new(
            1,
            CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
        )
    }
}

/// Unique identifier for an MLS group
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(Vec<u8>);

impl GroupId {
    /// Create a new group ID from bytes
    pub fn new(id: Vec<u8>) -> Self {
        Self(id)
    }

    /// Generate a random group ID
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut id = vec![0u8; 32];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }

    /// Get the group ID as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to bytes vector
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for GroupId {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for GroupId {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl AsRef<[u8]> for GroupId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// State machine for managing MLS protocol state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStateMachine {
    /// Current epoch number
    pub epoch: u64,
    /// Current state
    pub state: ProtocolState,
    /// Schema version for forward compatibility
    pub schema_version: u8,
}

/// Protocol states
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolState {
    /// Initial state before group creation
    Initial,
    /// Group is being created
    Creating,
    /// Group is active and operational
    Active,
    /// Group is being updated
    Updating,
    /// Group has been terminated
    Terminated,
}

impl ProtocolStateMachine {
    /// Create a new protocol state machine
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            state: ProtocolState::Initial,
            schema_version: 1,
        }
    }

    /// Transition to creating state
    pub fn start_creation(&mut self) -> Result<()> {
        match self.state {
            ProtocolState::Initial => {
                self.state = ProtocolState::Creating;
                Ok(())
            }
            _ => Err(MlsError::InvalidGroupState(format!(
                "Cannot start creation from state {:?}",
                self.state
            ))),
        }
    }

    /// Transition to active state
    pub fn activate(&mut self) -> Result<()> {
        match self.state {
            ProtocolState::Creating => {
                self.state = ProtocolState::Active;
                Ok(())
            }
            _ => Err(MlsError::InvalidGroupState(format!(
                "Cannot activate from state {:?}",
                self.state
            ))),
        }
    }

    /// Start an update operation
    pub fn start_update(&mut self) -> Result<()> {
        match self.state {
            ProtocolState::Active => {
                self.state = ProtocolState::Updating;
                Ok(())
            }
            _ => Err(MlsError::InvalidGroupState(format!(
                "Cannot start update from state {:?}",
                self.state
            ))),
        }
    }

    /// Complete an update operation
    pub fn complete_update(&mut self) -> Result<()> {
        match self.state {
            ProtocolState::Updating => {
                self.state = ProtocolState::Active;
                self.epoch += 1;
                Ok(())
            }
            _ => Err(MlsError::InvalidGroupState(format!(
                "Cannot complete update from state {:?}",
                self.state
            ))),
        }
    }

    /// Terminate the group
    pub fn terminate(&mut self) -> Result<()> {
        if matches!(self.state, ProtocolState::Terminated) {
            return Err(MlsError::InvalidGroupState(
                "Group is already terminated".to_string(),
            ));
        }

        self.state = ProtocolState::Terminated;
        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> &ProtocolState {
        &self.state
    }

    /// Get current epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Check if group is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, ProtocolState::Active)
    }

    /// Check if group is terminated
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, ProtocolState::Terminated)
    }

    /// Set the epoch number (internal use)
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_message_serialization() {
        let msg = HandshakeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            content: vec![1, 2, 3],
            signature: create_test_signature(),
        };

        let mls_msg = MlsMessage::Handshake(msg);
        let bytes = mls_msg.to_bytes().unwrap();
        let decoded = MlsMessage::from_bytes(&bytes).unwrap();

        assert_eq!(mls_msg.epoch(), decoded.epoch());
        assert_eq!(mls_msg.sender(), decoded.sender());
    }

    #[test]
    fn test_handshake_validation() {
        let valid = HandshakeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            content: vec![1, 2, 3],
            signature: create_test_signature(),
        };
        assert!(valid.validate().is_ok());

        let empty = HandshakeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            content: vec![],
            signature: create_test_signature(),
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn test_protocol_state() {
        let mut state = ProtocolSessionState::new(0);
        assert!(state.pending_proposals.is_empty());

        let proposal = ProposalContent::Remove(RemoveProposal {
            removed: MemberId::generate(),
        });
        state.add_proposal(proposal);
        assert_eq!(state.pending_proposals.len(), 1);

        state.clear_proposals();
        assert!(state.pending_proposals.is_empty());
    }

    #[test]
    fn test_tree_node_types() {
        let leaf = TreeNode::Leaf(LeafNode {
            key_package: None,
            unmerged_leaves: vec![],
        });

        let parent = TreeNode::Parent(ParentNode {
            public_key: None,
            unmerged_leaves: vec![],
        });

        match leaf {
            TreeNode::Leaf(_) => (),
            TreeNode::Parent(_) => panic!("Expected leaf node"),
        }

        match parent {
            TreeNode::Parent(_) => (),
            TreeNode::Leaf(_) => panic!("Expected parent node"),
        }
    }

    #[test]
    fn test_message_type_equality() {
        assert_eq!(MessageType::Handshake, MessageType::Handshake);
        assert_ne!(MessageType::Handshake, MessageType::Application);
    }

    #[test]
    fn test_group_info_serialization() {
        let info = GroupInfo {
            group_id: vec![1, 2, 3],
            epoch: 42,
            tree_hash: vec![4, 5, 6],
            confirmed_transcript_hash: vec![7, 8, 9],
            extensions: vec![],
            confirmation_tag: vec![10, 11, 12],
            signer: MemberId::generate(),
        };

        let bytes = postcard::to_stdvec(&info).unwrap();
        let decoded: GroupInfo = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(info.group_id, decoded.group_id);
        assert_eq!(info.epoch, decoded.epoch);
    }

    #[test]
    fn test_update_path_construction() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let member_id = MemberId::generate();
        let cred = Credential::new_basic(member_id, None, &keypair, keypair.suite).unwrap();
        let key_package = KeyPackage::new(keypair, cred).unwrap();

        let path = UpdatePath {
            leaf_key_package: key_package,
            nodes: vec![],
        };

        assert!(path.nodes.is_empty());
    }

    // Helper function to create test signature
    fn create_test_signature() -> DebugMlDsaSignature {
        let keypair = KeyPair::generate(CipherSuite::default());
        let sig = keypair.sign(b"test").unwrap();
        match sig {
            crate::crypto::Signature::MlDsa(ml_dsa_sig) => DebugMlDsaSignature(ml_dsa_sig),
            _ => panic!("Expected ML-DSA signature for default suite"),
        }
    }

    #[test]
    fn test_encrypted_path_secret() {
        let keypair1 = KeyPair::generate(CipherSuite::default());
        let keypair2 = KeyPair::generate(CipherSuite::default());
        let member_id = MemberId::generate();

        // Create encrypted path secret using ML-KEM
        let (ciphertext, _shared_secret) = keypair1.encapsulate(keypair2.public_key()).unwrap();

        let eps = EncryptedPathSecret {
            recipient: member_id,
            ciphertext: ciphertext.to_bytes(),
        };

        assert_eq!(eps.recipient, member_id);
    }

    #[test]
    fn test_welcome_message_validation() {
        let valid = WelcomeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            cipher_suite: CipherSuite::default(),
            group_info: vec![1, 2, 3],
            secrets: vec![EncryptedGroupSecrets {
                recipient_key_package_hash: vec![1],
                kem_ciphertext: vec![2],
                encrypted_path_secret: vec![3],
            }],
            signature: create_test_signature(),
        };
        assert!(valid.validate().is_ok());

        let no_secrets = WelcomeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            cipher_suite: CipherSuite::default(),
            group_info: vec![1, 2, 3],
            secrets: vec![],
            signature: create_test_signature(),
        };
        assert!(no_secrets.validate().is_err());
    }
}

/// Audit log entry for group operations (SPEC-2 §8)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Timestamp of the event
    pub timestamp: std::time::SystemTime,
    /// Type of event (group_created, epoch_advanced, member_added, etc.)
    pub event_type: String,
    /// Cipher suite ID used
    pub cipher_suite_id: CipherSuiteId,
    /// Whether cipher suite is PQC-only
    pub is_pqc_only: bool,
    /// Whether cipher suite is deprecated
    pub is_deprecated: bool,
    /// Member ID involved (if applicable)
    pub member_id: Option<MemberId>,
    /// Old epoch (for epoch changes)
    pub old_epoch: Option<u64>,
    /// New epoch (for epoch changes)
    pub new_epoch: Option<u64>,
    /// Additional context
    pub context: Option<String>,
}

// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms)]

//! # Saorsa MLS - Message Layer Security Protocol (RFC 9420) with Post-Quantum Cryptography
//!
//! This crate implements the Message Layer Security (MLS) protocol as specified in
//! [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/) for secure group communication,
//! enhanced with post-quantum cryptographic algorithms for quantum resistance.
//!
//! MLS provides:
//!
//! - **End-to-end encryption** for group messaging
//! - **Forward secrecy** - past messages remain secure even if keys are compromised
//! - **Post-compromise security** - the group can heal after a compromise
//! - **Asynchronous group management** - members can join/leave without real-time coordination
//! - **Scalable tree-based key derivation** using `TreeKEM`
//!
//! ## Core Components
//!
//! - `protocol`: MLS protocol message structures and state machines
//! - `crypto`: Cryptographic primitives and key derivation
//! - `group`: Group state management and `TreeKEM` operations
//! - `member`: Member identity and authentication
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use saorsa_mls::{MlsGroup, MemberIdentity, MemberId, GroupConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create a new MLS group
//! let config = GroupConfig::default();
//! let creator_identity = MemberIdentity::generate(MemberId::generate())?;
//! let mut group = MlsGroup::new(config, creator_identity).await?;
//!
//! // Add members to the group
//! let new_member = MemberIdentity::generate(MemberId::generate())?;
//! let welcome = group.add_member(&new_member).await?;
//!
//! // Send encrypted messages
//! let message = group.encrypt_message(b"Hello, secure group!")?;
//! let decrypted = group.decrypt_message(&message)?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;
use thiserror::Error;

pub mod api;
pub mod crypto;
pub mod group;
pub mod key_schedule;
pub mod member;
pub mod protocol;
pub mod quic_integration;
pub mod treekem;

pub use api::{
    add_member, group_new, group_new_with_config, recv, remove_member, send, Ciphertext,
    CommitOptions, GroupId as SimpleGroupId, Identity,
};
pub use crypto::{
    AeadCipher, CipherSuite, CipherSuiteId, Hash, HpkeContext, KeyPair, KeySchedule, MlsAead,
    MlsHash, MlsKem, MlsSignature,
};
pub use group::{GroupConfig, GroupId, GroupState, MlsGroup};
pub use member::{
    Credential, CredentialType, GroupMember, KeyPackage, MemberId, MemberIdentity, MemberState,
    TrustStore,
};
pub use protocol::{AuditLogEntry, *};

/// Errors that can occur in MLS operations
#[derive(Debug, Error)]
pub enum MlsError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid group state: {0}")]
    InvalidGroupState(String),

    #[error("Member not found: {0:?}")]
    MemberNotFound(MemberId),

    #[error("Unauthorized operation: {0}")]
    Unauthorized(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    #[error("Message decryption failed")]
    DecryptionFailed,

    #[error("Invalid epoch: expected {expected}, got {actual}")]
    InvalidEpoch { expected: u64, actual: u64 },

    #[error("`TreeKEM` operation failed: {0}")]
    TreeKemError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, MlsError>;

/// MLS protocol version
pub const MLS_VERSION: u16 = 1;

/// Maximum group size (`TreeKEM` limitation)
pub const MAX_GROUP_SIZE: usize = 65536; // 2^16

/// Key rotation interval
pub const DEFAULT_KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(24 * 3600); // 24 hours

/// Message sequence number type
pub type MessageSequence = u64;

/// Epoch number for group state versioning
pub type EpochNumber = u64;

/// Wire format version for backwards compatibility
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireFormat {
    pub version: u16,
    pub extensions: Vec<u16>,
}

impl Default for WireFormat {
    fn default() -> Self {
        Self {
            version: MLS_VERSION,
            extensions: Vec::new(),
        }
    }
}

/// MLS configuration parameters
#[derive(Debug, Clone)]
pub struct MlsConfig {
    /// Maximum number of members in a group
    pub max_group_size: usize,
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    /// Enable post-compromise security
    pub enable_pcs: bool,
    /// Enable forward secrecy
    pub enable_fs: bool,
    /// Cipher suite to use
    pub cipher_suite: CipherSuite,
    /// Maximum message age before rejection
    pub max_message_age: Duration,
}

impl Default for MlsConfig {
    fn default() -> Self {
        Self {
            max_group_size: MAX_GROUP_SIZE,
            key_rotation_interval: DEFAULT_KEY_ROTATION_INTERVAL,
            enable_pcs: true,
            enable_fs: true,
            cipher_suite: CipherSuite::default(),
            max_message_age: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// MLS statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct MlsStats {
    pub groups_active: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub key_rotations: u64,
    pub member_additions: u64,
    pub member_removals: u64,
    pub epoch_transitions: u64,
}

// Default is now derived

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mls_config_defaults() {
        let config = MlsConfig::default();
        assert_eq!(config.max_group_size, MAX_GROUP_SIZE);
        assert_eq!(config.key_rotation_interval, DEFAULT_KEY_ROTATION_INTERVAL);
        assert!(config.enable_pcs);
        assert!(config.enable_fs);
    }

    #[test]
    fn test_wire_format_default() {
        let format = WireFormat::default();
        assert_eq!(format.version, MLS_VERSION);
        assert!(format.extensions.is_empty());
    }

    #[test]
    fn test_mls_stats_default() {
        let stats = MlsStats::default();
        assert_eq!(stats.groups_active, 0);
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
    }
}

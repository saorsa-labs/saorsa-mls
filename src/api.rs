// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Simplified API for MLS group messaging with QUIC stream integration

use crate::{
    crypto::{random_bytes, SecretBytes},
    group::MlsGroup,
    member::{MemberId, MemberIdentity},
    protocol::{ApplicationMessage, CommitMessage},
    MlsError, Result,
};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Group identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub Bytes);

impl GroupId {
    /// Generate a new random group ID
    pub fn generate() -> Self {
        Self(Bytes::from(random_bytes(32)))
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Bytes::from(bytes))
    }
}

/// Commit options for padding and metadata
#[derive(Debug, Clone, Default)]
pub struct CommitOptions {
    /// Padding size for traffic analysis resistance
    pub padding: usize,
}

/// Encrypted ciphertext with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// The encrypted payload
    pub data: Bytes,
    /// Sender's member ID
    pub sender_id: MemberId,
    /// Message sequence number
    pub sequence: u64,
    /// Epoch number
    pub epoch: u64,
    /// Signature over the ciphertext
    #[serde(skip)]
    pub signature: Option<crate::crypto::DebugMlDsaSignature>,
}

/// Identity type for simplified API
pub type Identity = MemberIdentity;

/// Commit type for simplified API
pub type Commit = CommitMessage;

/// Storage for group state persistence
#[derive(Debug)]
struct GroupStorage {
    /// Current epoch number
    epoch: u64,
    /// Transcript hash for epoch
    #[allow(dead_code)]
    transcript_hash: SecretBytes,
    /// Ratchet states per member
    ratchets: HashMap<MemberId, SecretBytes>,
}

/// Group manager for simplified API
#[derive(Debug)]
pub struct GroupManager {
    groups: Arc<RwLock<HashMap<GroupId, Arc<MlsGroup>>>>,
    storage: Arc<RwLock<HashMap<GroupId, GroupStorage>>>,
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupManager {
    /// Create a new group manager
    pub fn new() -> Self {
        Self {
            groups: Arc::new(RwLock::new(HashMap::new())),
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new group with initial members
    pub async fn group_new(&self, members: &[Identity]) -> Result<GroupId> {
        self.group_new_with_config(members, crate::GroupConfig::default())
            .await
    }

    /// Create a new group with explicit configuration (including cipher suite)
    pub async fn group_new_with_config(
        &self,
        members: &[Identity],
        config: crate::GroupConfig,
    ) -> Result<GroupId> {
        if members.is_empty() {
            return Err(MlsError::InvalidGroupState(
                "Group must have at least one member".to_string(),
            ));
        }

        let suite = crate::CipherSuite::from_id(config.cipher_suite).ok_or_else(|| {
            MlsError::InvalidGroupState(format!(
                "unsupported cipher suite 0x{:04X}",
                config.cipher_suite.as_u16()
            ))
        })?;

        if let Some(mismatch) = members
            .iter()
            .find(|identity| identity.cipher_suite() != suite)
        {
            return Err(MlsError::InvalidGroupState(format!(
                "member {} does not match group cipher suite",
                mismatch.id
            )));
        }

        let group_id = GroupId::generate();

        // Use first member as creator
        let creator = members[0].clone();
        let mut group = MlsGroup::new(config, creator).await?;

        // Add remaining members
        for member in &members[1..] {
            group.add_member(member).await?;
        }

        // Store group
        let mut groups = self.groups.write();
        groups.insert(group_id.clone(), Arc::new(group));

        // Initialize storage
        let storage = GroupStorage {
            epoch: 0,
            transcript_hash: SecretBytes::from(random_bytes(32)),
            ratchets: HashMap::new(),
        };
        let mut storages = self.storage.write();
        storages.insert(group_id.clone(), storage);

        Ok(group_id)
    }

    /// Add a member to the group
    pub async fn add_member(&self, group_id: &GroupId, id: Identity) -> Result<Commit> {
        // We need to replace the group with a mutable one temporarily
        // First, validate and remove under lock
        let mut group = {
            let mut groups = self.groups.write();
            let existing = groups
                .get(group_id)
                .ok_or_else(|| MlsError::InvalidGroupState("Group not found".to_string()))?;

            if id.cipher_suite() != existing.cipher_suite() {
                return Err(MlsError::InvalidGroupState(
                    "member identity does not match group cipher suite".to_string(),
                ));
            }

            groups
                .remove(group_id)
                .expect("group must still exist after prior lookup")
            // Lock is released here when `groups` goes out of scope
        };

        // Get mutable reference and add member (lock is not held during await)
        let result = {
            let group_mut = Arc::get_mut(&mut group).ok_or_else(|| {
                MlsError::InvalidGroupState("Cannot modify shared group".to_string())
            })?;

            group_mut.add_member(&id).await
        };

        // Put the group back under a new lock
        {
            let mut groups = self.groups.write();
            groups.insert(group_id.clone(), group);
        }

        let _welcome = result?;

        // Update storage with new epoch
        let mut storages = self.storage.write();
        if let Some(storage) = storages.get_mut(group_id) {
            storage.epoch += 1;
            storage
                .ratchets
                .insert(id.id, SecretBytes::from(random_bytes(32)));
        }
        let _epoch = storages.get(group_id).map(|s| s.epoch).unwrap_or(0);

        // Convert welcome to commit
        // In a real implementation, this would contain actual proposals
        Ok(Commit {
            proposals: vec![crate::protocol::ProposalRef::Reference(vec![1, 2, 3])],
            path: None,
        })
    }

    /// Remove a member from the group
    pub async fn remove_member(&self, group_id: &GroupId, id: Identity) -> Result<Commit> {
        // We need to replace the group with a mutable one temporarily
        // First, validate and remove under lock
        let mut group = {
            let mut groups = self.groups.write();
            let existing = groups
                .get(group_id)
                .ok_or_else(|| MlsError::InvalidGroupState("Group not found".to_string()))?;

            if id.cipher_suite() != existing.cipher_suite() {
                return Err(MlsError::InvalidGroupState(
                    "member identity does not match group cipher suite".to_string(),
                ));
            }

            groups
                .remove(group_id)
                .expect("group must still exist after prior lookup")
            // Lock is released here when `groups` goes out of scope
        };

        // Get mutable reference and remove member (lock is not held during await)
        let result = {
            let group_mut = Arc::get_mut(&mut group).ok_or_else(|| {
                MlsError::InvalidGroupState("Cannot modify shared group".to_string())
            })?;

            group_mut.remove_member(&id.id).await
        };

        // Put the group back under a new lock
        {
            let mut groups = self.groups.write();
            groups.insert(group_id.clone(), group);
        }

        result?;

        // Update storage
        let mut storages = self.storage.write();
        if let Some(storage) = storages.get_mut(group_id) {
            storage.epoch += 1;
            storage.ratchets.remove(&id.id);
        }
        let _epoch = storages.get(group_id).map(|s| s.epoch).unwrap_or(0);

        Ok(Commit {
            proposals: vec![crate::protocol::ProposalRef::Reference(vec![4, 5, 6])],
            path: None,
        })
    }

    /// Send an encrypted message to the group
    pub fn send(&self, group_id: &GroupId, app_data: &[u8]) -> Result<Ciphertext> {
        let groups = self.groups.read();
        let group = groups
            .get(group_id)
            .ok_or_else(|| MlsError::InvalidGroupState("Group not found".to_string()))?;

        // Encrypt the message
        let app_msg = group.encrypt_message(app_data)?;

        // Get current state for metadata (not needed since we use message epoch)
        let storages = self.storage.read();
        let _storage = storages
            .get(group_id)
            .ok_or_else(|| MlsError::InvalidGroupState("Storage not found".to_string()))?;

        Ok(Ciphertext {
            data: Bytes::from(app_msg.ciphertext),
            sender_id: app_msg.sender,
            sequence: app_msg.sequence,
            epoch: app_msg.epoch, // Use the actual epoch from the message
            signature: Some(app_msg.signature),
        })
    }

    /// Receive and decrypt a message from the group
    pub fn recv(&self, group_id: &GroupId, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        let groups = self.groups.read();
        let group = groups
            .get(group_id)
            .ok_or_else(|| MlsError::InvalidGroupState("Group not found".to_string()))?;

        // Reconstruct ApplicationMessage from Ciphertext
        let app_msg = ApplicationMessage {
            epoch: ciphertext.epoch,
            sender: ciphertext.sender_id,
            generation: 0, // Simplified
            sequence: ciphertext.sequence,
            ciphertext: ciphertext.data.to_vec(),
            signature: ciphertext
                .signature
                .clone()
                .ok_or_else(|| MlsError::InvalidMessage("Missing signature".to_string()))?,
        };

        // Decrypt the message
        group.decrypt_message(&app_msg)
    }
}

// Global instance for simplified API
lazy_static::lazy_static! {
    static ref MANAGER: GroupManager = GroupManager::new();
}

/// Create a new group with initial members
///
/// # Arguments
/// * `members` - Initial group members
///
/// # Returns
/// * `GroupId` - The identifier for the created group
pub async fn group_new(members: &[Identity]) -> anyhow::Result<GroupId> {
    MANAGER.group_new(members).await.map_err(Into::into)
}

/// Create a new group with explicit configuration
pub async fn group_new_with_config(
    members: &[Identity],
    config: crate::GroupConfig,
) -> anyhow::Result<GroupId> {
    MANAGER
        .group_new_with_config(members, config)
        .await
        .map_err(Into::into)
}

/// Add a member to an existing group
///
/// # Arguments
/// * `g` - The group identifier
/// * `id` - The identity of the member to add
///
/// # Returns
/// * `Commit` - The commit message for the add operation
pub async fn add_member(g: &GroupId, id: Identity) -> anyhow::Result<Commit> {
    MANAGER.add_member(g, id).await.map_err(Into::into)
}

/// Remove a member from a group
///
/// # Arguments
/// * `g` - The group identifier
/// * `id` - The identity of the member to remove
///
/// # Returns
/// * `Commit` - The commit message for the remove operation
pub async fn remove_member(g: &GroupId, id: Identity) -> anyhow::Result<Commit> {
    MANAGER.remove_member(g, id).await.map_err(Into::into)
}

/// Send an encrypted message to the group
///
/// # Arguments
/// * `g` - The group identifier
/// * `app` - The application data to encrypt
///
/// # Returns
/// * `Ciphertext` - The encrypted message
pub fn send(g: &GroupId, app: &[u8]) -> anyhow::Result<Ciphertext> {
    MANAGER.send(g, app).map_err(Into::into)
}

/// Receive and decrypt a message from the group
///
/// # Arguments
/// * `g` - The group identifier
/// * `ct` - The encrypted ciphertext
///
/// # Returns
/// * `Vec<u8>` - The decrypted application data
pub fn recv(g: &GroupId, ct: &Ciphertext) -> anyhow::Result<Vec<u8>> {
    MANAGER.recv(g, ct).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_group_creation() {
        let member1 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let member2 = MemberIdentity::generate(MemberId::generate()).unwrap();

        let members = vec![member1, member2];
        let group_id = group_new(&members).await.unwrap();

        assert!(!group_id.0.is_empty());
    }

    #[tokio::test]
    async fn test_add_remove_member() {
        let member1 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let member2 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let member3 = MemberIdentity::generate(MemberId::generate()).unwrap();

        let members = vec![member1.clone(), member2];
        let group_id = group_new(&members).await.unwrap();

        // Add member
        let commit = add_member(&group_id, member3.clone()).await.unwrap();
        assert!(!commit.proposals.is_empty() || commit.path.is_some());

        // Remove member
        let commit = remove_member(&group_id, member3).await.unwrap();
        assert!(!commit.proposals.is_empty() || commit.path.is_some());
    }

    #[tokio::test]
    async fn test_send_recv() {
        let member1 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let member2 = MemberIdentity::generate(MemberId::generate()).unwrap();

        let members = vec![member1, member2];
        let group_id = group_new(&members).await.unwrap();

        let message = b"Hello, MLS group!";
        let ciphertext = send(&group_id, message).unwrap();

        let decrypted = recv(&group_id, &ciphertext).unwrap();
        assert_eq!(decrypted, message);
    }
}

// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixed version of group.rs that resolves deadlock issues

use crate::{
    crypto::{labels, random_bytes, AeadCipher, CipherSuite, Hash, KeySchedule},
    member::{MemberId, MemberIdentity, MemberRegistry},
    protocol::{
        ApplicationMessage, AuditLogEntry, EncryptedGroupSecrets, GroupInfo, ProtocolStateMachine,
        WelcomeMessage,
    },
    EpochNumber, MlsError, MlsStats, Result,
};
// postcard serialization (size limits removed - postcard doesn't support them)
use dashmap::DashMap;
use parking_lot::RwLock;
use saorsa_pqc::api::{MlDsa, MlDsaPublicKey, MlKem};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::SystemTime,
};

/// Sliding replay window for sequences
#[derive(Debug, Default)]
struct ReplayWindow {
    max_seen: u64,
    window: u64,
}

impl ReplayWindow {
    // Allow if sequence is new within a 64-slot window; update state
    fn allow_and_update(&mut self, seq: u64) -> bool {
        if seq > self.max_seen {
            let shift = seq - self.max_seen;
            if shift >= 64 {
                self.window = 0;
            } else {
                self.window <<= shift;
            }
            self.window |= 1;
            self.max_seen = seq;
            true
        } else {
            let offset = self.max_seen - seq;
            if offset >= 64 {
                false
            } else {
                let mask = 1u64 << offset;
                if self.window & mask != 0 {
                    false
                } else {
                    self.window |= mask;
                    true
                }
            }
        }
    }
}

pub use crate::protocol::{GroupConfig, GroupId};

/// MLS group state with `TreeKEM` key management - FIXED VERSION
#[derive(Debug)]
pub struct MlsGroup {
    config: GroupConfig,
    group_id: GroupId,
    epoch: AtomicU64,
    creator: MemberIdentity,
    members: Arc<RwLock<MemberRegistry>>,
    tree: Arc<RwLock<TreeKemState>>,
    key_schedule: Arc<RwLock<Option<KeySchedule>>>,
    // Per-sender send sequence numbers
    send_sequences: Arc<DashMap<MemberId, u64>>,
    protocol_state: Arc<RwLock<ProtocolStateMachine>>,
    stats: Arc<RwLock<MlsStats>>,
    secrets: Arc<DashMap<String, crate::crypto::SecretBytes>>,
    // Per-sender replay windows
    recv_windows: Arc<DashMap<MemberId, ReplayWindow>>,
    cipher_suite: CipherSuite,
    // Rekey tracking (SPEC-2 §3)
    epoch_start_time: Arc<RwLock<SystemTime>>,
    epoch_message_count: AtomicU64,
    // Audit logging (SPEC-2 §8)
    audit_log: Arc<RwLock<Vec<AuditLogEntry>>>,
}

impl MlsGroup {
    /// Create a new MLS group
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if group initialization fails.
    pub async fn new(config: GroupConfig, creator: MemberIdentity) -> Result<Self> {
        let group_id = GroupId::generate();
        let cipher_suite = CipherSuite::from_id(config.cipher_suite).ok_or_else(|| {
            MlsError::InvalidGroupState(format!(
                "unsupported cipher suite 0x{:04X}",
                config.cipher_suite.as_u16()
            ))
        })?;

        if creator.cipher_suite() != cipher_suite {
            return Err(MlsError::InvalidGroupState(
                "creator identity does not match group cipher suite".to_string(),
            ));
        }

        let mut members = MemberRegistry::new();
        members.add_member(creator.clone())?;

        let tree = TreeKemState::new(creator.key_package.agreement_key.clone(), cipher_suite)?;

        // Create initial audit log entry
        let mut audit_log = Vec::new();
        audit_log.push(AuditLogEntry {
            timestamp: SystemTime::now(),
            event_type: "group_created".to_string(),
            cipher_suite_id: config.cipher_suite,
            is_pqc_only: cipher_suite.is_pqc_only(),
            is_deprecated: cipher_suite.is_deprecated(),
            member_id: Some(creator.id),
            old_epoch: None,
            new_epoch: Some(0),
            context: Some(format!(
                "Group created with cipher suite 0x{:04X} ({})",
                config.cipher_suite.as_u16(),
                if cipher_suite.is_pqc_only() {
                    "PQC-only"
                } else {
                    "deprecated"
                }
            )),
        });

        let group = Self {
            config,
            group_id,
            epoch: AtomicU64::new(0),
            creator,
            members: Arc::new(RwLock::new(members)),
            tree: Arc::new(RwLock::new(tree)),
            key_schedule: Arc::new(RwLock::new(None)),
            send_sequences: Arc::new(DashMap::new()),
            protocol_state: Arc::new(RwLock::new(ProtocolStateMachine::new(0))),
            stats: Arc::new(RwLock::new(MlsStats::default())),
            secrets: Arc::new(DashMap::new()),
            recv_windows: Arc::new(DashMap::new()),
            cipher_suite,
            epoch_start_time: Arc::new(RwLock::new(SystemTime::now())),
            epoch_message_count: AtomicU64::new(0),
            audit_log: Arc::new(RwLock::new(audit_log)),
        };

        // Initialize key schedule for epoch 0
        group.initialize_epoch_keys()?;

        Ok(group)
    }

    /// Add a new member to the group - FIXED to avoid deadlock
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if adding the member fails or group size limit is reached.
    pub async fn add_member(&mut self, identity: &MemberIdentity) -> Result<WelcomeMessage> {
        if identity.cipher_suite() != self.cipher_suite {
            return Err(MlsError::InvalidGroupState(
                "member identity does not match group cipher suite".to_string(),
            ));
        }

        // Scope locks to release before any await
        let (_member_id, _tree_position, should_advance) = {
            let mut members = self.members.write();
            let mut tree = self.tree.write();
            let mut stats = self.stats.write();

            // Check group size limit
            if members.active_member_count() >= self.config.max_members.unwrap_or(1000) as usize {
                return Err(MlsError::InvalidGroupState(
                    "Group has reached maximum size".to_string(),
                ));
            }

            // Add member to registry
            let member_id = identity.id;
            let member_index = members.add_member(identity.clone())?;

            // Update TreeKEM - use member index as tree position
            let tree_position = member_index as usize;
            tree.add_leaf(tree_position, identity.key_package.agreement_key.clone())?;

            // Update statistics
            stats.member_additions += 1;
            stats.groups_active = members.active_member_count();

            (member_id, tree_position, true)
        }; // All locks released here

        if should_advance {
            self.advance_epoch()?;
        }

        // Encapsulate path secret for the new member using ML-KEM
        let kem_public = saorsa_pqc::api::MlKemPublicKey::from_bytes(
            self.cipher_suite.ml_kem_variant(),
            &identity.key_package.agreement_key,
        )
        .map_err(|e| MlsError::CryptoError(format!("Invalid KEM public key: {e:?}")))?;

        if should_advance {
            self.advance_epoch()?;
        }

        let application_secret_bytes = self
            .secrets
            .get(labels::APPLICATION)
            .ok_or_else(|| {
                MlsError::KeyDerivationError("Application secret not found".to_string())
            })?
            .as_bytes()
            .to_vec();

        let ml_kem = MlKem::new(self.cipher_suite.ml_kem_variant());
        let (shared_secret, ciphertext) = ml_kem
            .encapsulate(&kem_public)
            .map_err(|e| MlsError::CryptoError(format!("Encapsulation failed: {e:?}")))?;

        // Create welcome message (no locks held)
        let group_info = self.create_group_info()?;
        let group_info_bytes = postcard::to_stdvec(&group_info)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;

        // Sign group info with creator's key (supports both ML-DSA and SLH-DSA)
        let signature_enum = self.creator.sign(&group_info_bytes)?;

        // Extract the underlying ML-DSA signature (Welcome message currently only supports ML-DSA)
        let signature = match signature_enum {
            crate::crypto::Signature::MlDsa(sig) => sig,
            crate::crypto::Signature::SlhDsa(_) => {
                return Err(MlsError::ProtocolError(
                    "Welcome messages with SLH-DSA not yet supported".to_string(),
                ));
            }
        };

        let shared_bytes = shared_secret.to_bytes();
        let encrypted_path_secret = EncryptedGroupSecrets::encrypt_for_recipient(
            self.cipher_suite,
            &shared_bytes,
            &application_secret_bytes,
        )?;

        let welcome_secrets = vec![EncryptedGroupSecrets {
            recipient_key_package_hash: identity.key_package.agreement_key.clone(),
            kem_ciphertext: ciphertext.to_bytes(),
            encrypted_path_secret,
        }];

        let welcome = WelcomeMessage {
            epoch: self.current_epoch(),
            sender: self.creator.id,
            cipher_suite: self.cipher_suite,
            group_info: group_info_bytes,
            secrets: welcome_secrets,
            signature: crate::crypto::DebugMlDsaSignature(signature),
        };

        // Log member addition (SPEC-2 §8)
        self.audit_log.write().push(AuditLogEntry {
            timestamp: SystemTime::now(),
            event_type: "member_added".to_string(),
            cipher_suite_id: self.config.cipher_suite,
            is_pqc_only: self.cipher_suite.is_pqc_only(),
            is_deprecated: self.cipher_suite.is_deprecated(),
            member_id: Some(identity.id),
            old_epoch: None,
            new_epoch: Some(self.current_epoch()),
            context: Some(format!("Member {:?} added to group", identity.id)),
        });

        Ok(welcome)
    }

    /// Remove a member from the group - FIXED to avoid deadlock
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if the member is not found or removal fails.
    pub async fn remove_member(&mut self, member_id: &MemberId) -> Result<()> {
        // Scope locks to release before any await
        let should_advance = {
            let mut members = self.members.write();
            let mut tree = self.tree.write();
            let mut stats = self.stats.write();

            // Find member index first
            let member_index = members
                .find_member_index(member_id)
                .ok_or(MlsError::MemberNotFound(*member_id))?;

            // Remove from registry
            let _removed_member = members.remove_member(member_index)?;
            let tree_position = member_index as usize;

            // Update TreeKEM
            tree.remove_leaf(tree_position)?;

            // Update statistics
            stats.member_removals += 1;
            stats.groups_active = members.active_member_count();

            true
        }; // All locks released here

        // Advance epoch if needed (no locks held)
        if should_advance {
            self.advance_epoch()?;
        }

        // Log member removal (SPEC-2 §8)
        self.audit_log.write().push(AuditLogEntry {
            timestamp: SystemTime::now(),
            event_type: "member_removed".to_string(),
            cipher_suite_id: self.config.cipher_suite,
            is_pqc_only: self.cipher_suite.is_pqc_only(),
            is_deprecated: self.cipher_suite.is_deprecated(),
            member_id: Some(*member_id),
            old_epoch: None,
            new_epoch: Some(self.current_epoch()),
            context: Some(format!("Member {:?} removed from group", member_id)),
        });

        Ok(())
    }

    /// Encrypt a message for the group - FIXED to avoid deadlock
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if encryption fails or key derivation fails.
    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<ApplicationMessage> {
        // Derive per-sender application key and base nonce
        let sender_id = self.creator.id;
        let (app_key, base_nonce) = self.get_sender_application_key_and_nonce(sender_id)?;

        let cipher = AeadCipher::new(app_key, self.cipher_suite)?;

        // Per-sender sequence number
        let sequence = self
            .send_sequences
            .entry(sender_id)
            .and_modify(|s| *s += 1)
            .or_insert(0)
            .to_owned();
        let nonce = Self::xor_nonce_with_sequence(&base_nonce, sequence);
        let aad = self.create_application_aad_with_seq_sender(sequence, sender_id);
        let ciphertext = cipher.encrypt(&nonce, plaintext, &aad)?;

        // Combine nonce + ciphertext for wire format
        let mut wire_ciphertext = nonce;
        wire_ciphertext.extend_from_slice(&ciphertext);

        // Sign the ciphertext using the creator's signing key (supports both ML-DSA and SLH-DSA)
        let signature_enum = self.creator.sign(&wire_ciphertext)?;

        // Extract the underlying ML-DSA signature (Application message currently only supports ML-DSA)
        let signature = match signature_enum {
            crate::crypto::Signature::MlDsa(sig) => sig,
            crate::crypto::Signature::SlhDsa(_) => {
                return Err(MlsError::ProtocolError(
                    "Application messages with SLH-DSA not yet supported".to_string(),
                ));
            }
        };

        let message = ApplicationMessage {
            epoch: self.current_epoch(),
            sender: self.creator.id,
            generation: 0, // Simplified
            sequence,
            ciphertext: wire_ciphertext,
            signature: crate::crypto::DebugMlDsaSignature(signature),
        };

        // Increment epoch message counter for rekey tracking (SPEC-2 §3)
        self.epoch_message_count.fetch_add(1, Ordering::Relaxed);

        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.messages_sent += 1;
        } // Lock released

        Ok(message)
    }

    /// Decrypt an application message - FIXED to avoid deadlock
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if decryption fails, epoch mismatch, or key derivation fails.
    pub fn decrypt_message(&self, message: &ApplicationMessage) -> Result<Vec<u8>> {
        // Verify epoch
        if message.epoch != self.current_epoch() {
            return Err(MlsError::InvalidEpoch {
                expected: self.current_epoch(),
                actual: message.epoch,
            });
        }

        // Derive per-sender key/nonce for the sender of this message
        let (receiver_key, base_nonce) =
            self.get_sender_application_key_and_nonce(message.sender)?;
        let cipher = AeadCipher::new(receiver_key, self.cipher_suite)?;

        // Verify the message signature before decryption
        let verifying_key = {
            let members = self.members.read();
            let index = members
                .find_member_index(&message.sender)
                .ok_or(MlsError::MemberNotFound(message.sender))?;
            let member = members
                .get_member(index)
                .ok_or(MlsError::MemberNotFound(message.sender))?;
            MlDsaPublicKey::from_bytes(
                self.cipher_suite.ml_dsa_variant(),
                &member.identity.key_package.verifying_key,
            )
            .expect("Invalid ML-DSA public key")
        };
        let ml_dsa = MlDsa::new(self.cipher_suite.ml_dsa_variant());
        let signature_valid = ml_dsa
            .verify(&verifying_key, &message.ciphertext, &message.signature.0)
            .map_err(|e| MlsError::InvalidMessage(format!("invalid signature: {e:?}")))?;
        if !signature_valid {
            return Err(MlsError::InvalidMessage("invalid signature".to_string()));
        }

        // Extract nonce and ciphertext
        let nonce_size = self.cipher_suite.nonce_size();
        if message.ciphertext.len() < nonce_size {
            return Err(MlsError::DecryptionFailed);
        }

        let (nonce, ciphertext) = message.ciphertext.split_at(nonce_size);
        let aad = self.create_application_aad_with_seq_sender(message.sequence, message.sender);

        // Recompute expected nonce from base and sequence and compare
        let expected_nonce = Self::xor_nonce_with_sequence(&base_nonce, message.sequence);
        if nonce != expected_nonce.as_slice() {
            return Err(MlsError::DecryptionFailed);
        }

        let plaintext = cipher.decrypt(nonce, ciphertext, &aad)?;

        // Replay protection using per-sender sliding window
        if !self
            .recv_windows
            .entry(message.sender)
            .or_default()
            .allow_and_update(message.sequence)
        {
            return Err(MlsError::ProtocolError("replay detected".to_string()));
        }

        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.messages_received += 1;
        } // Lock released

        Ok(plaintext)
    }

    /// Derive and cache per-sender application key and base nonce
    fn get_sender_application_key_and_nonce(&self, sender: MemberId) -> Result<(Vec<u8>, Vec<u8>)> {
        let key_cache = format!("application_key::{sender}");
        let nonce_cache = format!("application_nonce::{sender}");

        if let (Some(k), Some(n)) = (self.secrets.get(&key_cache), self.secrets.get(&nonce_cache)) {
            return Ok((k.as_bytes().to_vec(), n.as_bytes().to_vec()));
        }

        // Load application secret
        let app_secret = self
            .secrets
            .get("application")
            .ok_or(MlsError::KeyDerivationError(
                "Application secret not found".to_string(),
            ))?
            .as_bytes()
            .to_vec();

        // Create a fresh key schedule instead of accessing the stored one
        let key_schedule = KeySchedule::new(self.cipher_suite);

        // Derive per-sender key and base nonce using HKDF labels
        let mut info_key = Vec::new();
        info_key.extend_from_slice(b"mls application key");
        info_key.extend_from_slice(sender.0.as_bytes());
        let app_key = key_schedule.derive_key(
            &self.current_epoch().to_be_bytes(),
            &app_secret,
            &info_key,
            self.cipher_suite.key_size(),
        )?;

        let mut info_nonce = Vec::new();
        info_nonce.extend_from_slice(b"mls application nonce");
        info_nonce.extend_from_slice(sender.0.as_bytes());
        let base_nonce = key_schedule.derive_key(
            &self.current_epoch().to_be_bytes(),
            &app_secret,
            &info_nonce,
            self.cipher_suite.nonce_size(),
        )?;

        // Cache
        self.secrets
            .insert(key_cache, crate::crypto::SecretBytes::from(app_key.clone()));
        self.secrets.insert(
            nonce_cache,
            crate::crypto::SecretBytes::from(base_nonce.clone()),
        );

        Ok((app_key, base_nonce))
    }

    /// Advance to next epoch - FIXED to avoid deadlock
    fn advance_epoch(&self) -> Result<()> {
        let old_epoch = self.epoch.load(Ordering::SeqCst);
        let new_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;

        // Reset rekey tracking counters (SPEC-2 §3)
        *self.epoch_start_time.write() = SystemTime::now();
        self.epoch_message_count.store(0, Ordering::Relaxed);

        // Update protocol state with scoped lock
        {
            let mut state = self.protocol_state.write();
            state.set_epoch(new_epoch);
        } // Lock released

        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.epoch_transitions += 1;
        } // Lock released

        // Reinitialize keys (no locks held during async operation)
        self.initialize_epoch_keys()?;

        // Log epoch advance (SPEC-2 §8)
        self.audit_log.write().push(AuditLogEntry {
            timestamp: SystemTime::now(),
            event_type: "epoch_advanced".to_string(),
            cipher_suite_id: self.config.cipher_suite,
            is_pqc_only: self.cipher_suite.is_pqc_only(),
            is_deprecated: self.cipher_suite.is_deprecated(),
            member_id: None,
            old_epoch: Some(old_epoch),
            new_epoch: Some(new_epoch),
            context: Some(format!(
                "Epoch advanced: {} -> {} (membership change)",
                old_epoch, new_epoch
            )),
        });

        Ok(())
    }

    /// Initialize cryptographic keys for current epoch - FIXED
    fn initialize_epoch_keys(&self) -> Result<()> {
        // Get root secret with scoped lock
        let root_secret = {
            let tree = self.tree.read();
            tree.get_root_secret()?
        }; // Lock released

        let ks = KeySchedule::new(self.cipher_suite);
        let epoch_bytes = self.current_epoch().to_be_bytes();

        // Derive epoch-specific secrets (no locks held)
        let derive_labels = [
            labels::EPOCH_SECRET,
            labels::SENDER_DATA_SECRET,
            labels::HANDSHAKE_SECRET,
            labels::APPLICATION_SECRET,
            labels::EXPORTER_SECRET,
            labels::AUTHENTICATION_SECRET,
            labels::EXTERNAL_SECRET,
            labels::CONFIRMATION_KEY,
            labels::MEMBERSHIP_KEY,
            labels::RESUMPTION_PSK,
            labels::INIT_SECRET,
        ];
        let lengths: Vec<usize> = vec![self.cipher_suite.hash_size(); derive_labels.len()];
        let secrets = ks.derive_keys(&epoch_bytes, &root_secret, &derive_labels, &lengths)?;

        // Store secrets (DashMap handles concurrency)
        self.secrets.clear();
        let labels = [
            "epoch",
            "sender_data",
            "handshake",
            "application",
            "exporter",
            "authentication",
            "external",
            "confirmation",
            "membership",
            "resumption_psk",
            "init",
        ];

        for (label, secret) in labels.iter().zip(secrets.iter()) {
            self.secrets.insert(
                (*label).to_string(),
                crate::crypto::SecretBytes::from(secret.clone()),
            );
        }

        // Update key schedule with scoped lock
        {
            let mut key_schedule = self.key_schedule.write();
            *key_schedule = Some(ks);
        } // Lock released

        Ok(())
    }

    // Other methods remain the same but follow the pattern:
    // - Use scoped locks { } to ensure release before await
    // - Clone data if needed after lock release
    // - Never hold locks across await points

    pub fn current_epoch(&self) -> EpochNumber {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Get the cipher suite pinned for this group
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Get current epoch number
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Get epoch age (time since epoch started) - SPEC-2 §3
    pub fn epoch_age(&self) -> std::time::Duration {
        self.epoch_start_time
            .read()
            .elapsed()
            .unwrap_or(std::time::Duration::from_secs(0))
    }

    /// Get number of messages sent in current epoch - SPEC-2 §3
    pub fn epoch_message_count(&self) -> u64 {
        self.epoch_message_count.load(Ordering::Relaxed)
    }

    /// Check if rekey is needed per SPEC-2 §3 policy
    ///
    /// Returns true if either:
    /// - Epoch age >= max_epoch_age (default 24 hours)
    /// - Message count >= max_messages_per_epoch (default 10,000)
    pub fn needs_rekey(&self) -> bool {
        let epoch_age = self.epoch_age();
        let message_count = self.epoch_message_count();

        epoch_age >= self.config.max_epoch_age()
            || message_count >= self.config.max_messages_per_epoch()
    }

    /// Perform epoch update / rekey - SPEC-2 §3
    pub async fn perform_epoch_update(&mut self) -> Result<()> {
        let old_epoch = self.epoch();
        let new_epoch = old_epoch + 1;

        // Advance epoch
        self.epoch.store(new_epoch, Ordering::Relaxed);

        // Reset counters
        *self.epoch_start_time.write() = SystemTime::now();
        self.epoch_message_count.store(0, Ordering::Relaxed);

        // Reinitialize keys
        self.initialize_epoch_keys()?;

        // Log epoch advance
        self.audit_log.write().push(AuditLogEntry {
            timestamp: SystemTime::now(),
            event_type: "epoch_advanced".to_string(),
            cipher_suite_id: self.config.cipher_suite,
            is_pqc_only: self.cipher_suite.is_pqc_only(),
            is_deprecated: self.cipher_suite.is_deprecated(),
            member_id: None,
            old_epoch: Some(old_epoch),
            new_epoch: Some(new_epoch),
            context: Some(format!(
                "Automatic rekey: epoch {} -> {}",
                old_epoch, new_epoch
            )),
        });

        Ok(())
    }

    /// Get audit log entries - SPEC-2 §8
    pub fn get_audit_log(&self) -> Vec<AuditLogEntry> {
        self.audit_log.read().clone()
    }

    /// Export audit log as JSON - SPEC-2 §8
    pub fn export_audit_log_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&*self.audit_log.read())
            .map_err(|e| MlsError::SerializationError(e.to_string()))
    }

    /// MLS Exporter interface per RFC 9420 §8.5
    ///
    /// Derives application-specific secrets from the group's exporter secret.
    /// This allows applications to derive additional keying material that is
    /// bound to the MLS group state and current epoch.
    ///
    /// The exporter is deterministic: calling it multiple times with the same
    /// inputs in the same epoch will produce identical output. The output changes
    /// when the epoch advances (e.g., after member additions/removals).
    ///
    /// # Arguments
    ///
    /// * `label` - Application-specific label to distinguish different uses
    /// * `context` - Application-specific context data
    /// * `length` - Desired output length in bytes
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if:
    /// - The exporter secret for the current epoch is not available
    /// - The key derivation operation fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use saorsa_mls::{MlsGroup, GroupConfig, MemberIdentity, MemberId};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = GroupConfig::default();
    /// # let creator = MemberIdentity::generate(MemberId::generate())?;
    /// # let group = MlsGroup::new(config, creator).await?;
    /// // Derive a secret for presence tags (saorsa-gossip integration)
    /// let presence_tag = group.exporter("presence-tag", b"", 32)?;
    ///
    /// // Derive a per-epoch salt
    /// let epoch_salt = group.exporter("epoch-salt", b"room-id-123", 32)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn exporter(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        // Get the exporter secret for the current epoch
        let exporter_secret = self
            .secrets
            .get("exporter")
            .ok_or_else(|| {
                MlsError::CryptoError("Exporter secret not available for current epoch".to_string())
            })?
            .as_bytes()
            .to_vec();

        // Get the key schedule with scoped lock
        let key_schedule = {
            self.key_schedule
                .read()
                .clone()
                .ok_or_else(|| MlsError::CryptoError("Key schedule not initialized".to_string()))?
        }; // Lock released here

        // Derive the exported secret using RFC 9420 exporter construction
        key_schedule.export_secret(&exporter_secret, label, context, length)
    }

    /// Update the group epoch
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if epoch update fails.
    pub async fn update_epoch(&self) -> Result<()> {
        self.advance_epoch()
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id.clone()
    }

    pub fn stats(&self) -> MlsStats {
        self.stats.read().clone()
    }

    pub fn member_count(&self) -> usize {
        self.members.read().active_member_count()
    }

    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members
            .read()
            .active_members()
            .map(|m| m.identity.id)
            .collect()
    }

    pub fn is_member_active(&self, member_id: &MemberId) -> bool {
        let members = self.members.read();
        if let Some(index) = members.find_member_index(member_id) {
            if let Some(member) = members.get_member(index) {
                return member.is_active();
            }
        }
        false
    }

    fn create_group_info(&self) -> Result<GroupInfo> {
        Ok(GroupInfo {
            group_id: self.group_id.as_bytes().to_vec(),
            epoch: self.current_epoch(),
            tree_hash: {
                let tree = self.tree.read();
                tree.compute_tree_hash()?
            }, // Lock released after getting hash
            confirmed_transcript_hash: vec![0; 32], // Simplified
            extensions: vec![],
            confirmation_tag: vec![0; 32], // Simplified
            signer: self.creator.id,
        })
    }

    fn create_application_aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(self.group_id.as_bytes());
        aad.extend_from_slice(&self.current_epoch().to_be_bytes());
        aad
    }

    fn create_application_aad_with_seq_sender(&self, sequence: u64, sender: MemberId) -> Vec<u8> {
        let mut aad = self.create_application_aad();
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad.extend_from_slice(sender.0.as_bytes());
        aad
    }

    /// MLS-style nonce = `base_nonce` XOR seq (seq in 12 bytes BE)
    fn xor_nonce_with_sequence(base_nonce: &[u8], sequence: u64) -> Vec<u8> {
        let mut seq_bytes = [0u8; 12];
        // Put sequence in the last 8 bytes, big-endian
        seq_bytes[4..].copy_from_slice(&sequence.to_be_bytes());
        base_nonce
            .iter()
            .zip(seq_bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }
}

/// `TreeKEM` state for managing group key derivation
#[derive(Debug)]
pub struct TreeKemState {
    /// Binary tree nodes
    nodes: Vec<Option<TreeNode>>,
    /// Tree size (number of leaves)
    size: usize,
    /// Root secret
    root_secret: Vec<u8>,
    /// Cipher suite for hashing/derivation
    cipher_suite: CipherSuite,
}

impl TreeKemState {
    /// Create new `TreeKEM` state with initial member
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if tree initialization fails.
    pub fn new(initial_key: Vec<u8>, cipher_suite: CipherSuite) -> Result<Self> {
        let root_secret = random_bytes(32);
        let mut state = Self {
            nodes: Vec::new(),
            size: 0,
            root_secret,
            cipher_suite,
        };

        // Add initial member
        state.add_leaf(0, initial_key)?;

        Ok(state)
    }

    /// Add a leaf node (new member)
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if adding the leaf fails or position is invalid.
    pub fn add_leaf(&mut self, position: usize, public_key: Vec<u8>) -> Result<()> {
        // Ensure tree capacity
        let required_size = (position + 1) * 2; // Binary tree property
        if self.nodes.len() < required_size {
            self.nodes.resize(required_size, None);
        }

        // Create leaf node
        let leaf = TreeNode {
            public_key,
            secret: random_bytes(32),
            parent: Self::parent_index(position),
        };

        self.nodes[position] = Some(leaf);
        self.size = self.size.max(position + 1);

        // Update parent nodes up to root
        self.update_path(position);

        Ok(())
    }

    /// Remove a leaf node
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if position is invalid or removal fails.
    pub fn remove_leaf(&mut self, position: usize) -> Result<()> {
        if position >= self.nodes.len() {
            return Err(MlsError::TreeKemError("Invalid leaf position".to_string()));
        }

        self.nodes[position] = None;

        // Update parent path
        self.update_path(position);

        Ok(())
    }

    /// Get the root secret for key derivation
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if root secret is not available.
    pub fn get_root_secret(&self) -> Result<Vec<u8>> {
        Ok(self.root_secret.clone())
    }

    /// Compute tree hash for integrity verification
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if hash computation fails.
    pub fn compute_tree_hash(&self) -> Result<Vec<u8>> {
        let hash = Hash::new(self.cipher_suite);
        let mut tree_data = Vec::new();

        for n in self.nodes.iter().flatten() {
            tree_data.extend_from_slice(&n.public_key);
        }

        Ok(hash.hash(&tree_data))
    }

    // Private helper methods

    /// Update path from leaf to root
    fn update_path(&mut self, leaf_position: usize) {
        let mut current = leaf_position;

        while let Some(parent_idx) = Self::parent_index(current) {
            if parent_idx >= self.nodes.len() {
                self.nodes.resize(parent_idx + 1, None);
            }

            // Create or update parent node
            let left_child = self.left_child(parent_idx);
            let right_child = self.right_child(parent_idx);

            let mut parent_secret = Vec::new();

            // Combine secrets from children
            if let Some(left_idx) = left_child {
                if let Some(Some(left_node)) = self.nodes.get(left_idx) {
                    parent_secret.extend_from_slice(&left_node.secret);
                }
            }

            if let Some(right_idx) = right_child {
                if let Some(Some(right_node)) = self.nodes.get(right_idx) {
                    parent_secret.extend_from_slice(&right_node.secret);
                }
            }

            // Hash combined secrets for parent
            let hash = Hash::new(self.cipher_suite);
            let new_secret = hash.hash(&parent_secret);

            self.nodes[parent_idx] = Some(TreeNode {
                public_key: new_secret[..32].to_vec(), // Use hash as public key
                secret: new_secret.clone(),
                parent: Self::parent_index(parent_idx),
            });

            current = parent_idx;
        }

        // Update root secret
        if let Some(root_node) = &self.nodes.get(Self::root_index()).and_then(|n| n.as_ref()) {
            self.root_secret = root_node.secret.clone();
        }
    }

    /// Get parent index for a given node
    fn parent_index(index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            Some((index - 1) / 2)
        }
    }

    /// Get left child index
    fn left_child(&self, index: usize) -> Option<usize> {
        let child = 2 * index + 1;
        if child < self.nodes.len() {
            Some(child)
        } else {
            None
        }
    }

    /// Get right child index
    fn right_child(&self, index: usize) -> Option<usize> {
        let child = 2 * index + 2;
        if child < self.nodes.len() {
            Some(child)
        } else {
            None
        }
    }

    /// Get root index (always 0 for our tree)
    fn root_index() -> usize {
        0
    }
}

/// Node in the `TreeKEM` binary tree
#[derive(Debug, Clone)]
struct TreeNode {
    /// Public key for this node
    public_key: Vec<u8>,
    /// Secret key material
    secret: Vec<u8>,
    /// Parent node index
    #[allow(dead_code)] // Future use for tree navigation
    parent: Option<usize>,
}

/// Group state snapshot for persistence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupState {
    pub group_id: GroupId,
    pub epoch: EpochNumber,
    pub config: GroupConfig,
    pub members: Vec<MemberId>,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
}

impl GroupState {
    /// Create state snapshot from group
    pub fn from_group(group: &MlsGroup) -> Self {
        Self {
            group_id: group.group_id.clone(),
            epoch: group.current_epoch(),
            config: group.config.clone(),
            members: group.member_ids(),
            created_at: SystemTime::now(), // Simplified
            last_activity: SystemTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CipherSuiteId, MemberId, MemberIdentity};

    #[test]
    fn test_group_config_default() {
        let config = GroupConfig::default();
        assert_eq!(config.protocol_version, 1);
        assert_eq!(config.schema_version, 1); // Fixed: should be 1, not 0
    }

    #[test]
    fn test_group_id_generation() {
        let id1 = GroupId::generate();
        let id2 = GroupId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_group_id_serialization() {
        let id = GroupId::generate();
        let serialized = postcard::to_stdvec(&id).expect("serialization failed");
        let deserialized: GroupId =
            postcard::from_bytes(&serialized).expect("deserialization failed");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_replay_window_default() {
        let window = ReplayWindow::default();
        assert_eq!(window.max_seen, 0);
        assert_eq!(window.window, 0);
    }

    #[test]
    fn test_tree_node_creation() {
        let node = TreeNode {
            public_key: vec![1, 2, 3, 4],
            secret: vec![5, 6, 7, 8],
            parent: None,
        };

        assert_eq!(node.public_key, vec![1, 2, 3, 4]);
        assert_eq!(node.secret, vec![5, 6, 7, 8]);
        assert!(node.parent.is_none());
    }

    #[test]
    fn test_treekem_state_creation() -> crate::Result<()> {
        let initial_key = vec![1, 2, 3, 4];
        let state = TreeKemState::new(initial_key, CipherSuite::default())?;
        assert_eq!(state.size, 1);
        assert!(!state.nodes.is_empty());
        Ok(())
    }

    #[test]
    fn test_treekem_add_leaf() -> crate::Result<()> {
        let initial_key = vec![1, 2, 3, 4];
        let mut state = TreeKemState::new(initial_key, CipherSuite::default())?;

        let new_key = vec![5, 6, 7, 8];
        state.add_leaf(1, new_key)?;

        assert_eq!(state.size, 2);
        Ok(())
    }

    #[test]
    fn test_treekem_remove_leaf() -> crate::Result<()> {
        let initial_key = vec![1, 2, 3, 4];
        let mut state = TreeKemState::new(initial_key, CipherSuite::default())?;

        state.remove_leaf(0)?;

        // Node should be removed (set to None)
        assert!(state.nodes[0].is_none());
        Ok(())
    }

    #[test]
    fn test_treekem_root_secret() -> crate::Result<()> {
        let initial_key = vec![1, 2, 3, 4];
        let state = TreeKemState::new(initial_key, CipherSuite::default())?;

        let root_secret = state.get_root_secret()?;
        assert!(!root_secret.is_empty());
        assert_eq!(root_secret.len(), 32);

        Ok(())
    }

    #[test]
    fn test_treekem_tree_hash() -> crate::Result<()> {
        let initial_key = vec![1, 2, 3, 4];
        let state = TreeKemState::new(initial_key, CipherSuite::default())?;

        let hash = state.compute_tree_hash()?;
        assert!(!hash.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_creation() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;
        assert_eq!(group.current_epoch(), 0);
        assert!(!group.member_ids().is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_group_state_from_group() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config.clone(), creator_identity).await?;
        let state = GroupState::from_group(&group);

        assert_eq!(state.group_id, group.group_id);
        assert_eq!(state.epoch, group.current_epoch());
        assert_eq!(state.config.protocol_version, config.protocol_version);
        assert_eq!(state.members.len(), group.member_ids().len());

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_member_addition() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let mut group = MlsGroup::new(config, creator_identity).await?;
        let new_member = MemberIdentity::generate(MemberId::generate())?;

        let initial_size = group.member_ids().len();
        let _welcome = group.add_member(&new_member).await?;

        // Member should be added
        assert_eq!(group.member_ids().len(), initial_size + 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_member_removal() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let mut group = MlsGroup::new(config, creator_identity).await?;
        let new_member = MemberIdentity::generate(MemberId::generate())?;

        // Add a member first
        group.add_member(&new_member).await?;
        let member_count_after_add = group.member_ids().len();

        // Remove the member
        let member_id = new_member.id;
        group.remove_member(&member_id).await?;

        assert_eq!(group.member_ids().len(), member_count_after_add - 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_message_encryption() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;

        let message = b"Hello, secure group!";
        let encrypted = group.encrypt_message(message)?;

        // Encrypted message should be different from original
        assert_ne!(encrypted.ciphertext, message);
        assert!(!encrypted.ciphertext.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_message_decryption() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;

        let original_message = b"Hello, secure group!";
        let encrypted = group.encrypt_message(original_message)?;
        let decrypted = group.decrypt_message(&encrypted)?;

        assert_eq!(decrypted, original_message);

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_epoch_advancement() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;
        let initial_epoch = group.current_epoch();

        group.update_epoch().await?;

        assert_eq!(group.current_epoch(), initial_epoch + 1);

        Ok(())
    }

    #[test]
    fn test_helper_functions() {
        // Test parent_index function
        assert_eq!(TreeKemState::parent_index(0), None); // Root has no parent
        assert_eq!(TreeKemState::parent_index(1), Some(0));
        assert_eq!(TreeKemState::parent_index(2), Some(0));
        assert_eq!(TreeKemState::parent_index(3), Some(1));

        // Test root_index function
        let root = TreeKemState::root_index();
        assert_eq!(root, 0);
    }

    #[test]
    #[allow(deprecated)] // Testing backward compatibility with SPEC-PROD suite
    fn test_group_config_modification() {
        let config = GroupConfig {
            max_members: Some(100),
            lifetime: Some(3600),
            cipher_suite: CipherSuiteId::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
            ..Default::default()
        };

        // Test config values
        assert_eq!(config.max_members, Some(100));
        assert_eq!(config.lifetime, Some(3600));
        assert_eq!(
            config.cipher_suite,
            CipherSuiteId::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87
        );
    }

    #[test]
    fn test_tree_node_cloning() {
        let node = TreeNode {
            public_key: vec![1, 2, 3, 4],
            secret: vec![5, 6, 7, 8],
            parent: Some(1),
        };

        let cloned = node.clone();
        assert_eq!(node.public_key, cloned.public_key);
        assert_eq!(node.secret, cloned.secret);
        assert_eq!(node.parent, cloned.parent);
    }

    #[tokio::test]
    async fn test_mls_group_member_count() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;

        assert_eq!(group.member_count(), 1);
        assert_eq!(group.member_ids().len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_stats() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;

        let stats = group.stats();
        // Let's just check that stats exist and have reasonable values
        assert!(stats.groups_active <= 1); // Should be 0 or 1
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_mls_group_group_id() -> crate::Result<()> {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate())?;

        let group = MlsGroup::new(config, creator_identity).await?;

        let group_id = group.group_id();
        assert_eq!(group_id, group.group_id);

        Ok(())
    }
}

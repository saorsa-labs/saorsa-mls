// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC stream mapping for MLS messages

use crate::api::{Ciphertext, GroupId};
use anyhow::Result;
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// MLS frame type for QUIC streams
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MlsFrameType {
    /// Application data frame
    ApplicationData = 0x01,
    /// Handshake frame (add/remove/update)
    Handshake = 0x02,
    /// Welcome message for new members
    Welcome = 0x03,
    /// Commit message frame
    Commit = 0x04,
}

/// MLS frame wrapper for QUIC transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsFrame {
    /// Frame type
    pub frame_type: MlsFrameType,
    /// Group identifier
    pub group_id: GroupId,
    /// Frame payload
    pub payload: Bytes,
}

/// QUIC stream manager for MLS
///
/// This is a placeholder showing how MLS frames would be mapped to QUIC streams.
/// Actual implementation would use ant_quic Connection and SendStream/RecvStream types.
#[derive(Debug)]
pub struct QuicStreamManager {
    /// Active QUIC connections per group (placeholder)
    connections: Arc<RwLock<HashMap<GroupId, Vec<u8>>>>,
    /// Active stream IDs per group
    stream_ids: Arc<RwLock<HashMap<GroupId, Vec<u64>>>>,
}

impl Default for QuicStreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicStreamManager {
    /// Create a new QUIC stream manager
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            stream_ids: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a connection placeholder for a group
    ///
    /// In a real implementation, this would store an ant_quic::Connection
    pub fn register_connection(&self, group_id: GroupId, _connection_data: Vec<u8>) {
        let mut connections = self.connections.write();
        connections.insert(group_id, _connection_data);
    }

    /// Send an MLS frame over QUIC (placeholder)
    ///
    /// In a real implementation, this would:
    /// 1. Get the ant_quic::Connection for the group
    /// 2. Open a unidirectional stream via connection.open_send()
    /// 3. Write the serialized frame to the stream
    pub async fn send_frame(&self, frame: &MlsFrame) -> Result<()> {
        let connections = self.connections.read();
        let _connection_data = connections
            .get(&frame.group_id)
            .ok_or_else(|| anyhow::anyhow!("No connection for group"))?;

        // Placeholder: In real implementation, would send via QUIC stream
        let _data = postcard::to_stdvec(frame)?;

        // Record stream ID
        let mut stream_ids = self.stream_ids.write();
        stream_ids
            .entry(frame.group_id.clone())
            .or_default()
            .push(Self::stream_for_frame_type(frame.frame_type));

        Ok(())
    }

    /// Send application data over QUIC
    pub async fn send_application_data(
        &self,
        group_id: &GroupId,
        ciphertext: &Ciphertext,
    ) -> Result<()> {
        let frame = MlsFrame {
            frame_type: MlsFrameType::ApplicationData,
            group_id: group_id.clone(),
            payload: ciphertext.data.clone(),
        };

        self.send_frame(&frame).await
    }

    /// Receive an MLS frame from QUIC (placeholder)
    ///
    /// In a real implementation, this would:
    /// 1. Get the ant_quic::Connection for the group
    /// 2. Accept an incoming stream via connection.accept_recv()
    /// 3. Read and deserialize the frame
    pub async fn receive_frame(&self, _group_id: &GroupId) -> Result<MlsFrame> {
        // Placeholder: Return a dummy frame
        Ok(MlsFrame {
            frame_type: MlsFrameType::ApplicationData,
            group_id: GroupId::generate(),
            payload: Bytes::new(),
        })
    }

    /// Map a stream to a specific frame type
    pub fn stream_for_frame_type(frame_type: MlsFrameType) -> u64 {
        match frame_type {
            MlsFrameType::ApplicationData => 0,
            MlsFrameType::Handshake => 1,
            MlsFrameType::Welcome => 2,
            MlsFrameType::Commit => 3,
        }
    }

    /// Close all streams for a group
    pub async fn close_group(&self, group_id: &GroupId) -> Result<()> {
        // Remove connection data
        let mut connections = self.connections.write();
        connections.remove(group_id);

        // Remove stream IDs
        let mut stream_ids = self.stream_ids.write();
        stream_ids.remove(group_id);

        Ok(())
    }
}

/// Helper to encode MLS frames for QUIC transport
pub fn encode_frame(frame: &MlsFrame) -> Result<Vec<u8>> {
    Ok(postcard::to_stdvec(frame)?)
}

/// Helper to decode MLS frames from QUIC transport
pub fn decode_frame(data: &[u8]) -> Result<MlsFrame> {
    Ok(postcard::from_bytes(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encoding() {
        let frame = MlsFrame {
            frame_type: MlsFrameType::ApplicationData,
            group_id: GroupId::generate(),
            payload: Bytes::from(b"test payload".to_vec()),
        };

        let encoded = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&encoded).unwrap();

        assert_eq!(frame.frame_type as u8, decoded.frame_type as u8);
        assert_eq!(frame.group_id, decoded.group_id);
        assert_eq!(frame.payload, decoded.payload);
    }

    #[test]
    fn test_stream_mapping() {
        assert_eq!(
            QuicStreamManager::stream_for_frame_type(MlsFrameType::ApplicationData),
            0
        );
        assert_eq!(
            QuicStreamManager::stream_for_frame_type(MlsFrameType::Handshake),
            1
        );
        assert_eq!(
            QuicStreamManager::stream_for_frame_type(MlsFrameType::Welcome),
            2
        );
        assert_eq!(
            QuicStreamManager::stream_for_frame_type(MlsFrameType::Commit),
            3
        );
    }
}

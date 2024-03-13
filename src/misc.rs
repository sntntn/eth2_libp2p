use crate::MessageId;

use libp2p::PeerId;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct GossipId {
    pub source: PeerId,
    pub message_id: MessageId,
}

impl Default for GossipId {
    fn default() -> Self {
        Self {
            source: PeerId::from_bytes(&[0; 2]).expect("PeerId byte length should be valid"),
            message_id: MessageId::new(&[]),
        }
    }
}

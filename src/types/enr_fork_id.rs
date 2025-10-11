use ssz::Ssz;
use types::phase0::primitives::{Epoch, ForkDigest, Version};

#[derive(Debug, Clone, Copy, Default, Ssz)]
pub struct EnrForkId {
    pub fork_digest: ForkDigest,
    pub next_fork_version: Version,
    pub next_fork_epoch: Epoch,
}

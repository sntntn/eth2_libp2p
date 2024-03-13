pub(crate) mod base;
pub(crate) mod ssz_snappy;

use self::base::{BaseInboundCodec, BaseOutboundCodec};
use self::ssz_snappy::{SSZSnappyInboundCodec, SSZSnappyOutboundCodec};
use crate::rpc::protocol::RPCError;
use crate::rpc::{InboundRequest, OutboundRequest, RPCCodedResponse};
use libp2p::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use types::preset::Preset;

// Known types of codecs
pub enum InboundCodec<P: Preset> {
    SSZSnappy(BaseInboundCodec<SSZSnappyInboundCodec<P>, P>),
}

pub enum OutboundCodec<P: Preset> {
    SSZSnappy(BaseOutboundCodec<SSZSnappyOutboundCodec<P>, P>),
}

impl<P: Preset> Encoder<RPCCodedResponse<P>> for InboundCodec<P> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCCodedResponse<P>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            InboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<P: Preset> Decoder for InboundCodec<P> {
    type Item = InboundRequest<P>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            InboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}

impl<P: Preset> Encoder<OutboundRequest<P>> for OutboundCodec<P> {
    type Error = RPCError;

    fn encode(&mut self, item: OutboundRequest<P>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            OutboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<P: Preset> Decoder for OutboundCodec<P> {
    type Item = RPCCodedResponse<P>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            OutboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}

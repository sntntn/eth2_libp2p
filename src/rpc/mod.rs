//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use handler::RPCHandler;
use libp2p::core::transport::PortUse;
use libp2p::swarm::{
    handler::ConnectionHandler, CloseConnection, ConnectionId, NetworkBehaviour, NotifyHandler,
    ToSwarm,
};
use libp2p::swarm::{ConnectionClosed, FromSwarm, SubstreamProtocol, THandlerInEvent};
use libp2p::PeerId;
use slog::o;
use tracing::{debug, trace};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std_ext::ArcExt as _;
use types::{config::Config as ChainConfig, preset::Preset};

use crate::types::ForkContext;

pub(crate) use handler::{HandlerErr, HandlerEvent};
pub(crate) use methods::{
    MetaData, MetaDataV1, MetaDataV2, MetaDataV3, Ping, RpcResponse, RpcSuccessResponse,
};
pub use protocol::RequestType;

use self::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig};
use self::protocol::RPCProtocol;
use self::self_limiter::SelfRateLimiter;
use crate::rpc::rate_limiter::RateLimiterItem;
use crate::rpc::response_limiter::ResponseLimiter;
pub use handler::SubstreamId;
pub use methods::{
    BlobsByRangeRequest, BlobsByRootRequest, BlocksByRangeRequest, BlocksByRootRequest,
    GoodbyeReason, LightClientBootstrapRequest, ResponseTermination, RpcErrorResponse,
    StatusMessage,
};
pub use protocol::{Protocol, RPCError};

pub(crate) mod codec;
pub mod config;
mod handler;
pub mod methods;
mod outbound;
mod protocol;
mod rate_limiter;
mod response_limiter;
mod self_limiter;

// Maximum number of concurrent requests per protocol ID that a client may issue.
const MAX_CONCURRENT_REQUESTS: usize = 2;

/// Composite trait for a request id.
pub trait ReqId: Send + 'static + std::fmt::Debug + Copy + Clone {}
impl<T> ReqId for T where T: Send + 'static + std::fmt::Debug + Copy + Clone {}

/// RPC events sent from the application.
#[derive(Debug, Clone)]
pub enum RPCSend<Id, P: Preset> {
    /// A request sent from the application.
    ///
    /// The `Id` is given by the application making the request. These
    /// go over *outbound* connections.
    Request(Id, RequestType<P>),
    /// A response sent from the application..
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RpcResponse<P>),
    /// Application has requested to terminate the connection with a goodbye message.
    Shutdown(Id, GoodbyeReason),
}

/// RPC events received from outside the application.
#[derive(Debug, Clone)]
pub enum RPCReceived<Id, P: Preset> {
    /// A request received from the outside.
    ///
    /// The `SubstreamId` is given by the `RPCHandler` as it identifies this request with the
    /// *inbound* substream over which it is managed.
    Request(InboundRequestId, RequestType<P>),
    /// A response received from the outside.
    ///
    /// The `Id` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(Id, RpcSuccessResponse<P>),
    /// Marks a request as completed
    EndOfStream(Id, ResponseTermination),
}

// An identifier for the inbound requests received via Rpc.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct InboundRequestId {
    /// The connection ID of the peer that sent the request.
    connection_id: ConnectionId,
    /// The ID of the substream that sent the request.
    substream_id: SubstreamId,
}

// An Active inbound request received via Rpc.
struct ActiveInboundRequest<P: Preset> {
    pub peer_id: PeerId,
    pub request_type: RequestType<P>,
    pub peer_disconnected: bool,
}

impl InboundRequestId {
    /// Creates an _unchecked_ [`InboundRequestId`].
    ///
    /// [`Rpc`] enforces that [`InboundRequestId`]s are unique and not reused.
    /// This constructor does not, hence the _unchecked_.
    ///
    /// It is primarily meant for allowing manual tests.
    pub fn new_unchecked(connection_id: usize, substream_id: usize) -> Self {
        Self {
            connection_id: ConnectionId::new_unchecked(connection_id),
            substream_id: SubstreamId::new(substream_id),
        }
    }
}

impl<P: Preset, Id: std::fmt::Debug> std::fmt::Display for RPCSend<Id, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCSend::Request(id, req) => write!(f, "RPC Request(id: {:?}, {})", id, req),
            RPCSend::Response(id, res) => write!(f, "RPC Response(id: {:?}, {})", id, res),
            RPCSend::Shutdown(_id, reason) => write!(f, "Sending Goodbye: {}", reason),
        }
    }
}

/// Messages sent to the user from the RPC protocol.
#[derive(Debug)]
pub struct RPCMessage<Id, P: Preset> {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// Handler managing this message.
    pub connection_id: ConnectionId,
    /// The message that was sent.
    pub message: Result<RPCReceived<Id, P>, HandlerErr<Id>>,
}

type BehaviourAction<Id, P> = ToSwarm<RPCMessage<Id, P>, RPCSend<Id, P>>;

pub struct NetworkParams {
    pub max_payload_size: usize,
    pub ttfb_timeout: Duration,
    pub resp_timeout: Duration,
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<Id: ReqId, P: Preset> {
    chain_config: Arc<ChainConfig>,
    /// Rate limiter for our responses.
    response_limiter: Option<ResponseLimiter<P>>,
    /// Rate limiter for our own requests.
    outbound_request_limiter: SelfRateLimiter<Id, P>,
    /// Active inbound requests that are awaiting a response.
    active_inbound_requests: HashMap<InboundRequestId, ActiveInboundRequest<P>>,
    /// Queue of events to be processed.
    events: Vec<BehaviourAction<Id, P>>,
    fork_context: Arc<ForkContext>,
    enable_light_client_server: bool,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
    /// Networking constant values
    network_params: NetworkParams,
    /// A sequential counter indicating when data gets modified.
    seq_number: u64,
}

impl<Id: ReqId, P: Preset> RPC<Id, P> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        fork_context: Arc<ForkContext>,
        enable_light_client_server: bool,
        inbound_rate_limiter_config: Option<InboundRateLimiterConfig>,
        outbound_rate_limiter_config: Option<OutboundRateLimiterConfig>,
        log: slog::Logger,
        network_params: NetworkParams,
        seq_number: u64,
    ) -> Self {
        let log = log.new(o!("service" => "libp2p_rpc"));

        let response_limiter = inbound_rate_limiter_config.map(|config| {
            debug!(?config, "Using response rate limiting params");
            ResponseLimiter::new(config, fork_context.clone(), log.clone())
                .expect("Inbound limiter configuration parameters are valid")
        });

        let outbound_request_limiter: SelfRateLimiter<Id, P> = SelfRateLimiter::new(
            outbound_rate_limiter_config,
            fork_context.clone(),
            log.clone(),
        )
        .expect("Outbound limiter configuration parameters are valid");

        RPC {
            chain_config,
            response_limiter,
            outbound_request_limiter,
            active_inbound_requests: HashMap::new(),
            events: Vec::new(),
            fork_context,
            enable_light_client_server,
            log,
            network_params,
            seq_number,
        }
    }

    /// Sends an RPC response.
    /// Returns an `Err` if the request does exist in the active inbound requests list.
    pub fn send_response(
        &mut self,
        request_id: InboundRequestId,
        response: RpcResponse<P>,
    ) -> Result<(), RpcResponse<P>> {
        let Some(ActiveInboundRequest {
            peer_id,
            request_type,
            peer_disconnected,
        }) = self.active_inbound_requests.remove(&request_id)
        else {
            return Err(response);
        };

        // Add the request back to active requests if the response is `Success` and requires stream
        // termination.
        if request_type.protocol().terminator().is_some()
            && matches!(response, RpcResponse::Success(_))
        {
            self.active_inbound_requests.insert(
                request_id,
                ActiveInboundRequest {
                    peer_id,
                    request_type: request_type.clone(),
                    peer_disconnected,
                },
            );
        }

        if peer_disconnected {
            trace!(
                %peer_id, 
                ?request_id, 
                %response,
                "Discarding response, peer is no longer connected"
            );

            return Ok(());
        }

        self.send_response_inner(peer_id, request_type.protocol(), request_id, response);
        Ok(())
    }

    fn send_response_inner(
        &mut self,
        peer_id: PeerId,
        protocol: Protocol,
        request_id: InboundRequestId,
        response: RpcResponse<P>,
    ) {
        if let Some(response_limiter) = self.response_limiter.as_mut() {
            if !response_limiter.allows(
                peer_id,
                protocol,
                request_id.connection_id,
                request_id.substream_id,
                response.clone(),
            ) {
                // Response is logged and queued internally in the response limiter.
                return;
            }
        }

        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(request_id.connection_id),
            event: RPCSend::Response(request_id.substream_id, response),
        });
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: Id, req: RequestType<P>) {
        match self
            .outbound_request_limiter
            .allows(peer_id, request_id, req)
        {
            Ok(event) => self.events.push(BehaviourAction::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event,
            }),
            Err(_e) => {
                // Request is logged and queued internally in the self rate limiter.
            }
        }
    }

    /// Application wishes to disconnect from this peer by sending a Goodbye message. This
    /// gracefully terminates the RPC behaviour with a goodbye message.
    pub fn shutdown(&mut self, peer_id: PeerId, id: Id, reason: GoodbyeReason) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Shutdown(id, reason),
        });
    }

    pub fn update_seq_number(&mut self, seq_number: u64) {
        self.seq_number = seq_number
    }

    /// Send a Ping request to the destination `PeerId` via `ConnectionId`.
    pub fn ping(&mut self, peer_id: PeerId, id: Id) {
        let ping = Ping {
            data: self.seq_number,
        };
        trace!(%peer_id, "Sending Ping");
        self.send_request(peer_id, id, RequestType::Ping(ping));
    }
}

impl<Id, P> NetworkBehaviour for RPC<Id, P>
where
    P: Preset,
    Id: ReqId,
{
    type ConnectionHandler = RPCHandler<Id, P>;
    type ToSwarm = RPCMessage<Id, P>;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        let protocol = SubstreamProtocol::new(
            RPCProtocol {
                chain_config: self.chain_config.clone_arc(),
                fork_context: self.fork_context.clone(),
                max_rpc_size: self.chain_config.max_payload_size,
                enable_light_client_server: self.enable_light_client_server,
                phantom: PhantomData,
                ttfb_timeout: self.network_params.ttfb_timeout,
            },
            (),
        );
        let log = self
            .log
            .new(slog::o!("peer_id" => peer_id.to_string(), "connection_id" => connection_id.to_string()));
        let handler = RPCHandler::new(
            protocol,
            self.fork_context.clone(),
            self.network_params.resp_timeout,
            peer_id,
            connection_id,
            &log,
        );

        Ok(handler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        let protocol = SubstreamProtocol::new(
            RPCProtocol {
                chain_config: self.chain_config.clone_arc(),
                fork_context: self.fork_context.clone(),
                max_rpc_size: self.chain_config.max_payload_size,
                enable_light_client_server: self.enable_light_client_server,
                phantom: PhantomData,
                ttfb_timeout: self.network_params.ttfb_timeout,
            },
            (),
        );

        let log = self
            .log
            .new(slog::o!("peer_id" => peer_id.to_string(), "connection_id" => connection_id.to_string()));

        let handler = RPCHandler::new(
            protocol,
            self.fork_context.clone(),
            self.network_params.resp_timeout,
            peer_id,
            connection_id,
            &log,
        );

        Ok(handler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // NOTE: FromSwarm is a non exhaustive enum so updates should be based on release notes more
        // than compiler feedback
        // The self rate limiter holds on to requests and attempts to process them within our rate
        // limits. If a peer disconnects whilst we are self-rate limiting, we want to terminate any
        // pending requests and return an error response to the application.

        if let FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            remaining_established,
            connection_id,
            ..
        }) = event
        {
            // If there are still connections remaining, do nothing.
            if remaining_established > 0 {
                return;
            }

            // Get a list of pending requests from the self rate limiter
            for (id, proto) in self.outbound_request_limiter.peer_disconnected(peer_id) {
                let error_msg = ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Err(HandlerErr::Outbound {
                        id,
                        proto,
                        error: RPCError::Disconnected,
                    }),
                });
                self.events.push(error_msg);
            }

            self.active_inbound_requests
                .values_mut()
                .filter(|request| request.peer_id == peer_id)
                .for_each(|request| request.peer_disconnected = true);

            if let Some(limiter) = self.response_limiter.as_mut() {
                limiter.peer_disconnected(peer_id);
            }

            // Replace the pending Requests to the disconnected peer
            // with reports of failed requests.
            self.events.iter_mut().for_each(|event| match &event {
                ToSwarm::NotifyHandler {
                    peer_id: p,
                    event: RPCSend::Request(request_id, req),
                    ..
                } if *p == peer_id => {
                    *event = ToSwarm::GenerateEvent(RPCMessage {
                        peer_id,
                        connection_id,
                        message: Err(HandlerErr::Outbound {
                            id: *request_id,
                            proto: req.versioned_protocol().protocol(),
                            error: RPCError::Disconnected,
                        }),
                    });
                }
                _ => {}
            });
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: <Self::ConnectionHandler as ConnectionHandler>::ToBehaviour,
    ) {
        match event {
            HandlerEvent::Ok(RPCReceived::Request(request_id, request_type)) => {
                let is_concurrent_request_limit_exceeded = self
                    .active_inbound_requests
                    .iter()
                    .filter(
                        |(
                            _inbound_request_id,
                            ActiveInboundRequest {
                                peer_id: request_peer_id,
                                request_type: active_request_type,
                                peer_disconnected,
                            },
                        )| {
                            *request_peer_id == peer_id
                                && active_request_type.protocol() == request_type.protocol()
                                && !peer_disconnected
                        },
                    )
                    .count()
                    >= MAX_CONCURRENT_REQUESTS;

                // Restricts more than MAX_CONCURRENT_REQUESTS inbound requests from running simultaneously on the same protocol per peer.
                if is_concurrent_request_limit_exceeded {
                    // There is already an active request with the same protocol. Send an error code to the peer.
                    debug!(
                        request = %request_type,
                        protocol = %request_type.protocol(), 
                        %peer_id, 
                        "There is an active request with the same protocol"
                    );


                    self.send_response_inner(
                        peer_id,
                        request_type.protocol(),
                        request_id,
                        RpcResponse::Error(
                            RpcErrorResponse::RateLimited,
                            format!("Rate limited. There are already {MAX_CONCURRENT_REQUESTS} active requests with the same protocol")
                                .into(),
                        ),
                    );
                    return;
                }

                // Requests that are below the limit on the number of simultaneous requests are added to the active inbound requests.
                self.active_inbound_requests.insert(
                    request_id,
                    ActiveInboundRequest {
                        peer_id,
                        request_type: request_type.clone(),
                        peer_disconnected: false,
                    },
                );

                // If we received a Ping, we queue a Pong response.
                if let RequestType::Ping(_) = request_type {
                    trace!(connection_id = %connection_id, %peer_id, "Received Ping, queueing Pong");

                    self.send_response(
                        request_id,
                        RpcResponse::Success(RpcSuccessResponse::Pong(Ping {
                            data: self.seq_number,
                        })),
                    )
                    .expect("Request to exist");
                }

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Ok(RPCReceived::Request(request_id, request_type)),
                }));
            }
            HandlerEvent::Ok(RPCReceived::Response(id, response)) => {
                if response.protocol().terminator().is_none() {
                    // Inform the limiter that a response has been received.
                    self.outbound_request_limiter
                        .request_completed(&peer_id, response.protocol());
                }

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Ok(RPCReceived::Response(id, response)),
                }));
            }
            HandlerEvent::Ok(RPCReceived::EndOfStream(id, response_termination)) => {
                // Inform the limiter that a response has been received.
                self.outbound_request_limiter
                    .request_completed(&peer_id, response_termination.as_protocol());

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Ok(RPCReceived::EndOfStream(id, response_termination)),
                }));
            }
            HandlerEvent::Err(err) => {
                // Inform the limiter that the request has ended with an error.
                let protocol = match err {
                    HandlerErr::Inbound { proto, .. } | HandlerErr::Outbound { proto, .. } => proto,
                };
                self.outbound_request_limiter
                    .request_completed(&peer_id, protocol);

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Err(err),
                }));
            }
            HandlerEvent::Close(_) => {
                // Handle the close event here.
                self.events.push(ToSwarm::CloseConnection {
                    peer_id,
                    connection: CloseConnection::All,
                });
            }
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(response_limiter) = self.response_limiter.as_mut() {
            if let Poll::Ready(responses) = response_limiter.poll_ready(cx) {
                for response in responses {
                    self.events.push(ToSwarm::NotifyHandler {
                        peer_id: response.peer_id,
                        handler: NotifyHandler::One(response.connection_id),
                        event: RPCSend::Response(response.substream_id, response.response),
                    });
                }
            }
        }

        if let Poll::Ready(event) = self.outbound_request_limiter.poll_ready(cx) {
            self.events.push(event)
        }

        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }

        Poll::Pending
    }
}

impl<Id, P> slog::KV for RPCMessage<Id, P>
where
    P: Preset,
    Id: ReqId,
{
    fn serialize(
        &self,
        _record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments("peer_id", &format_args!("{}", self.peer_id))?;
        match &self.message {
            Ok(received) => {
                let (msg_kind, protocol) = match received {
                    RPCReceived::Request(_, request_type) => {
                        ("request", request_type.versioned_protocol().protocol())
                    }
                    RPCReceived::Response(_, res) => ("response", res.protocol()),
                    RPCReceived::EndOfStream(_, end) => (
                        "end_of_stream",
                        match end {
                            ResponseTermination::BlocksByRange => Protocol::BlocksByRange,
                            ResponseTermination::BlocksByRoot => Protocol::BlocksByRoot,
                            ResponseTermination::BlobsByRange => Protocol::BlobsByRange,
                            ResponseTermination::BlobsByRoot => Protocol::BlobsByRoot,
                            ResponseTermination::DataColumnsByRoot => Protocol::DataColumnsByRoot,
                            ResponseTermination::DataColumnsByRange => Protocol::DataColumnsByRange,
                            ResponseTermination::LightClientUpdatesByRange => {
                                Protocol::LightClientUpdatesByRange
                            }
                        },
                    ),
                };
                serializer.emit_str("msg_kind", msg_kind)?;
                serializer.emit_arguments("protocol", &format_args!("{}", protocol))?;
            }
            Err(error) => {
                let (msg_kind, protocol) = match &error {
                    HandlerErr::Inbound { proto, .. } => ("inbound_err", *proto),
                    HandlerErr::Outbound { proto, .. } => ("outbound_err", *proto),
                };
                serializer.emit_str("msg_kind", msg_kind)?;
                serializer.emit_arguments("protocol", &format_args!("{}", protocol))?;
            }
        };

        slog::Result::Ok(())
    }
}

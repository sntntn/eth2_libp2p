use crate::common::metrics;
use crate::rpc::config::InboundRateLimiterConfig;
use crate::rpc::rate_limiter::{RPCRateLimiter, RateLimitedErr};
use crate::rpc::self_limiter::timestamp_now;
use crate::rpc::{Protocol, RpcResponse, SubstreamId};
use crate::types::ForkContext;
use crate::PeerId;
use futures::FutureExt;
use libp2p::swarm::ConnectionId;
use tracing::debug;
use logging::crit;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_util::time::DelayQueue;
use types::preset::Preset;

/// A response that was rate limited or waiting on rate limited responses for the same peer and
/// protocol.
#[derive(Clone)]
pub(super) struct QueuedResponse<P: Preset> {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub substream_id: SubstreamId,
    pub response: RpcResponse<P>,
    pub protocol: Protocol,
    pub queued_at: Duration,
}

pub(super) struct ResponseLimiter<P: Preset> {
    /// Rate limiter for our responses.
    limiter: RPCRateLimiter,
    /// Responses queued for sending. These responses are stored when the response limiter rejects them.
    delayed_responses: HashMap<(PeerId, Protocol), VecDeque<QueuedResponse<P>>>,
    /// The delay required to allow a peer's outbound response per protocol.
    next_response: DelayQueue<(PeerId, Protocol)>,
}

impl<P: Preset> ResponseLimiter<P> {
    /// Creates a new [`ResponseLimiter`] based on configuration values.
    pub fn new(
        config: InboundRateLimiterConfig,
        fork_context: Arc<ForkContext>,
    ) -> Result<Self, &'static str> {
        Ok(ResponseLimiter {
            limiter: RPCRateLimiter::new_with_config(config.0, fork_context)?,
            delayed_responses: HashMap::new(),
            next_response: DelayQueue::new(),
        })
    }

    /// Checks if the rate limiter allows the response. When not allowed, the response is delayed
    /// until it can be sent.
    pub fn allows(
        &mut self,
        peer_id: PeerId,
        protocol: Protocol,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        response: RpcResponse<P>,
    ) -> bool {
        // First check that there are not already other responses waiting to be sent.
        if let Some(queue) = self.delayed_responses.get_mut(&(peer_id, protocol)) {
            debug!(%peer_id, %protocol, "Response rate limiting since there are already other responses waiting to be sent");
            queue.push_back(QueuedResponse {
                peer_id,
                connection_id,
                substream_id,
                response,
                protocol,
                queued_at: timestamp_now(),
            });
            return false;
        }

        if let Err(wait_time) = Self::try_limiter(
            &mut self.limiter,
            peer_id,
            response.clone(),
            protocol,
        ) {
            self.delayed_responses
                .entry((peer_id, protocol))
                .or_default()
                .push_back(QueuedResponse {
                    peer_id,
                    connection_id,
                    substream_id,
                    response,
                    protocol,
                    queued_at: timestamp_now(),
                });
            self.next_response.insert((peer_id, protocol), wait_time);
            return false;
        }

        true
    }

    /// Checks if the limiter allows the response. If the response should be delayed, the duration
    /// to wait is returned.
    fn try_limiter(
        limiter: &mut RPCRateLimiter,
        peer_id: PeerId,
        response: RpcResponse<P>,
        protocol: Protocol,
    ) -> Result<(), Duration> {
        match limiter.allows(&peer_id, &(response.clone(), protocol)) {
            Ok(()) => Ok(()),
            Err(e) => match e {
                RateLimitedErr::TooLarge => {
                    // This should never happen with default parameters. Let's just send the response.
                    // Log a crit since this is a config issue.
                    crit!(
                        %protocol,
                        "Response rate limiting error for a batch that will never fit. Sending response anyway. Check configuration parameters."
                    );
                    Ok(())
                }
                RateLimitedErr::TooSoon(wait_time) => {
                    debug!(%peer_id, %protocol, wait_time_ms = wait_time.as_millis(), "Response rate limiting");
                    Err(wait_time)
                }
            },
        }
    }

    /// Informs the limiter that a peer has disconnected. This removes any pending responses.
    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        self.delayed_responses
            .retain(|(map_peer_id, _protocol), _queue| map_peer_id != &peer_id);
    }

    /// When a peer and protocol are allowed to send a next response, this function checks the
    /// queued responses and attempts marking as ready as many as the limiter allows.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Vec<QueuedResponse<P>>> {
        let mut responses = vec![];
        while let Poll::Ready(Some(expired)) = self.next_response.poll_expired(cx) {
            let (peer_id, protocol) = expired.into_inner();

            if let Entry::Occupied(mut entry) = self.delayed_responses.entry((peer_id, protocol)) {
                let queue = entry.get_mut();
                // Take delayed responses from the queue, as long as the limiter allows it.
                while let Some(response) = queue.pop_front() {
                    match Self::try_limiter(
                        &mut self.limiter,
                        response.peer_id,
                        response.response.clone(),
                        response.protocol,
                    ) {
                        Ok(()) => {
                            metrics::observe_duration(
                                &crate::metrics::RESPONSE_IDLING,
                                timestamp_now().saturating_sub(response.queued_at),
                            );
                            responses.push(response)
                        }
                        Err(wait_time) => {
                            // The response was taken from the queue, but the limiter didn't allow it.
                            queue.push_front(response);
                            self.next_response.insert((peer_id, protocol), wait_time);
                            break;
                        }
                    }
                }
                if queue.is_empty() {
                    entry.remove();
                }
            }
        }

        // Prune the rate limiter.
        let _ = self.limiter.poll_unpin(cx);

        if !responses.is_empty() {
            return Poll::Ready(responses);
        }
        Poll::Pending
    }
}

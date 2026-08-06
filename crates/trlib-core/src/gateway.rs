//! Runtime-independent connection state machine.

use crate::Result;
use crate::config::GatewayConfig;
use crate::mtproto::{ExternalEnvelope, parse_external};
use crate::transport::{FrameStatus, Framing};

/// Result of polling caller-owned stream bytes.
#[derive(Clone, Copy, Debug)]
pub enum GatewayPoll<'a> {
    /// Buffer more bytes until at least this total size is available.
    NeedMore(u32),
    /// One complete MTProto envelope borrowing from the input stream buffer.
    Packet {
        /// Parsed external envelope.
        envelope: ExternalEnvelope<'a>,
        /// Bytes that the caller can discard after processing the event.
        consumed: u32,
    },
    /// Telegram quick acknowledgement.
    QuickAck {
        /// Acknowledgement token including its marker bit.
        token: u32,
        /// Bytes that the caller can discard.
        consumed: u8,
    },
}

/// Small per-connection gateway over a caller-selected framing implementation.
///
/// It owns no network socket and no receive buffer. The embedding reactor keeps
/// those resources and calls [`CoreGateway::poll`] whenever bytes arrive.
#[derive(Clone, Copy)]
pub struct CoreGateway<'codec> {
    framing: &'codec dyn Framing,
    config: GatewayConfig,
}

impl<'codec> CoreGateway<'codec> {
    /// Creates a gateway with explicit resource limits.
    pub const fn new(framing: &'codec dyn Framing, config: GatewayConfig) -> Self {
        Self { framing, config }
    }

    /// Returns bytes that must be written once when opening the stream.
    #[inline]
    pub fn stream_init_bytes(&self) -> &'static [u8] {
        self.framing.init_bytes()
    }

    /// Parses at most one event from the current stream prefix.
    pub fn poll<'input>(&self, input: &'input [u8]) -> Result<GatewayPoll<'input>> {
        match self.framing.decode(input, self.config.max_frame_bytes)? {
            FrameStatus::NeedMore(required) => Ok(GatewayPoll::NeedMore(required)),
            FrameStatus::QuickAck { token, consumed } => {
                Ok(GatewayPoll::QuickAck { token, consumed })
            }
            FrameStatus::Packet(bounds) => {
                let payload = bounds.payload(input).ok_or_else(|| {
                    crate::Error::new(crate::ErrorKind::InvalidPacket, 0, bounds.consumed)
                })?;
                let envelope = parse_external(payload, self.config.max_message_bytes)?;
                Ok(GatewayPoll::Packet {
                    envelope,
                    consumed: bounds.consumed,
                })
            }
        }
    }

    /// Returns the active resource limits.
    #[inline]
    pub const fn config(&self) -> GatewayConfig {
        self.config
    }
}

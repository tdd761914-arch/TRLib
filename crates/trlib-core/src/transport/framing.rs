//! Object-safe framing interface to avoid generic code duplication.

use crate::Result;

/// Location of one frame inside the supplied stream buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FrameBounds {
    /// First payload byte.
    pub payload_offset: u32,
    /// Payload length in bytes.
    pub payload_length: u32,
    /// Total bytes consumed from the stream.
    pub consumed: u32,
}

impl FrameBounds {
    /// Borrows the payload from the same input passed to `decode`.
    #[inline]
    pub fn payload(self, input: &[u8]) -> Option<&[u8]> {
        let start = self.payload_offset as usize;
        let end = start.checked_add(self.payload_length as usize)?;
        input.get(start..end)
    }
}

/// Outcome of decoding the current stream prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStatus {
    /// At least this many total buffered bytes are required.
    NeedMore(u32),
    /// One complete packet is available.
    Packet(FrameBounds),
    /// Telegram quick acknowledgement value.
    QuickAck {
        /// Acknowledgement token, including the high marker bit.
        token: u32,
        /// Bytes consumed from the stream.
        consumed: u8,
    },
}

/// Object-safe framing selected once per connection.
pub trait Framing {
    /// Bytes that initialize a fresh outbound stream.
    fn init_bytes(&self) -> &'static [u8];

    /// Finds the next frame without copying its payload.
    fn decode(&self, input: &[u8], max_frame_bytes: u32) -> Result<FrameStatus>;

    /// Serializes one frame into caller-owned memory and returns bytes written.
    fn encode(&self, payload: &[u8], output: &mut [u8]) -> Result<usize>;
}

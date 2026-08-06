//! Intermediate TCP transport (`0xeeeeeeee`).

use crate::error::{Error, ErrorKind, Result, narrow};
use crate::transport::{FrameBounds, FrameStatus, Framing};

/// Non-padded intermediate TCP framing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Intermediate;

impl Framing for Intermediate {
    #[inline]
    fn init_bytes(&self) -> &'static [u8] {
        &[0xee, 0xee, 0xee, 0xee]
    }

    fn decode(&self, input: &[u8], max_frame_bytes: u32) -> Result<FrameStatus> {
        let Some(prefix) = input.get(..4) else {
            return Ok(FrameStatus::NeedMore(4));
        };
        let prefix: &[u8; 4] = prefix
            .try_into()
            .map_err(|_| Error::new(ErrorKind::NeedMore, 0, 4))?;
        let encoded = u32::from_le_bytes(*prefix);
        if encoded & 0x8000_0000 != 0 {
            return Ok(FrameStatus::QuickAck {
                token: encoded,
                consumed: 4,
            });
        }
        if encoded == 0 || encoded & 3 != 0 {
            return Err(Error::new(ErrorKind::InvalidLength, 0, encoded));
        }
        if encoded > max_frame_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded, 0, encoded));
        }
        let total = 4usize
            .checked_add(encoded as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, encoded))?;
        if input.len() < total {
            return Ok(FrameStatus::NeedMore(narrow(total)));
        }
        Ok(FrameStatus::Packet(FrameBounds {
            payload_offset: 4,
            payload_length: encoded,
            consumed: narrow(total),
        }))
    }

    fn encode(&self, payload: &[u8], output: &mut [u8]) -> Result<usize> {
        if payload.is_empty() || payload.len() & 3 != 0 || payload.len() > 0x7fff_ffff {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                0,
                narrow(payload.len()),
            ));
        }
        let total = 4usize
            .checked_add(payload.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, narrow(payload.len())))?;
        let output_length = output.len();
        let destination = output.get_mut(..total).ok_or_else(|| {
            Error::new(
                ErrorKind::OutputTooSmall,
                0,
                narrow(total.saturating_sub(output_length)),
            )
        })?;
        destination[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        destination[4..].copy_from_slice(payload);
        Ok(total)
    }
}

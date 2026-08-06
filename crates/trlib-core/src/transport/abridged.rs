//! Abridged TCP transport (`0xef`).

use crate::error::{Error, ErrorKind, Result, narrow};
use crate::transport::{FrameBounds, FrameStatus, Framing};

/// Abridged TCP framing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Abridged;

impl Framing for Abridged {
    #[inline]
    fn init_bytes(&self) -> &'static [u8] {
        &[0xef]
    }

    fn decode(&self, input: &[u8], max_frame_bytes: u32) -> Result<FrameStatus> {
        let Some(&first) = input.first() else {
            return Ok(FrameStatus::NeedMore(1));
        };
        let (words, header_length) = if first < 0x7f {
            (u32::from(first), 1usize)
        } else if first == 0x7f {
            let Some(length) = input.get(1..4) else {
                return Ok(FrameStatus::NeedMore(4));
            };
            (
                u32::from(length[0]) | (u32::from(length[1]) << 8) | (u32::from(length[2]) << 16),
                4usize,
            )
        } else {
            return Err(Error::new(ErrorKind::InvalidLength, 0, u32::from(first)));
        };
        let bytes = words
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, words))?;
        if bytes == 0 {
            return Err(Error::new(ErrorKind::InvalidLength, 0, 0));
        }
        if bytes > max_frame_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded, 0, bytes));
        }
        let total = header_length
            .checked_add(bytes as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, bytes))?;
        if input.len() < total {
            return Ok(FrameStatus::NeedMore(narrow(total)));
        }
        Ok(FrameStatus::Packet(FrameBounds {
            payload_offset: header_length as u32,
            payload_length: bytes,
            consumed: narrow(total),
        }))
    }

    fn encode(&self, payload: &[u8], output: &mut [u8]) -> Result<usize> {
        if payload.is_empty() || payload.len() & 3 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                0,
                narrow(payload.len()),
            ));
        }
        let words = payload.len() / 4;
        let header_length = if words < 0x7f {
            1usize
        } else if words <= 0x00ff_ffff {
            4usize
        } else {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                0,
                narrow(payload.len()),
            ));
        };
        let total = header_length
            .checked_add(payload.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, narrow(payload.len())))?;
        if output.len() < total {
            return Err(Error::new(
                ErrorKind::OutputTooSmall,
                0,
                narrow(total - output.len()),
            ));
        }
        if header_length == 1 {
            output[0] = words as u8;
        } else {
            output[..4].copy_from_slice(&[
                0x7f,
                words as u8,
                (words >> 8) as u8,
                (words >> 16) as u8,
            ]);
        }
        output[header_length..total].copy_from_slice(payload);
        Ok(total)
    }
}

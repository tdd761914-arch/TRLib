//! Allocation-free TL serialization into caller-owned memory.

use crate::error::{Error, ErrorKind, Result, narrow};
use crate::tl::ConstructorId;

/// Cursor over a caller-provided output slice.
#[derive(Debug)]
pub struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    /// Creates a writer at byte zero.
    #[inline]
    pub fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    /// Returns the number of bytes written.
    #[inline]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the initialized prefix of the output buffer.
    #[inline]
    pub fn written(&self) -> &[u8] {
        &self.output[..self.position]
    }

    /// Returns the initialized output prefix mutably.
    ///
    /// This is primarily useful for in-place MTProto encryption after an
    /// envelope has been serialized into the caller-owned network buffer.
    #[inline]
    pub fn written_mut(&mut self) -> &mut [u8] {
        &mut self.output[..self.position]
    }

    /// Writes raw bytes.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.position.checked_add(bytes.len()).ok_or_else(|| {
            Error::new(
                ErrorKind::OutputTooSmall,
                narrow(self.position),
                narrow(bytes.len()),
            )
        })?;
        let position = self.position;
        let available = self.output.len().saturating_sub(position);
        let destination = self.output.get_mut(position..end).ok_or_else(|| {
            Error::new(
                ErrorKind::OutputTooSmall,
                narrow(position),
                narrow(bytes.len().saturating_sub(available)),
            )
        })?;
        destination.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    /// Writes one byte.
    #[inline]
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_all(&[value])
    }

    /// Writes a little-endian 32-bit integer.
    #[inline]
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    /// Writes a little-endian signed 32-bit integer.
    #[inline]
    pub fn write_i32(&mut self, value: i32) -> Result<()> {
        self.write_u32(value as u32)
    }

    /// Writes a little-endian 64-bit integer.
    #[inline]
    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    /// Writes a little-endian signed 64-bit integer.
    #[inline]
    pub fn write_i64(&mut self, value: i64) -> Result<()> {
        self.write_u64(value as u64)
    }

    /// Writes a TL constructor prefix.
    #[inline]
    pub fn write_constructor(&mut self, id: ConstructorId) -> Result<()> {
        self.write_u32(id.get())
    }

    /// Writes canonical TL `bytes` and zero padding.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let length = bytes.len();
        let header_length = if length < 254 {
            self.write_u8(length as u8)?;
            1usize
        } else if length <= 0x00ff_ffff {
            self.write_u8(254)?;
            self.write_all(&[length as u8, (length >> 8) as u8, (length >> 16) as u8])?;
            4usize
        } else {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(self.position),
                narrow(length),
            ));
        };
        self.write_all(bytes)?;
        let padding = (4 - ((header_length + length) & 3)) & 3;
        self.write_all(&[0; 3][..padding])
    }

    /// Writes a UTF-8 TL `string`.
    #[inline]
    pub fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_bytes(value.as_bytes())
    }
}

//! Bounds-checked little-endian cursor over a borrowed byte slice.

use core::str;

use crate::error::{Error, ErrorKind, Result, narrow};
use crate::tl::{ConstructorId, VECTOR};

/// Borrowed TL `bytes` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlBytes<'a>(&'a [u8]);

impl<'a> TlBytes<'a> {
    /// Returns the underlying input slice without copying.
    #[inline]
    pub const fn as_slice(self) -> &'a [u8] {
        self.0
    }
}

/// Borrowed, UTF-8-validated TL `string` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlString<'a>(&'a str);

impl<'a> TlString<'a> {
    /// Returns the borrowed string.
    #[inline]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// A cursor that advances through a borrowed packet.
#[derive(Clone, Copy, Debug)]
pub struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a cursor at byte zero.
    #[inline]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the current byte offset.
    #[inline]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the unconsumed input.
    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    /// Returns the number of unconsumed bytes.
    #[inline]
    pub const fn remaining_len(&self) -> usize {
        self.input.len() - self.position
    }

    /// Requires all input bytes to have been consumed.
    #[inline]
    pub fn finish(self) -> Result<()> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(self.position),
                narrow(self.remaining_len()),
            ))
        }
    }

    /// Reads exactly `length` bytes and borrows them from the input.
    #[inline]
    pub fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidLength,
                narrow(self.position),
                narrow(length),
            )
        })?;
        let bytes = self.input.get(self.position..end).ok_or_else(|| {
            Error::new(
                ErrorKind::NeedMore,
                narrow(self.position),
                narrow(end.saturating_sub(self.input.len())),
            )
        })?;
        self.position = end;
        Ok(bytes)
    }

    /// Skips `length` bytes.
    #[inline]
    pub fn skip(&mut self, length: usize) -> Result<()> {
        self.take(length).map(|_| ())
    }

    /// Reads one byte.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads a little-endian unsigned 32-bit integer.
    #[inline]
    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes: &[u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::NeedMore, narrow(self.position), 4))?;
        Ok(u32::from_le_bytes(*bytes))
    }

    /// Reads a little-endian signed 32-bit integer.
    #[inline]
    pub fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }

    /// Reads a little-endian unsigned 64-bit integer.
    #[inline]
    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes: &[u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::NeedMore, narrow(self.position), 8))?;
        Ok(u64::from_le_bytes(*bytes))
    }

    /// Reads a little-endian signed 64-bit integer.
    #[inline]
    pub fn read_i64(&mut self) -> Result<i64> {
        Ok(self.read_u64()? as i64)
    }

    /// Reads a 16-byte TL integer without changing its byte order.
    #[inline]
    pub fn read_int128(&mut self) -> Result<&'a [u8; 16]> {
        self.take(16)?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::NeedMore, narrow(self.position), 16))
    }

    /// Reads a 32-byte TL integer without changing its byte order.
    #[inline]
    pub fn read_int256(&mut self) -> Result<&'a [u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::NeedMore, narrow(self.position), 32))
    }

    /// Reads a constructor prefix.
    #[inline]
    pub fn read_constructor(&mut self) -> Result<ConstructorId> {
        self.read_u32().map(ConstructorId::new)
    }

    /// Reads and validates a constructor prefix.
    #[inline]
    pub fn expect_constructor(&mut self, expected: ConstructorId) -> Result<()> {
        let at = self.position;
        let actual = self.read_constructor()?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::UnexpectedConstructor,
                narrow(at),
                actual.get(),
            ))
        }
    }

    /// Reads TL `bytes`, including canonical length and four-byte padding.
    pub fn read_bytes(&mut self) -> Result<TlBytes<'a>> {
        let start = self.position;
        let first = self.read_u8()?;
        let (length, header_length) = if first < 254 {
            (usize::from(first), 1usize)
        } else if first == 254 {
            let length_bytes = self.take(3)?;
            let length = usize::from(length_bytes[0])
                | (usize::from(length_bytes[1]) << 8)
                | (usize::from(length_bytes[2]) << 16);
            if length < 254 {
                return Err(Error::new(
                    ErrorKind::InvalidLength,
                    narrow(start),
                    narrow(length),
                ));
            }
            (length, 4usize)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(start),
                u32::from(first),
            ));
        };

        let value = self.take(length)?;
        let padding = (4 - ((header_length + length) & 3)) & 3;
        let padding_at = self.position;
        let padding_bytes = self.take(padding)?;
        if padding_bytes.iter().any(|byte| *byte != 0) {
            return Err(Error::new(
                ErrorKind::InvalidPacket,
                narrow(padding_at),
                narrow(padding),
            ));
        }
        Ok(TlBytes(value))
    }

    /// Reads and validates a UTF-8 TL `string` without allocating.
    pub fn read_string(&mut self) -> Result<TlString<'a>> {
        let at = self.position;
        let bytes = self.read_bytes()?.as_slice();
        let value = str::from_utf8(bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidUtf8, narrow(at), narrow(bytes.len())))?;
        Ok(TlString(value))
    }

    /// Reads a vector prefix and its element count.
    ///
    /// Callers deliberately perform the element loop themselves. This keeps
    /// generated parsers non-generic and avoids one iterator monomorphization
    /// per element type.
    pub fn read_vector_len(&mut self, maximum: u32) -> Result<u32> {
        self.expect_constructor(VECTOR)?;
        let count = self.read_u32()?;
        if count > maximum {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                narrow(self.position.saturating_sub(4)),
                count,
            ));
        }
        Ok(count)
    }
}

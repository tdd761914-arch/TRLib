//! TL constructor prefixes and opaque borrowed objects.

use crate::Result;
use crate::tl::Cursor;

/// Four-byte TL constructor identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ConstructorId(u32);

impl ConstructorId {
    /// Creates an identifier from its wire value.
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the little-endian wire value.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A type with a statically known TL constructor prefix.
pub trait Constructor {
    /// Wire constructor identifier.
    const ID: ConstructorId;
}

/// Opaque TL object borrowing its body from an enclosing length-delimited packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawObject<'a> {
    /// Constructor prefix.
    pub id: ConstructorId,
    /// Bytes following the constructor prefix.
    pub body: &'a [u8],
}

impl<'a> RawObject<'a> {
    /// Reads a raw object whose end is already known by the enclosing protocol.
    pub fn from_exact(input: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(input);
        let id = cursor.read_constructor()?;
        Ok(Self {
            id,
            body: cursor.remaining(),
        })
    }
}

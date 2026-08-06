//! Compact errors that never allocate.

use core::fmt;

/// Result type used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Stable categories suitable for metrics and protocol decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorKind {
    /// More input bytes are required.
    NeedMore = 1,
    /// A length is invalid, non-canonical, or exceeds the configured limit.
    InvalidLength = 2,
    /// A constructor prefix does not match the expected TL type.
    UnexpectedConstructor = 3,
    /// The packet violates an MTProto invariant.
    InvalidPacket = 4,
    /// A caller-provided output buffer is too small.
    OutputTooSmall = 5,
    /// Text bytes are not valid UTF-8.
    InvalidUtf8 = 6,
    /// Authentication or message-key verification failed.
    Authentication = 7,
    /// A compile-time-disabled feature was requested.
    FeatureDisabled = 8,
    /// A configured resource limit was exceeded.
    LimitExceeded = 9,
    /// A request requires protocol state that the caller has not supplied.
    InvalidState = 10,
}

/// Allocation-free error with the byte offset and one numeric detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Error {
    kind: ErrorKind,
    offset: u32,
    detail: u32,
}

impl Error {
    /// Creates an error. Large offsets/details saturate before this call.
    #[inline]
    pub const fn new(kind: ErrorKind, offset: u32, detail: u32) -> Self {
        Self {
            kind,
            offset,
            detail,
        }
    }

    /// Returns the stable error category.
    #[inline]
    pub const fn kind(self) -> ErrorKind {
        self.kind
    }

    /// Returns the input offset related to the failure.
    #[inline]
    pub const fn offset(self) -> u32 {
        self.offset
    }

    /// Returns a category-specific numeric detail.
    #[inline]
    pub const fn detail(self) -> u32 {
        self.detail
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at byte {} (detail {})",
            self.kind, self.offset, self.detail
        )
    }
}

impl core::error::Error for Error {}

#[inline]
pub(crate) const fn narrow(value: usize) -> u32 {
    if value > u32::MAX as usize {
        u32::MAX
    } else {
        value as u32
    }
}

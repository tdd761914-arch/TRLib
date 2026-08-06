//! Runtime-independent MTProto stream framing.

mod framing;

#[cfg(feature = "transport-abridged")]
mod abridged;
#[cfg(feature = "transport-intermediate")]
mod intermediate;

#[cfg(feature = "transport-abridged")]
pub use abridged::Abridged;
pub use framing::{FrameBounds, FrameStatus, Framing};
#[cfg(feature = "transport-intermediate")]
pub use intermediate::Intermediate;

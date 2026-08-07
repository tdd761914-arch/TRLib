#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Small, runtime-independent building blocks for MTProto 2.0 gateways.
//!
//! Parsing borrows from caller-owned buffers. Networking and scheduling are
//! intentionally left to the embedding application, so the same state machine
//! can run on epoll, io_uring, an embedded reactor, or a synchronous test loop.

#[cfg(any(feature = "api", feature = "api-common"))]
pub mod api;
#[cfg(feature = "auth-key")]
pub mod auth_key;
pub mod config;
#[cfg(feature = "crypto-rustcrypto")]
pub mod crypto;
pub mod error;
pub mod gateway;
#[rustfmt::skip]
pub mod generated;
pub mod mtproto;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "session-document")]
pub mod session;
#[cfg(feature = "tdlib-compat")]
pub mod tdlib;
pub mod tl;
pub mod transport;

pub use error::{Error, ErrorKind, Result};

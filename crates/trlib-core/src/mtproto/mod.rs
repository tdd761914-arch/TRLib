//! MTProto packet envelopes and session invariants.

mod envelope;
mod message_id;
#[cfg(feature = "crypto-rustcrypto")]
mod outbound;

pub use envelope::{
    DecryptedEnvelope, EncryptedEnvelope, ExternalEnvelope, PlainEnvelope, parse_decrypted,
    parse_external,
};
pub use message_id::{MessageDirection, MessageIdWindow, validate_message_id};
#[cfg(feature = "crypto-rustcrypto")]
pub use outbound::{OutboundMessage, encode_encrypted, encrypted_packet_len};

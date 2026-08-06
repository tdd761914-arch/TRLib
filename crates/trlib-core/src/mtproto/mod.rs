//! MTProto packet envelopes and session invariants.

mod envelope;
mod message_id;

pub use envelope::{
    DecryptedEnvelope, EncryptedEnvelope, ExternalEnvelope, PlainEnvelope, parse_decrypted,
    parse_external,
};
pub use message_id::{MessageDirection, MessageIdWindow, validate_message_id};

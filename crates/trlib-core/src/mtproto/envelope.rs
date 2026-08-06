//! Borrowed views over plain and encrypted MTProto 2.0 envelopes.

use crate::error::{Error, ErrorKind, Result, narrow};
use crate::tl::Cursor;

/// Wire layout of the fixed external encrypted header.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct EncryptedHeader {
    /// Little-endian authorization key identifier.
    pub auth_key_id: [u8; 8],
    /// Message-key bytes.
    pub message_key: [u8; 16],
}

/// Wire layout of the fixed unencrypted header.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PlainHeader {
    /// Eight zero bytes.
    pub auth_key_id: [u8; 8],
    /// Little-endian message identifier.
    pub message_id: [u8; 8],
    /// Little-endian body length.
    pub body_length: [u8; 4],
}

const _: [(); 24] = [(); core::mem::size_of::<EncryptedHeader>()];
const _: [(); 20] = [(); core::mem::size_of::<PlainHeader>()];

/// Borrowed external MTProto envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalEnvelope<'a> {
    /// An authorization-handshake packet.
    Plain(PlainEnvelope<'a>),
    /// An encrypted session packet.
    Encrypted(EncryptedEnvelope<'a>),
}

/// Borrowed unencrypted authorization-handshake packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlainEnvelope<'a> {
    /// Time-derived message identifier.
    pub message_id: u64,
    /// Exact TL body.
    pub body: &'a [u8],
}

/// Borrowed encrypted packet. Decryption can be performed in place by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedEnvelope<'a> {
    /// Authorization-key identifier.
    pub auth_key_id: u64,
    /// Message-key bytes borrowed from the packet.
    pub message_key: &'a [u8; 16],
    /// AES-IGE ciphertext borrowed from the packet.
    pub encrypted_data: &'a [u8],
}

/// Borrowed view after authenticated in-place decryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecryptedEnvelope<'a> {
    /// Current server salt.
    pub server_salt: u64,
    /// Session identifier.
    pub session_id: u64,
    /// Message identifier.
    pub message_id: u64,
    /// Message sequence number.
    pub sequence_number: u32,
    /// Exact TL body.
    pub body: &'a [u8],
    /// Authenticated random padding.
    pub padding: &'a [u8],
}

/// Parses an external MTProto packet without allocations.
pub fn parse_external(input: &[u8], max_message_bytes: u32) -> Result<ExternalEnvelope<'_>> {
    let mut cursor = Cursor::new(input);
    let auth_key_id = cursor.read_u64()?;
    if auth_key_id == 0 {
        let message_id = cursor.read_u64()?;
        let body_length = cursor.read_u32()?;
        if body_length & 3 != 0 {
            return Err(Error::new(ErrorKind::InvalidLength, 16, body_length));
        }
        if body_length > max_message_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded, 16, body_length));
        }
        let body = cursor.take(body_length as usize)?;
        cursor.finish()?;
        return Ok(ExternalEnvelope::Plain(PlainEnvelope { message_id, body }));
    }

    let message_key = cursor.read_int128()?;
    let encrypted_data = cursor.remaining();
    if encrypted_data.len() < 32 || encrypted_data.len() & 15 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            narrow(cursor.position()),
            narrow(encrypted_data.len()),
        ));
    }
    if encrypted_data.len() > max_message_bytes as usize + 1_072 {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            narrow(cursor.position()),
            narrow(encrypted_data.len()),
        ));
    }
    Ok(ExternalEnvelope::Encrypted(EncryptedEnvelope {
        auth_key_id,
        message_key,
        encrypted_data,
    }))
}

/// Parses authenticated plaintext after AES-IGE decryption.
pub fn parse_decrypted(input: &[u8], max_message_bytes: u32) -> Result<DecryptedEnvelope<'_>> {
    if input.len() & 15 != 0 {
        return Err(Error::new(ErrorKind::InvalidLength, 0, narrow(input.len())));
    }
    let mut cursor = Cursor::new(input);
    let server_salt = cursor.read_u64()?;
    let session_id = cursor.read_u64()?;
    let message_id = cursor.read_u64()?;
    let sequence_number = cursor.read_u32()?;
    let body_length = cursor.read_u32()?;
    if body_length & 3 != 0 {
        return Err(Error::new(ErrorKind::InvalidLength, 28, body_length));
    }
    if body_length > max_message_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded, 28, body_length));
    }
    let body = cursor.take(body_length as usize)?;
    let padding = cursor.remaining();
    if !(12..=1_024).contains(&padding.len()) {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            narrow(cursor.position()),
            narrow(padding.len()),
        ));
    }
    Ok(DecryptedEnvelope {
        server_salt,
        session_id,
        message_id,
        sequence_number,
        body,
        padding,
    })
}

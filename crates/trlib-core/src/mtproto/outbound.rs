//! Allocation-free construction of encrypted MTProto 2.0 envelopes.

use crate::crypto::{AuthKeyRef, CryptoDirection, SessionCrypto};
use crate::error::{Error, ErrorKind, Result, narrow};
use crate::tl::Writer;

/// Fixed metadata preceding an encrypted MTProto message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct OutboundMessage<'a> {
    /// Current server salt.
    pub server_salt: u64,
    /// Per-connection session identifier.
    pub session_id: u64,
    /// Fresh client message identifier.
    pub message_id: u64,
    /// MTProto message sequence number.
    pub sequence_number: u32,
    /// Exact boxed TL method or container body.
    pub body: &'a [u8],
    /// Caller-generated random MTProto padding.
    pub padding: &'a [u8],
}

/// Returns the output length required for an encrypted external envelope.
pub fn encrypted_packet_len(message: OutboundMessage<'_>) -> Result<usize> {
    if message.body.len() & 3 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            0,
            narrow(message.body.len()),
        ));
    }
    if !(12..=1_024).contains(&message.padding.len()) {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            narrow(message.body.len().saturating_add(32)),
            narrow(message.padding.len()),
        ));
    }
    let encrypted_data = 32usize
        .checked_add(message.body.len())
        .and_then(|value| value.checked_add(message.padding.len()))
        .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, u32::MAX))?;
    if encrypted_data & 15 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            0,
            narrow(encrypted_data),
        ));
    }
    encrypted_data
        .checked_add(24)
        .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, u32::MAX))
}

/// Serializes and encrypts one complete external MTProto 2.0 envelope.
///
/// The embedding runtime supplies an object-safe crypto backend, the existing
/// authorization key and random padding.  No network runtime, RNG, `Vec` or
/// duplicate plaintext buffer is required.  `output` receives the exact bytes
/// that a selected transport codec should frame.
pub fn encode_encrypted(
    crypto: &dyn SessionCrypto,
    direction: CryptoDirection,
    auth_key: &AuthKeyRef<'_>,
    auth_key_id: u64,
    message: OutboundMessage<'_>,
    output: &mut [u8],
) -> Result<usize> {
    let total = encrypted_packet_len(message)?;
    if output.len() < total {
        return Err(Error::new(
            ErrorKind::OutputTooSmall,
            0,
            narrow(total.saturating_sub(output.len())),
        ));
    }
    let mut writer = Writer::new(&mut output[..total]);
    writer.write_u64(auth_key_id)?;
    writer.write_all(&[0; 16])?;
    writer.write_u64(message.server_salt)?;
    writer.write_u64(message.session_id)?;
    writer.write_u64(message.message_id)?;
    writer.write_u32(message.sequence_number)?;
    writer.write_u32(
        u32::try_from(message.body.len())
            .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, u32::MAX))?,
    )?;
    writer.write_all(message.body)?;
    writer.write_all(message.padding)?;

    let mut message_key = [0u8; 16];
    {
        let written = writer.written_mut();
        crypto.seal(direction, auth_key, &mut written[24..], &mut message_key)?;
        written[8..24].copy_from_slice(&message_key);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{OutboundMessage, encode_encrypted};
    use crate::crypto::{AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto};
    use crate::mtproto::{ExternalEnvelope, parse_decrypted, parse_external};

    #[test]
    fn encodes_and_opens_a_direct_method_without_a_second_plaintext_buffer() {
        let mut auth_key_bytes = [0u8; 256];
        for (index, byte) in auth_key_bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let auth_key = AuthKeyRef::new(&auth_key_bytes).expect("key");
        let mut output = [0u8; 72];
        let length = encode_encrypted(
            &RustCrypto,
            CryptoDirection::ClientToServer,
            &auth_key,
            99,
            OutboundMessage {
                server_salt: 1,
                session_id: 2,
                message_id: 3,
                sequence_number: 4,
                body: &0xbe7e_8ef1u32.to_le_bytes(),
                padding: &[7; 12],
            },
            &mut output,
        )
        .expect("encode");
        assert_eq!(length, output.len());
        let (message_key, encrypted_offset) = match parse_external(&output, 1_024).expect("packet")
        {
            ExternalEnvelope::Encrypted(envelope) => (*envelope.message_key, 24usize),
            _ => panic!("expected encrypted packet"),
        };
        RustCrypto
            .open(
                CryptoDirection::ClientToServer,
                &auth_key,
                &message_key,
                &mut output[encrypted_offset..],
            )
            .expect("open");
        let decoded = parse_decrypted(&output[encrypted_offset..], 1_024).expect("decoded");
        assert_eq!(decoded.body, 0xbe7e_8ef1u32.to_le_bytes());
    }
}

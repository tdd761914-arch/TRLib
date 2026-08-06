//! Encrypted, line-oriented MTProto session documents.
//!
//! This module is a deliberately small replacement for a session database.
//! It serializes one session into a fixed-layout plaintext, encrypts it with
//! AES-256-CTR, authenticates it using HMAC-SHA-256, then writes an auditable
//! text document.  There is no SQLite, allocator, serializer framework or
//! runtime dependency.  The caller owns both scratch buffers.

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result, narrow};
use crate::tl::{Cursor, Writer};

const DOCUMENT_HEADER: &[u8] = b"TRLib-session-v1\nsalt=";
const DATA_PREFIX: &[u8] = b"\ndata=";
const TAG_PREFIX: &[u8] = b"\ntag=";
const DOCUMENT_SUFFIX: &[u8] = b"\n";
const RECORD_MAGIC: u32 = 0x534c_5254;
const RECORD_VERSION: u32 = 1;
const RECORD_PREFIX_BYTES: usize = 60;

/// Number of bytes in an encoded binary session record.
pub const SESSION_RECORD_BYTES: usize = RECORD_PREFIX_BYTES + 256;

/// Exact number of bytes in a text session document.
pub const SESSION_DOCUMENT_BYTES: usize = DOCUMENT_HEADER.len()
    + 32
    + DATA_PREFIX.len()
    + SESSION_RECORD_BYTES * 2
    + TAG_PREFIX.len()
    + 64
    + DOCUMENT_SUFFIX.len();

/// Recommended PBKDF2-HMAC-SHA-256 iteration count for a human passphrase.
///
/// For unattended deployments, use a 32-byte secret from a platform key store
/// with [`SessionKey::from_bytes`] instead of a passphrase.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Session counters and identity stored alongside the MTProto authorization key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SessionMetadata {
    /// Telegram data-center identifier.
    pub dc_id: i32,
    /// MTProto `auth_key_id` used in encrypted envelope headers.
    pub auth_key_id: u64,
    /// Current server salt.
    pub server_salt: u64,
    /// Current MTProto session identifier.
    pub session_id: u64,
    /// Next outbound content-related sequence number.
    pub sequence_number: u32,
    /// Persistent update PTS counter.
    pub pts: i32,
    /// Persistent secret-chat QTS counter.
    pub qts: i32,
    /// Persistent server date from `updates.state`.
    pub date: i32,
    /// Persistent update sequence counter.
    pub seq: i32,
    /// Persistent unread-count snapshot.
    pub unread_count: i32,
}

/// Borrowed session record with an authorization key owned by the caller.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SessionRecordRef<'a> {
    metadata: SessionMetadata,
    auth_key: &'a [u8; 256],
}

impl<'a> SessionRecordRef<'a> {
    /// Combines metadata with a borrowed, exact 2048-bit MTProto key.
    #[inline]
    pub const fn new(metadata: SessionMetadata, auth_key: &'a [u8; 256]) -> Self {
        Self { metadata, auth_key }
    }

    /// Returns stored session metadata.
    #[inline]
    pub const fn metadata(self) -> SessionMetadata {
        self.metadata
    }

    /// Borrows the stored MTProto authorization key without copying it.
    #[inline]
    pub const fn auth_key(self) -> &'a [u8; 256] {
        self.auth_key
    }
}

/// A 256-bit key used to encrypt and authenticate a session document.
///
/// The key zeroizes itself on drop.  It is intentionally separate from the
/// MTProto authorization key so a leaked document password does not become an
/// implicit network protocol credential.
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Creates a document key from a high-entropy 32-byte secret.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives a key from a passphrase with caller-selected PBKDF2 iterations.
    ///
    /// The same random 16-byte salt used by [`seal`] must be supplied when the
    /// document is opened.  A zero iteration count is rejected.
    pub fn derive_from_passphrase(
        passphrase: &[u8],
        salt: &[u8; 16],
        iterations: u32,
    ) -> Result<Self> {
        if iterations == 0 {
            return Err(Error::new(ErrorKind::InvalidLength, 0, 0));
        }
        let mut derived = pbkdf2_one_block(passphrase, salt, iterations);
        let key = Self(derived);
        derived.zeroize();
        Ok(key)
    }

    /// Borrows the raw key for integration with a platform key-management API.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Serializes and encrypts a session document into caller-owned text storage.
///
/// `salt` must be freshly random for every write; TRLib deliberately accepts
/// it from the host rather than linking a random-number runtime.  `scratch`
/// needs at least [`SESSION_RECORD_BYTES`] bytes and will contain ciphertext on
/// successful return.  The function does not allocate.
pub fn seal(
    key: &SessionKey,
    salt: &[u8; 16],
    record: SessionRecordRef<'_>,
    scratch: &mut [u8],
    output: &mut [u8],
) -> Result<usize> {
    let cipher_text = scratch_prefix(scratch)?;
    encode_record(record, cipher_text)?;
    let material = DocumentMaterial::derive(key, salt);
    aes_ctr(&material.stream_key, salt, cipher_text)?;
    let tag = hmac_sha256(&material.mac_key, b"TRLib-session-v1\0", salt, cipher_text);

    let mut writer = Writer::new(output);
    writer.write_all(DOCUMENT_HEADER)?;
    write_hex(&mut writer, salt)?;
    writer.write_all(DATA_PREFIX)?;
    write_hex(&mut writer, cipher_text)?;
    writer.write_all(TAG_PREFIX)?;
    write_hex(&mut writer, &tag)?;
    writer.write_all(DOCUMENT_SUFFIX)?;
    let written = writer.position();

    let mut tag = tag;
    tag.zeroize();
    Ok(written)
}

/// Authenticates, decrypts and parses a text session document in caller-owned
/// scratch storage.
///
/// The returned record borrows the authorization key from `scratch`; retain the
/// buffer for as long as that record is in use.  Authentication failures wipe
/// the decoded ciphertext prefix before returning an error.
pub fn open<'scratch>(
    key: &SessionKey,
    document: &[u8],
    scratch: &'scratch mut [u8],
) -> Result<SessionRecordRef<'scratch>> {
    if document.len() != SESSION_DOCUMENT_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            0,
            narrow(document.len()),
        ));
    }
    let cipher_text = scratch_prefix(scratch)?;
    let (salt_hex, data_hex, tag_hex) = split_document(document)?;
    let mut salt = [0u8; 16];
    let mut tag = [0u8; 32];
    decode_hex(salt_hex, &mut salt)?;
    decode_hex(data_hex, cipher_text)?;
    decode_hex(tag_hex, &mut tag)?;

    let material = DocumentMaterial::derive(key, &salt);
    let mut expected_tag =
        hmac_sha256(&material.mac_key, b"TRLib-session-v1\0", &salt, cipher_text);
    let authenticated: bool = expected_tag.ct_eq(&tag).into();
    expected_tag.zeroize();
    tag.zeroize();
    if !authenticated {
        cipher_text.zeroize();
        salt.zeroize();
        return Err(Error::new(ErrorKind::Authentication, 0, 0));
    }
    aes_ctr(&material.stream_key, &salt, cipher_text)?;
    salt.zeroize();
    parse_record(cipher_text)
}

/// Decodes the public PBKDF2/document salt from an exact session document.
///
/// This lets callers derive a [`SessionKey`] from a passphrase before invoking
/// [`open`]. The salt is not secret; `open` still authenticates the document
/// before it yields any plaintext record.
pub fn document_salt(document: &[u8]) -> Result<[u8; 16]> {
    if document.len() != SESSION_DOCUMENT_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            0,
            narrow(document.len()),
        ));
    }
    let (salt_hex, _, _) = split_document(document)?;
    let mut salt = [0u8; 16];
    decode_hex(salt_hex, &mut salt)?;
    Ok(salt)
}

fn scratch_prefix(scratch: &mut [u8]) -> Result<&mut [u8]> {
    if scratch.len() < SESSION_RECORD_BYTES {
        return Err(Error::new(
            ErrorKind::OutputTooSmall,
            0,
            narrow(SESSION_RECORD_BYTES.saturating_sub(scratch.len())),
        ));
    }
    Ok(&mut scratch[..SESSION_RECORD_BYTES])
}

fn encode_record(record: SessionRecordRef<'_>, output: &mut [u8]) -> Result<()> {
    let mut writer = Writer::new(output);
    writer.write_u32(RECORD_MAGIC)?;
    writer.write_u32(RECORD_VERSION)?;
    let metadata = record.metadata();
    writer.write_i32(metadata.dc_id)?;
    writer.write_u64(metadata.auth_key_id)?;
    writer.write_u64(metadata.server_salt)?;
    writer.write_u64(metadata.session_id)?;
    writer.write_u32(metadata.sequence_number)?;
    writer.write_i32(metadata.pts)?;
    writer.write_i32(metadata.qts)?;
    writer.write_i32(metadata.date)?;
    writer.write_i32(metadata.seq)?;
    writer.write_i32(metadata.unread_count)?;
    writer.write_all(record.auth_key())?;
    if writer.position() != SESSION_RECORD_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            narrow(writer.position()),
            narrow(SESSION_RECORD_BYTES),
        ));
    }
    Ok(())
}

fn parse_record(input: &[u8]) -> Result<SessionRecordRef<'_>> {
    let mut cursor = Cursor::new(input);
    let magic = cursor.read_u32()?;
    let version = cursor.read_u32()?;
    if magic != RECORD_MAGIC || version != RECORD_VERSION {
        return Err(Error::new(ErrorKind::InvalidPacket, 0, magic));
    }
    let metadata = SessionMetadata {
        dc_id: cursor.read_i32()?,
        auth_key_id: cursor.read_u64()?,
        server_salt: cursor.read_u64()?,
        session_id: cursor.read_u64()?,
        sequence_number: cursor.read_u32()?,
        pts: cursor.read_i32()?,
        qts: cursor.read_i32()?,
        date: cursor.read_i32()?,
        seq: cursor.read_i32()?,
        unread_count: cursor.read_i32()?,
    };
    let auth_key: &[u8; 256] = cursor
        .take(256)?
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidLength, narrow(cursor.position()), 256))?;
    cursor.finish()?;
    Ok(SessionRecordRef::new(metadata, auth_key))
}

fn split_document(input: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let salt_start = DOCUMENT_HEADER.len();
    let salt_end = salt_start + 32;
    let data_start = salt_end + DATA_PREFIX.len();
    let data_end = data_start + SESSION_RECORD_BYTES * 2;
    let tag_start = data_end + TAG_PREFIX.len();
    let tag_end = tag_start + 64;
    if input.get(..salt_start) != Some(DOCUMENT_HEADER)
        || input.get(salt_end..data_start) != Some(DATA_PREFIX)
        || input.get(data_end..tag_start) != Some(TAG_PREFIX)
        || input.get(tag_end..) != Some(DOCUMENT_SUFFIX)
    {
        return Err(Error::new(ErrorKind::InvalidPacket, 0, 0));
    }
    Ok((
        &input[salt_start..salt_end],
        &input[data_start..data_end],
        &input[tag_start..tag_end],
    ))
}

fn write_hex(writer: &mut Writer<'_>, input: &[u8]) -> Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input {
        writer.write_u8(HEX[usize::from(byte >> 4)])?;
        writer.write_u8(HEX[usize::from(byte & 0x0f)])?;
    }
    Ok(())
}

fn decode_hex(input: &[u8], output: &mut [u8]) -> Result<()> {
    if input.len() != output.len().saturating_mul(2) {
        return Err(Error::new(ErrorKind::InvalidLength, 0, narrow(input.len())));
    }
    for (index, pair) in input.chunks_exact(2).enumerate() {
        let high = hex_value(pair[0]).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidPacket,
                narrow(index.saturating_mul(2)),
                u32::from(pair[0]),
            )
        })?;
        let low = hex_value(pair[1]).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidPacket,
                narrow(index.saturating_mul(2).saturating_add(1)),
                u32::from(pair[1]),
            )
        })?;
        output[index] = (high << 4) | low;
    }
    Ok(())
}

#[inline]
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

struct DocumentMaterial {
    stream_key: [u8; 32],
    mac_key: [u8; 32],
}

impl DocumentMaterial {
    fn derive(key: &SessionKey, salt: &[u8; 16]) -> Self {
        Self {
            stream_key: hmac_sha256(key.as_bytes(), b"TRLib-session-stream-v1\0", salt, &[]),
            mac_key: hmac_sha256(key.as_bytes(), b"TRLib-session-mac-v1\0", salt, &[]),
        }
    }
}

impl Drop for DocumentMaterial {
    fn drop(&mut self) {
        self.stream_key.zeroize();
        self.mac_key.zeroize();
    }
}

fn aes_ctr(key: &[u8; 32], salt: &[u8; 16], data: &mut [u8]) -> Result<()> {
    let cipher =
        Aes256::new_from_slice(key).map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 32))?;
    let mut counter = *salt;
    let mut keystream = [0u8; 16];
    for (index, block) in data.chunks_mut(16).enumerate() {
        let counter_value = u32::try_from(index)
            .map_err(|_| Error::new(ErrorKind::LimitExceeded, 0, narrow(index)))?;
        counter[12..].copy_from_slice(&counter_value.to_be_bytes());
        keystream.copy_from_slice(&counter);
        let block_key = aes::cipher::Block::<Aes256>::from_mut_slice(&mut keystream);
        cipher.encrypt_block(block_key);
        for (target, mask) in block.iter_mut().zip(keystream.iter()) {
            *target ^= *mask;
        }
    }
    counter.zeroize();
    keystream.zeroize();
    Ok(())
}

fn pbkdf2_one_block(password: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let block_index = 1u32.to_be_bytes();
    let mut current = hmac_sha256(password, salt, &block_index, &[]);
    let mut output = current;
    for _ in 1..iterations {
        let next = hmac_sha256(password, &current, &[], &[]);
        current.zeroize();
        current = next;
        for (target, source) in output.iter_mut().zip(current.iter()) {
            *target ^= *source;
        }
    }
    current.zeroize();
    output
}

fn hmac_sha256(key: &[u8], first: &[u8], second: &[u8], third: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        let mut hash = Sha256::new();
        hash.update(key);
        let mut digest = hash.finalize();
        key_block[..32].copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; 64];
    let mut outer_pad = [0u8; 64];
    for (index, byte) in key_block.iter().enumerate() {
        inner_pad[index] = *byte ^ 0x36;
        outer_pad[index] = *byte ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(first);
    inner.update(second);
    inner.update(third);
    let mut inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(&inner_digest);
    let mut digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);

    key_block.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    inner_digest.as_mut_slice().zeroize();
    digest.as_mut_slice().zeroize();
    output
}

#[cfg(feature = "session-file")]
/// Blocking file helpers for applications that choose the standard library.
pub mod file {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::path::Path;

    use super::{SESSION_DOCUMENT_BYTES, SessionKey, SessionRecordRef, open, seal};

    /// Saves an encrypted text document without allocating a file-sized buffer.
    pub fn save(
        path: &Path,
        key: &SessionKey,
        salt: &[u8; 16],
        record: SessionRecordRef<'_>,
        crypto_scratch: &mut [u8],
        document_scratch: &mut [u8],
    ) -> io::Result<()> {
        let length = seal(key, salt, record, crypto_scratch, document_scratch).map_err(invalid)?;
        let mut file = File::create(path)?;
        file.write_all(&document_scratch[..length])?;
        file.sync_all()
    }

    /// Opens one exact encrypted text document into caller-owned scratch memory.
    pub fn load<'scratch>(
        path: &Path,
        key: &SessionKey,
        document_scratch: &mut [u8],
        crypto_scratch: &'scratch mut [u8],
    ) -> io::Result<SessionRecordRef<'scratch>> {
        if document_scratch.len() < SESSION_DOCUMENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session document scratch is too small",
            ));
        }
        let mut file = File::open(path)?;
        file.read_exact(&mut document_scratch[..SESSION_DOCUMENT_BYTES])?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session document has trailing bytes",
            ));
        }
        open(
            key,
            &document_scratch[..SESSION_DOCUMENT_BYTES],
            crypto_scratch,
        )
        .map_err(invalid)
    }

    fn invalid(error: crate::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SESSION_DOCUMENT_BYTES, SESSION_RECORD_BYTES, SessionKey, SessionMetadata,
        SessionRecordRef, document_salt, open, seal,
    };

    #[test]
    fn text_document_round_trips_without_a_heap_buffer() {
        let mut auth_key = [0u8; 256];
        for (index, byte) in auth_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let metadata = SessionMetadata {
            dc_id: 2,
            auth_key_id: 3,
            server_salt: 4,
            session_id: 5,
            sequence_number: 6,
            pts: 7,
            qts: 8,
            date: 9,
            seq: 10,
            unread_count: 11,
        };
        let key = SessionKey::from_bytes([42; 32]);
        let salt = [9u8; 16];
        let mut encrypt_scratch = [0u8; SESSION_RECORD_BYTES];
        let mut document = [0u8; SESSION_DOCUMENT_BYTES];
        let written = seal(
            &key,
            &salt,
            SessionRecordRef::new(metadata, &auth_key),
            &mut encrypt_scratch,
            &mut document,
        )
        .expect("seal");
        assert_eq!(written, SESSION_DOCUMENT_BYTES);
        assert!(document.starts_with(b"TRLib-session-v1\n"));
        assert!(!document.windows(32).any(|window| window == [42; 32]));
        assert_eq!(document_salt(&document).expect("salt"), salt);

        let mut decrypt_scratch = [0u8; SESSION_RECORD_BYTES];
        let restored = open(&key, &document, &mut decrypt_scratch).expect("open");
        assert_eq!(restored.metadata(), metadata);
        assert_eq!(restored.auth_key(), &auth_key);

        document[SESSION_DOCUMENT_BYTES - 2] ^= 1;
        assert!(open(&key, &document, &mut decrypt_scratch).is_err());
        assert_eq!(decrypt_scratch, [0; SESSION_RECORD_BYTES]);
    }

    #[test]
    fn passphrase_derivation_rejects_zero_iterations() {
        assert!(SessionKey::derive_from_passphrase(b"test", &[0; 16], 0).is_err());
    }
}

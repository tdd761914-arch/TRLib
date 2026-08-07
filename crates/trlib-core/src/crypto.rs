//! Optional MTProto 2.0 session cryptography using small `no_std` RustCrypto crates.
//!
//! This module handles the hot path after an authorization key already exists.
//! RSA/DH authorization-key creation is deliberately a separate future feature.

use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result, narrow};

/// Exact MTProto authorization-key size in bytes.
pub const AUTH_KEY_BYTES: usize = 256;

/// Borrowed, length-checked 2048-bit MTProto authorization key.
#[derive(Debug)]
#[repr(transparent)]
pub struct AuthKeyRef<'a>(&'a [u8; AUTH_KEY_BYTES]);

impl<'a> AuthKeyRef<'a> {
    /// Validates and borrows an authorization key without copying it.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        let key: &[u8; AUTH_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, narrow(bytes.len())))?;
        Ok(Self(key))
    }

    #[inline]
    fn as_bytes(&self) -> &[u8; AUTH_KEY_BYTES] {
        self.0
    }
}

/// Direction used by the MTProto 2.0 KDF (`x = 0` or `x = 8`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoDirection {
    /// Packet produced by the client (`x = 0`).
    ClientToServer,
    /// Packet produced by Telegram (`x = 8`).
    ServerToClient,
}

impl CryptoDirection {
    #[inline]
    const fn x(self) -> usize {
        match self {
            Self::ClientToServer => 0,
            Self::ServerToClient => 8,
        }
    }
}

/// Object-safe session cipher interface for runtime selection without generic bloat.
pub trait SessionCrypto {
    /// Computes `msg_key`, derives AES material, and encrypts in place.
    fn seal(
        &self,
        direction: CryptoDirection,
        auth_key: &AuthKeyRef<'_>,
        plaintext_and_padding: &mut [u8],
        message_key: &mut [u8; 16],
    ) -> Result<()>;

    /// Decrypts in place and verifies `msg_key` in constant time.
    fn open(
        &self,
        direction: CryptoDirection,
        auth_key: &AuthKeyRef<'_>,
        message_key: &[u8; 16],
        ciphertext: &mut [u8],
    ) -> Result<()>;
}

/// RustCrypto-backed AES-256-IGE and SHA-256 implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCrypto;

struct KeyIv {
    key: [u8; 32],
    iv: [u8; 32],
}

impl Drop for KeyIv {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl SessionCrypto for RustCrypto {
    fn seal(
        &self,
        direction: CryptoDirection,
        auth_key: &AuthKeyRef<'_>,
        plaintext_and_padding: &mut [u8],
        message_key: &mut [u8; 16],
    ) -> Result<()> {
        validate_block_data(plaintext_and_padding)?;
        *message_key = calculate_message_key(direction, auth_key, plaintext_and_padding);
        let material = derive_key_iv(direction, auth_key, message_key);
        aes_ige_encrypt(&material.key, &material.iv, plaintext_and_padding)
    }

    fn open(
        &self,
        direction: CryptoDirection,
        auth_key: &AuthKeyRef<'_>,
        message_key: &[u8; 16],
        ciphertext: &mut [u8],
    ) -> Result<()> {
        validate_block_data(ciphertext)?;
        let material = derive_key_iv(direction, auth_key, message_key);
        aes_ige_decrypt(&material.key, &material.iv, ciphertext)?;
        let mut calculated = calculate_message_key(direction, auth_key, ciphertext);
        let valid = calculated.ct_eq(message_key).into();
        calculated.zeroize();
        if valid {
            Ok(())
        } else {
            ciphertext.zeroize();
            Err(Error::new(ErrorKind::Authentication, 0, 0))
        }
    }
}

fn validate_block_data(data: &[u8]) -> Result<()> {
    if data.len() < 32 || data.len() & 15 != 0 {
        return Err(Error::new(ErrorKind::InvalidLength, 0, narrow(data.len())));
    }
    Ok(())
}

fn calculate_message_key(
    direction: CryptoDirection,
    auth_key: &AuthKeyRef<'_>,
    plaintext_and_padding: &[u8],
) -> [u8; 16] {
    let x = direction.x();
    let mut hash = Sha256::new();
    hash.update(&auth_key.as_bytes()[88 + x..120 + x]);
    hash.update(plaintext_and_padding);
    let mut digest = hash.finalize();
    let mut message_key = [0u8; 16];
    message_key.copy_from_slice(&digest[8..24]);
    digest.as_mut_slice().zeroize();
    message_key
}

fn derive_key_iv(
    direction: CryptoDirection,
    auth_key: &AuthKeyRef<'_>,
    message_key: &[u8; 16],
) -> KeyIv {
    let x = direction.x();

    let mut hash_a = Sha256::new();
    hash_a.update(message_key);
    hash_a.update(&auth_key.as_bytes()[x..x + 36]);
    let mut sha256_a = hash_a.finalize();

    let mut hash_b = Sha256::new();
    hash_b.update(&auth_key.as_bytes()[40 + x..76 + x]);
    hash_b.update(message_key);
    let mut sha256_b = hash_b.finalize();

    let mut material = KeyIv {
        key: [0; 32],
        iv: [0; 32],
    };
    material.key[..8].copy_from_slice(&sha256_a[..8]);
    material.key[8..24].copy_from_slice(&sha256_b[8..24]);
    material.key[24..].copy_from_slice(&sha256_a[24..]);
    material.iv[..8].copy_from_slice(&sha256_b[..8]);
    material.iv[8..24].copy_from_slice(&sha256_a[8..24]);
    material.iv[24..].copy_from_slice(&sha256_b[24..]);

    sha256_a.as_mut_slice().zeroize();
    sha256_b.as_mut_slice().zeroize();
    material
}

fn aes_ige_encrypt(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<()> {
    let cipher =
        Aes256::new_from_slice(key).map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 32))?;
    let mut previous_ciphertext: [u8; 16] = iv[..16]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 16))?;
    let mut previous_plaintext: [u8; 16] = iv[16..]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidLength, 16, 16))?;

    for block_bytes in data.chunks_exact_mut(16) {
        let mut plaintext = [0u8; 16];
        plaintext.copy_from_slice(block_bytes);
        for index in 0..16 {
            block_bytes[index] ^= previous_ciphertext[index];
        }
        let block = aes::cipher::Block::<Aes256>::from_mut_slice(block_bytes);
        cipher.encrypt_block(block);
        for index in 0..16 {
            block_bytes[index] ^= previous_plaintext[index];
        }
        previous_ciphertext.copy_from_slice(block_bytes);
        previous_plaintext.copy_from_slice(&plaintext);
        plaintext.zeroize();
    }
    previous_ciphertext.zeroize();
    previous_plaintext.zeroize();
    Ok(())
}

#[cfg(feature = "auth-key")]
pub(crate) fn aes_ige_encrypt_raw(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<()> {
    if data.len() < 16 || data.len() & 15 != 0 {
        return Err(Error::new(ErrorKind::InvalidLength, 0, narrow(data.len())));
    }
    aes_ige_encrypt(key, iv, data)
}

fn aes_ige_decrypt(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<()> {
    let cipher =
        Aes256::new_from_slice(key).map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 32))?;
    let mut previous_ciphertext: [u8; 16] = iv[..16]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 16))?;
    let mut previous_plaintext: [u8; 16] = iv[16..]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidLength, 16, 16))?;

    for block_bytes in data.chunks_exact_mut(16) {
        let mut ciphertext = [0u8; 16];
        ciphertext.copy_from_slice(block_bytes);
        for index in 0..16 {
            block_bytes[index] ^= previous_plaintext[index];
        }
        let block = aes::cipher::Block::<Aes256>::from_mut_slice(block_bytes);
        cipher.decrypt_block(block);
        for index in 0..16 {
            block_bytes[index] ^= previous_ciphertext[index];
        }
        previous_plaintext.copy_from_slice(block_bytes);
        previous_ciphertext.copy_from_slice(&ciphertext);
        ciphertext.zeroize();
    }
    previous_ciphertext.zeroize();
    previous_plaintext.zeroize();
    Ok(())
}

#[cfg(feature = "auth-key")]
pub(crate) fn aes_ige_decrypt_raw(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<()> {
    if data.len() < 16 || data.len() & 15 != 0 {
        return Err(Error::new(ErrorKind::InvalidLength, 0, narrow(data.len())));
    }
    aes_ige_decrypt(key, iv, data)
}

#[cfg(test)]
mod tests {
    use super::{
        AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto, calculate_message_key,
        derive_key_iv,
    };

    #[test]
    fn kdf_matches_independent_sha256_fixture() {
        let mut auth_key = [0u8; 256];
        for (index, byte) in auth_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let auth_key = AuthKeyRef::new(&auth_key).expect("valid key");
        let mut message_key = [0u8; 16];
        for (index, byte) in message_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let material = derive_key_iv(CryptoDirection::ServerToClient, &auth_key, &message_key);
        assert_eq!(
            material.key,
            [
                0x21, 0x77, 0x25, 0x79, 0x9b, 0x24, 0x58, 0x06, 0x45, 0x81, 0x74, 0xa1, 0xfc, 0xfb,
                0xc8, 0x83, 0x90, 0x68, 0x07, 0xb1, 0x50, 0x33, 0xfd, 0xd0, 0xea, 0x2b, 0x4d, 0x69,
                0xcf, 0x9c, 0x36, 0x4e,
            ]
        );
        assert_eq!(
            material.iv,
            [
                0x66, 0x9a, 0x65, 0x38, 0x91, 0x7a, 0x4f, 0xa5, 0x6c, 0xa3, 0x23, 0x60, 0xa4, 0x31,
                0xc9, 0x16, 0x0b, 0xe4, 0xad, 0x88, 0x71, 0x40, 0x98, 0x0d, 0xab, 0x91, 0xce, 0x7b,
                0xdc, 0x47, 0xff, 0xbc,
            ]
        );

        let mut plaintext = [0u8; 64];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        assert_eq!(
            calculate_message_key(CryptoDirection::ServerToClient, &auth_key, &plaintext),
            [
                0x96, 0x08, 0x13, 0x5b, 0x95, 0x5c, 0x65, 0xde, 0x13, 0xe4, 0xce, 0x04, 0xbc, 0x90,
                0x19, 0x07,
            ]
        );
    }

    #[test]
    fn session_crypto_round_trip_and_rejects_tampering() {
        let mut auth_key = [0u8; 256];
        for (index, byte) in auth_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let auth_key = AuthKeyRef::new(&auth_key).expect("valid key");
        let crypto = RustCrypto;
        let mut plaintext = [0u8; 64];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let expected = plaintext;
        let mut message_key = [0u8; 16];
        crypto
            .seal(
                CryptoDirection::ServerToClient,
                &auth_key,
                &mut plaintext,
                &mut message_key,
            )
            .expect("seal");
        assert_ne!(plaintext, expected);
        crypto
            .open(
                CryptoDirection::ServerToClient,
                &auth_key,
                &message_key,
                &mut plaintext,
            )
            .expect("open");
        assert_eq!(plaintext, expected);

        let mut wrong_key = message_key;
        wrong_key[0] ^= 1;
        assert!(
            crypto
                .open(
                    CryptoDirection::ServerToClient,
                    &auth_key,
                    &wrong_key,
                    &mut plaintext,
                )
                .is_err()
        );
        assert_eq!(plaintext, [0; 64]);
    }
}

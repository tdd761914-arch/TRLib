//! Allocation-free MTProto 2.0 authorization-key creation.
//!
//! The state machine performs the complete `req_pq_multi`/RSA/DH exchange on
//! caller-owned buffers.  It has no allocator, no operating-system calls and
//! no hidden randomness source: the embedding runtime implements
//! [`RandomSource`].  The built-in RSA key is the public Test DC key; a
//! production deployment should add its pinned server keys before enabling a
//! production connector.

#![allow(missing_docs)]

use crypto_bigint::{
    Odd, U2048,
    modular::{MontyForm, MontyParams},
};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::{aes_ige_decrypt_raw, aes_ige_encrypt_raw};
use crate::error::{Error, ErrorKind, Result, narrow};
use crate::generated::core::RES_PQ;
use crate::tl::ConstructorId;
use crate::tl::{Cursor, Writer};

const REQ_PQ_MULTI: ConstructorId = ConstructorId::new(0xbe7e8ef1);
const PQ_INNER_DATA_DC: ConstructorId = ConstructorId::new(0xa9f55f95);
const REQ_DH_PARAMS: ConstructorId = ConstructorId::new(0xd712e4be);
const SERVER_DH_PARAMS_OK: ConstructorId = ConstructorId::new(0xd0e8075c);
const SERVER_DH_INNER_DATA: ConstructorId = ConstructorId::new(0xb5890dba);
const CLIENT_DH_INNER_DATA: ConstructorId = ConstructorId::new(0x6643b654);
const SET_CLIENT_DH_PARAMS: ConstructorId = ConstructorId::new(0xf5045f1f);
const DH_GEN_OK: ConstructorId = ConstructorId::new(0x3bcbf734);
const DH_GEN_RETRY: ConstructorId = ConstructorId::new(0x46dc1fb9);
const DH_GEN_FAIL: ConstructorId = ConstructorId::new(0xa69dae02);

pub const TEST_DC_RSA_FINGERPRINT: u64 = 0xb25898df208d2603;

const RSA_MODULUS: U2048 = U2048::from_be_hex(
    "c8c11d635691fac091dd9489aedced2932aa8a0bcefef05fa800892d9b52ed03200865c9e97211cb2ee6c7ae96d3fb0e15aeffd66019b44a08a240cfdd2868a85e1f54d6fa5deaa041f6941ddf302690d61dc476385c2fa655142353cb4e4b59f6e5b6584db76fe8b1370263246c010c93d011014113ebdf987d093f9d37c2be48352d69a1683f8f6e6c2167983c761e3ab169fde5daaa12123fa1beab621e4da5935e9c198f82f35eae583a99386d8110ea6bd1abb0f568759f62694419ea5f69847c43462abef858b4cb5edc84e7b9226cd7bd7e183aa974a712c079dde85b9dc063b8a5c08e8f859c0ee5dcd824c7807f20153361a7f63cfd2a433a1be7f5",
);

const DH_PRIME: U2048 = U2048::from_be_hex(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c3720fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b",
);

/// Entropy callback required by the handshake.
pub trait RandomSource {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<()>;
}

/// Result of a successful authorization-key exchange.
#[derive(Debug)]
#[repr(C)]
pub struct AuthKeyMaterial {
    auth_key: [u8; 256],
    auth_key_id: u64,
    server_salt: u64,
    server_time: i32,
}

impl AuthKeyMaterial {
    pub fn auth_key(&self) -> &[u8; 256] {
        &self.auth_key
    }
    pub const fn auth_key_id(&self) -> u64 {
        self.auth_key_id
    }
    pub const fn server_salt(&self) -> u64 {
        self.server_salt
    }
    pub const fn server_time(&self) -> i32 {
        self.server_time
    }
}

impl Drop for AuthKeyMaterial {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.auth_key_id = 0;
        self.server_salt = 0;
        self.server_time = 0;
    }
}

/// Fixed-memory, resumable authorization-key handshake.
#[derive(Debug)]
pub struct AuthKeyHandshake {
    dc_id: i32,
    nonce: [u8; 16],
    server_nonce: [u8; 16],
    new_nonce: [u8; 32],
    dh_prime: [u8; 256],
    g_a: [u8; 256],
    auth_key: [u8; 256],
    server_time: i32,
    state: u8,
}

impl AuthKeyHandshake {
    /// Starts a production-DC handshake.  `dc_id` is encoded unchanged.
    pub fn new(random: &mut dyn RandomSource, dc_id: i32) -> Result<Self> {
        Self::new_inner(random, dc_id)
    }

    /// Starts a Test DC handshake.  Telegram encodes Test DC 2 as `10002`.
    pub fn new_test_dc(random: &mut dyn RandomSource, dc_id: i32) -> Result<Self> {
        Self::new_inner(random, dc_id.saturating_add(10_000))
    }

    fn new_inner(random: &mut dyn RandomSource, dc_id: i32) -> Result<Self> {
        let mut value = Self {
            dc_id,
            nonce: [0; 16],
            server_nonce: [0; 16],
            new_nonce: [0; 32],
            dh_prime: [0; 256],
            g_a: [0; 256],
            auth_key: [0; 256],
            server_time: 0,
            state: 0,
        };
        random.fill(&mut value.nonce)?;
        random.fill(&mut value.new_nonce)?;
        Ok(value)
    }

    /// Writes a plain `req_pq_multi` body.
    pub fn write_req_pq(&self, output: &mut [u8]) -> Result<usize> {
        let mut writer = Writer::new(output);
        writer.write_constructor(REQ_PQ_MULTI)?;
        writer.write_all(&self.nonce)?;
        Ok(writer.position())
    }

    /// Consumes `resPQ` and writes the plain `req_DH_params` body.
    pub fn accept_res_pq(
        &mut self,
        input: &[u8],
        random: &mut dyn RandomSource,
        output: &mut [u8],
    ) -> Result<usize> {
        if self.state != 0 {
            return Err(Error::new(ErrorKind::InvalidState, 0, self.state as u32));
        }
        let mut cursor = Cursor::new(input);
        cursor.expect_constructor(RES_PQ)?;
        if cursor.read_int128()? != &self.nonce {
            return Err(Error::new(ErrorKind::Authentication, 4, 0));
        }
        self.server_nonce = *cursor.read_int128()?;
        let pq_bytes = cursor.read_bytes()?.as_slice();
        if pq_bytes.is_empty() || pq_bytes.len() > 8 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                0,
                narrow(pq_bytes.len()),
            ));
        }
        let mut pq = 0u64;
        for byte in pq_bytes {
            pq = (pq << 8) | u64::from(*byte);
        }
        let mut fingerprints = [0u64; 8];
        let count = cursor.read_vector_len(8)? as usize;
        for item in &mut fingerprints[..count] {
            *item = cursor.read_u64()?;
        }
        cursor.finish()?;
        if !fingerprints[..count].contains(&TEST_DC_RSA_FINGERPRINT) {
            return Err(Error::new(
                ErrorKind::Authentication,
                0,
                TEST_DC_RSA_FINGERPRINT as u32,
            ));
        }
        let (p, q) = factor_pq(pq, self.nonce[0] as u64)?;
        let mut inner = [0u8; 144];
        let inner_len = {
            let mut iw = Writer::new(&mut inner);
            iw.write_constructor(PQ_INNER_DATA_DC)?;
            iw.write_bytes(pq_bytes)?;
            iw.write_bytes(&minimal_u32(p))?;
            iw.write_bytes(&minimal_u32(q))?;
            iw.write_all(&self.nonce)?;
            iw.write_all(&self.server_nonce)?;
            iw.write_all(&self.new_nonce)?;
            iw.write_i32(self.dc_id)?;
            iw.position()
        };
        let mut encrypted = [0u8; 256];
        rsa_pad_encrypt(&inner[..inner_len], random, &mut encrypted)?;
        let mut writer = Writer::new(output);
        writer.write_constructor(REQ_DH_PARAMS)?;
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.server_nonce)?;
        writer.write_bytes(&minimal_u32(p))?;
        writer.write_bytes(&minimal_u32(q))?;
        writer.write_i64(TEST_DC_RSA_FINGERPRINT as i64)?;
        writer.write_bytes(&encrypted)?;
        self.state = 1;
        Ok(writer.position())
    }

    /// Decrypts `server_DH_params_ok` and writes `set_client_DH_params`.
    pub fn accept_server_dh(
        &mut self,
        input: &[u8],
        random: &mut dyn RandomSource,
        output: &mut [u8],
    ) -> Result<usize> {
        if self.state != 1 {
            return Err(Error::new(ErrorKind::InvalidState, 0, self.state as u32));
        }
        let mut cursor = Cursor::new(input);
        cursor.expect_constructor(SERVER_DH_PARAMS_OK)?;
        if cursor.read_int128()? != &self.nonce {
            return Err(Error::new(ErrorKind::Authentication, 4, 0));
        }
        if cursor.read_int128()? != &self.server_nonce {
            return Err(Error::new(ErrorKind::Authentication, 20, 0));
        }
        let encrypted = cursor.read_bytes()?.as_slice();
        cursor.finish()?;
        if encrypted.len() < 32 || encrypted.len() > 1_024 || encrypted.len() & 15 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                0,
                narrow(encrypted.len()),
            ));
        }
        let mut plain = [0u8; 1_024];
        plain[..encrypted.len()].copy_from_slice(encrypted);
        let (key, iv) = temporary_aes(&self.new_nonce, &self.server_nonce);
        aes_ige_decrypt_raw(&key, &iv, &mut plain[..encrypted.len()])?;
        let mut inner = Cursor::new(&plain[20..encrypted.len()]);
        inner.expect_constructor(SERVER_DH_INNER_DATA)?;
        if inner.read_int128()? != &self.nonce || inner.read_int128()? != &self.server_nonce {
            return Err(Error::new(ErrorKind::Authentication, 0, 2));
        }
        let g = inner.read_i32()?;
        let prime = inner.read_bytes()?.as_slice();
        let ga = inner.read_bytes()?.as_slice();
        self.server_time = inner.read_i32()?;
        if inner.remaining_len() > 15 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(inner.position()),
                narrow(inner.remaining_len()),
            ));
        }
        let expected = sha1(&plain[20..20 + inner.position()]);
        if expected.ct_eq((&plain[..20]).into()).unwrap_u8() != 1 {
            return Err(Error::new(ErrorKind::Authentication, 0, 1));
        }
        if !(2..=7).contains(&g) || prime != DH_PRIME.to_be_bytes().as_ref() || ga.len() != 256 {
            return Err(Error::new(ErrorKind::InvalidPacket, 0, g as u32));
        }
        let prime_uint = DH_PRIME;
        let ga_uint = U2048::from_be_slice(ga);
        let lower = U2048::ONE.shl_vartime(1984);
        if ga_uint < lower {
            return Err(Error::new(ErrorKind::InvalidPacket, 0, 31));
        }
        if ga_uint > prime_uint.saturating_sub(&lower) {
            return Err(Error::new(ErrorKind::InvalidPacket, 0, 32));
        }
        self.dh_prime.copy_from_slice(prime);
        self.g_a.copy_from_slice(ga);
        random.fill(&mut self.auth_key)?;
        let mut b = U2048::from_be_slice(&self.auth_key);
        let params = MontyParams::<32>::new_vartime(
            Odd::new(prime_uint)
                .into_option()
                .ok_or_else(|| Error::new(ErrorKind::InvalidPacket, 0, 4))?,
        );
        let gb = MontyForm::new(&U2048::from_u32(g as u32), params)
            .pow(&b)
            .retrieve();
        let shared = MontyForm::new(&ga_uint, params).pow(&b).retrieve();
        if gb < lower || gb > prime_uint.saturating_sub(&lower) {
            return Err(Error::new(ErrorKind::InvalidPacket, 0, 33));
        }
        let gb_bytes = gb.to_be_bytes();
        let shared_bytes = shared.to_be_bytes();
        self.auth_key.copy_from_slice(shared_bytes.as_ref());
        b.zeroize();
        let mut client = [0u8; 512];
        let mut cw = Writer::new(&mut client[20..]);
        cw.write_constructor(CLIENT_DH_INNER_DATA)?;
        cw.write_all(&self.nonce)?;
        cw.write_all(&self.server_nonce)?;
        cw.write_i64(0)?;
        cw.write_bytes(gb_bytes.as_ref())?;
        let body_len = cw.position();
        let total = (20 + body_len + 15) & !15;
        let hash = sha1(&client[20..20 + body_len]);
        client[..20].copy_from_slice(&hash);
        random.fill(&mut client[20 + body_len..total])?;
        aes_ige_encrypt_raw(&key, &iv, &mut client[..total])?;
        let mut writer = Writer::new(output);
        writer.write_constructor(SET_CLIENT_DH_PARAMS)?;
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.server_nonce)?;
        writer.write_bytes(&client[..total])?;
        self.state = 2;
        Ok(writer.position())
    }

    /// Verifies `dh_gen_ok` and returns the resulting session material.
    pub fn finish(&mut self, input: &[u8]) -> Result<AuthKeyMaterial> {
        if self.state != 2 {
            return Err(Error::new(ErrorKind::InvalidState, 0, self.state as u32));
        }
        let mut cursor = Cursor::new(input);
        let id = cursor.read_constructor()?;
        if id != DH_GEN_OK {
            return Err(Error::new(
                if id == DH_GEN_RETRY || id == DH_GEN_FAIL {
                    ErrorKind::Authentication
                } else {
                    ErrorKind::UnexpectedConstructor
                },
                0,
                id.get(),
            ));
        }
        if cursor.read_int128()? != &self.nonce || cursor.read_int128()? != &self.server_nonce {
            return Err(Error::new(ErrorKind::Authentication, 0, 5));
        }
        let hash = cursor.read_int128()?;
        cursor.finish()?;
        let mut auth_hash = sha1(&self.auth_key);
        let mut input_hash = [0u8; 41];
        input_hash[..32].copy_from_slice(&self.new_nonce);
        input_hash[32] = 1;
        input_hash[33..].copy_from_slice(&auth_hash[..8]);
        let expected = sha1(&input_hash);
        if expected[4..20].ct_eq(hash).unwrap_u8() != 1 {
            return Err(Error::new(ErrorKind::Authentication, 0, 6));
        }
        let mut salt_bytes = [0u8; 8];
        for (index, byte) in salt_bytes.iter_mut().enumerate() {
            *byte = self.new_nonce[index] ^ self.server_nonce[index];
        }
        let auth_key_id = u64::from_le_bytes(
            auth_hash[12..20]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 8))?,
        );
        let material = AuthKeyMaterial {
            auth_key: self.auth_key,
            auth_key_id,
            server_salt: u64::from_le_bytes(salt_bytes),
            server_time: self.server_time,
        };
        self.auth_key = [0; 256];
        self.state = 3;
        auth_hash.zeroize();
        Ok(material)
    }
}

impl Drop for AuthKeyHandshake {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.server_nonce.zeroize();
        self.new_nonce.zeroize();
        self.dh_prime.zeroize();
        self.g_a.zeroize();
        self.auth_key.zeroize();
    }
}

fn sha1(input: &[u8]) -> [u8; 20] {
    let mut digest = Sha1::new();
    digest.update(input);
    let value = digest.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(value.as_ref());
    out
}

fn temporary_aes(new_nonce: &[u8; 32], server_nonce: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let mut first = [0u8; 48];
    first[..32].copy_from_slice(new_nonce);
    first[32..].copy_from_slice(server_nonce);
    let mut second = [0u8; 48];
    second[..16].copy_from_slice(server_nonce);
    second[16..].copy_from_slice(new_nonce);
    let a = sha1(&first);
    let b = sha1(&second);
    let c = {
        let mut v = [0u8; 64];
        v[..32].copy_from_slice(new_nonce);
        v[32..].copy_from_slice(new_nonce);
        sha1(&v[..64])
    };
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(&a);
    key[20..].copy_from_slice(&b[..12]);
    let mut iv = [0u8; 32];
    iv[..8].copy_from_slice(&b[12..20]);
    iv[8..28].copy_from_slice(&c);
    iv[28..].copy_from_slice(&new_nonce[..4]);
    (key, iv)
}

fn rsa_pad_encrypt(
    data: &[u8],
    random: &mut dyn RandomSource,
    output: &mut [u8; 256],
) -> Result<()> {
    if data.len() > 144 {
        return Err(Error::new(ErrorKind::InvalidLength, 0, narrow(data.len())));
    }
    let mut padded = [0u8; 192];
    padded[..data.len()].copy_from_slice(data);
    random.fill(&mut padded[data.len()..])?;
    let mut reversed = [0u8; 192];
    for index in 0..192 {
        reversed[index] = padded[191 - index];
    }
    for _ in 0..64 {
        let mut temp_key = [0u8; 32];
        random.fill(&mut temp_key)?;
        let mut hash_input = [0u8; 224];
        hash_input[..32].copy_from_slice(&temp_key);
        hash_input[32..].copy_from_slice(&padded);
        let digest = Sha256::digest(&hash_input);
        let mut data_hash = [0u8; 224];
        data_hash[..192].copy_from_slice(&reversed);
        data_hash[192..].copy_from_slice(digest.as_ref());
        aes_ige_encrypt_raw(&temp_key, &[0; 32], &mut data_hash)?;
        let encrypted_hash = Sha256::digest(&data_hash);
        for index in 0..32 {
            temp_key[index] ^= encrypted_hash[index];
        }
        let mut candidate = [0u8; 256];
        candidate[..32].copy_from_slice(&temp_key);
        candidate[32..].copy_from_slice(&data_hash);
        let value = U2048::from_be_slice(&candidate);
        if value < RSA_MODULUS {
            let params = MontyParams::<32>::new_vartime(
                Odd::new(RSA_MODULUS)
                    .into_option()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidState, 0, 0))?,
            );
            let encrypted = MontyForm::new(&value, params)
                .pow(&U2048::from_u32(65_537))
                .retrieve()
                .to_be_bytes();
            output.copy_from_slice(encrypted.as_ref());
            return Ok(());
        }
    }
    Err(Error::new(ErrorKind::LimitExceeded, 0, 64))
}

fn minimal_u32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn factor_pq(n: u64, seed: u64) -> Result<(u32, u32)> {
    if n < 15 || n & 1 == 0 {
        return Err(Error::new(ErrorKind::InvalidPacket, 0, n as u32));
    }
    let mut c = 1 + (seed % (n - 1));
    for _ in 0..32 {
        let mut x = 2 + (seed.wrapping_add(c) % (n - 3));
        let mut y = x;
        let mut d = 1u64;
        for _ in 0..200_000 {
            x = (mod_mul(x, x, n) + c) % n;
            y = (mod_mul(y, y, n) + c) % n;
            y = (mod_mul(y, y, n) + c) % n;
            d = gcd(x.abs_diff(y), n);
            if d > 1 {
                break;
            }
        }
        if d > 1 && d < n && n / d * d == n {
            let (a, b) = (d.min(n / d), d.max(n / d));
            if a <= u32::MAX as u64 && b <= u32::MAX as u64 {
                return Ok((a as u32, b as u32));
            }
        }
        c = c.wrapping_add(2);
    }
    Err(Error::new(ErrorKind::LimitExceeded, 0, n as u32))
}

fn mod_mul(a: u64, b: u64, n: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(n)) as u64
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixed(u8);
    impl RandomSource for Fixed {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<()> {
            for b in bytes {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn writes_req_pq_without_std_or_alloc() {
        let mut random = Fixed(1);
        let state = AuthKeyHandshake::new_test_dc(&mut random, 2).expect("state");
        let mut bytes = [0u8; 20];
        let len = state.write_req_pq(&mut bytes).expect("write");
        assert_eq!(len, 20);
        assert_eq!(&bytes[..4], &REQ_PQ_MULTI.get().to_le_bytes());
    }

    #[test]
    fn factors_test_sized_pq() {
        assert_eq!(
            factor_pq(1_786_331_737u64 * 1_880_278_339, 7).expect("factor"),
            (1_786_331_737, 1_880_278_339)
        );
    }
}

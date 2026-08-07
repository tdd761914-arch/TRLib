//! Small interactive Test DC login probe.  It intentionally keeps all
//! credentials in stdin-owned buffers and does not print the auth key.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use trlib_core::api::{
    ApiContext, AuthResponse, CodeSettings, parse_auth_response, write_get_me,
    write_init_connection_prefix, write_send_code, write_sign_in,
};
use trlib_core::auth_key::{AuthKeyHandshake, AuthKeyMaterial, RandomSource};
use trlib_core::crypto::{AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto};
use trlib_core::generated::users::USERS_USER_FULL;
use trlib_core::mtproto::{
    ExternalEnvelope, OutboundMessage, encode_encrypted, parse_decrypted, parse_external,
};
use trlib_core::tl::{ConstructorId, Cursor, VECTOR, Writer};
use trlib_core::transport::{Framing, Intermediate};
use trlib_core::{Error, ErrorKind, Result};

const TEST_DC: &str = "149.154.167.40:80";
const RPC_RESULT: ConstructorId = ConstructorId::new(0xf35c6d01);
const MSG_CONTAINER: ConstructorId = ConstructorId::new(0x73f1f8dc);

fn main() {
    if let Err(error) = run() {
        eprintln!("tg-test-login: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let address: SocketAddr = std::env::var("TRLIB_TEST_DC")
        .unwrap_or_else(|_| TEST_DC.into())
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidPacket, 0, 0))?;
    let api_id = prompt("API ID: ")?
        .parse::<i32>()
        .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 0))?;
    let api_hash = prompt("API hash: ")?;
    let phone = prompt("Phone (+...): ")?;
    let mut random = OsRandom;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 1))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_nodelay(true).ok();
    let codec = Intermediate;
    stream
        .write_all(codec.init_bytes())
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 2))?;

    let mut handshake = AuthKeyHandshake::new_test_dc(&mut random, 2)?;
    let mut session_bytes = [0u8; 8];
    random.fill(&mut session_bytes)?;
    let session_id = u64::from_le_bytes(session_bytes);
    let mut body = [0u8; 1024];
    let body_len = handshake.write_req_pq(&mut body)?;
    send_plain(&mut stream, &codec, &body[..body_len])?;
    let mut frame = [0u8; 8192];
    let len = receive_frame(&mut stream, &codec, &mut frame)?;
    let res_pq = plain_body(&frame[..len])?;
    let body_len = handshake.accept_res_pq(res_pq, &mut random, &mut body)?;
    send_plain(&mut stream, &codec, &body[..body_len])?;
    let len = receive_frame(&mut stream, &codec, &mut frame)?;
    let server_dh = plain_body(&frame[..len])?;
    let body_len = handshake.accept_server_dh(server_dh, &mut random, &mut body)?;
    send_plain(&mut stream, &codec, &body[..body_len])?;
    let len = receive_frame(&mut stream, &codec, &mut frame)?;
    let dh_gen = plain_body(&frame[..len])?;
    let material = handshake.finish(dh_gen)?;
    eprintln!(
        "MTProto auth key established on Test DC2 (id {:016x})",
        material.auth_key_id()
    );

    let context = ApiContext::new(
        api_id,
        &api_hash,
        "TRLib test",
        "rust",
        "0.1",
        "en",
        "",
        "en",
    );
    let request_len = {
        let mut writer = Writer::new(&mut body);
        write_init_connection_prefix(&mut writer, context)?;
        write_send_code(&mut writer, context, &phone, CodeSettings::EMPTY)?;
        writer.position()
    };
    let response_len = encrypted_call(
        &mut stream,
        &codec,
        &material,
        &mut random,
        session_id,
        1,
        &body[..request_len],
        &mut frame,
    )?;
    let result = rpc_result_body(&frame[..response_len])?;
    let sent = match parse_auth_response(result)? {
        AuthResponse::SentCode(value) => value,
        AuthResponse::RpcError(error) => {
            eprintln!("Telegram RPC {}: {}", error.code, error.message.as_str());
            return Err(Error::new(ErrorKind::Authentication, 0, error.code as u32));
        }
        _ => return Err(Error::new(ErrorKind::UnexpectedConstructor, 0, 0)),
    };
    let hash = sent.phone_code_hash.as_str().as_bytes();
    if hash.len() > 128 {
        return Err(Error::new(ErrorKind::LimitExceeded, 0, hash.len() as u32));
    }
    let mut phone_code_hash = [0u8; 128];
    phone_code_hash[..hash.len()].copy_from_slice(hash);
    let phone_code_hash_len = hash.len();
    let code = prompt("Login code: ")?;
    let request_len = {
        let hash_str = core::str::from_utf8(&phone_code_hash[..phone_code_hash_len])
            .map_err(|_| Error::new(ErrorKind::InvalidUtf8, 0, 0))?;
        let mut writer = Writer::new(&mut body);
        write_sign_in(&mut writer, &phone, hash_str, &code)?;
        writer.position()
    };
    let response_len = encrypted_call(
        &mut stream,
        &codec,
        &material,
        &mut random,
        session_id,
        3,
        &body[..request_len],
        &mut frame,
    )?;
    match parse_auth_response(rpc_result_body(&frame[..response_len])?)? {
        AuthResponse::Authorized(_) => {
            println!("Login successful on Telegram Test DC2.");
            let request_len = {
                let mut writer = Writer::new(&mut body);
                write_get_me(&mut writer)?;
                writer.position()
            };
            let response_len = encrypted_call(
                &mut stream,
                &codec,
                &material,
                &mut random,
                session_id,
                5,
                &body[..request_len],
                &mut frame,
            )?;
            let profile_result = rpc_result_body(&frame[..response_len])?;
            let mut profile = Cursor::new(profile_result);
            let profile_constructor = profile.read_constructor()?.get();
            if profile_constructor == USERS_USER_FULL.get() {
                println!("getMe profile response: users.userFull ({profile_constructor:#010x})");
            } else {
                println!("getMe response constructor: {profile_constructor:#010x}");
            }
        }
        AuthResponse::RpcError(error) => {
            eprintln!("Telegram RPC {}: {}", error.code, error.message.as_str());
            return Err(Error::new(ErrorKind::Authentication, 0, error.code as u32));
        }
        AuthResponse::SentCode(_) => return Err(Error::new(ErrorKind::InvalidState, 0, 3)),
        _ => return Err(Error::new(ErrorKind::UnexpectedConstructor, 0, 0)),
    }
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout()
        .flush()
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 4))?;
    let mut value = String::new();
    let read = io::stdin()
        .read_line(&mut value)
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 5))?;
    if read == 0 {
        return Err(Error::new(ErrorKind::InvalidState, 0, 16));
    }
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    if value.is_empty() {
        return Err(Error::new(ErrorKind::InvalidLength, 0, 0));
    }
    Ok(value)
}

fn send_plain(stream: &mut TcpStream, codec: &Intermediate, body: &[u8]) -> Result<()> {
    let mut packet = [0u8; 2048];
    let mut writer = Writer::new(&mut packet);
    writer.write_u64(0)?;
    writer.write_u64(message_id()?)?;
    writer.write_u32(body.len() as u32)?;
    writer.write_all(body)?;
    let mut framed = [0u8; 4096];
    let framed_len = codec.encode(writer.written(), &mut framed)?;
    stream
        .write_all(&framed[..framed_len])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 6))
}

fn encrypted_call(
    stream: &mut TcpStream,
    codec: &Intermediate,
    material: &AuthKeyMaterial,
    random: &mut dyn RandomSource,
    session_id: u64,
    sequence: u32,
    body: &[u8],
    frame: &mut [u8],
) -> Result<usize> {
    let auth_key = AuthKeyRef::new(material.auth_key())?;
    let padding_len = {
        let aligned = (16usize - ((32 + body.len()) & 15)) & 15;
        if aligned < 12 { aligned + 16 } else { aligned }
    };
    let mut padding = [0u8; 32];
    random.fill(&mut padding[..padding_len])?;
    let mut packet = [0u8; 8192];
    let packet_len = encode_encrypted(
        &RustCrypto,
        CryptoDirection::ClientToServer,
        &auth_key,
        material.auth_key_id(),
        OutboundMessage {
            server_salt: material.server_salt(),
            session_id,
            message_id: message_id()?,
            sequence_number: sequence,
            body,
            padding: &padding[..padding_len],
        },
        &mut packet,
    )?;
    let mut framed = [0u8; 9000];
    let framed_len = codec.encode(&packet[..packet_len], &mut framed)?;
    stream
        .write_all(&framed[..framed_len])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 7))?;
    for _ in 0..8 {
        let frame_len = receive_frame(stream, codec, frame)?;
        let (body_start, body_len) = {
            let payload = &mut frame[4..frame_len];
            let envelope = match parse_external(payload, 8_192)? {
                ExternalEnvelope::Encrypted(value) => value,
                _ => return Err(Error::new(ErrorKind::InvalidPacket, 0, 0)),
            };
            let message_key = *envelope.message_key;
            let encrypted_offset = 24usize;
            RustCrypto.open(
                CryptoDirection::ServerToClient,
                &auth_key,
                &message_key,
                &mut payload[encrypted_offset..],
            )?;
            let decrypted = parse_decrypted(&payload[encrypted_offset..], 8_192)?;
            (4 + encrypted_offset + 32, decrypted.body.len())
        };
        let body_end = body_start + body_len;
        frame.copy_within(body_start..body_end, 0);
        if rpc_result_body(&frame[..body_len]).is_ok() {
            return Ok(body_len);
        }
    }
    Err(Error::new(ErrorKind::InvalidState, 0, 15))
}

fn receive_frame(stream: &mut TcpStream, codec: &Intermediate, frame: &mut [u8]) -> Result<usize> {
    stream
        .read_exact(&mut frame[..4])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 8))?;
    let encoded = u32::from_le_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidLength, 0, 4))?,
    );
    let total = 4usize
        .checked_add(encoded as usize)
        .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, encoded))?;
    if encoded == 0 || encoded & 3 != 0 || total > frame.len() {
        return Err(Error::new(ErrorKind::InvalidLength, 0, encoded));
    }
    stream
        .read_exact(&mut frame[4..total])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 9))?;
    let _ = codec.decode(&frame[..total], frame.len() as u32)?;
    Ok(total)
}

fn plain_body(frame: &[u8]) -> Result<&[u8]> {
    match parse_external(&frame[4..], 8_192)? {
        ExternalEnvelope::Plain(value) => Ok(value.body),
        _ => Err(Error::new(ErrorKind::InvalidPacket, 0, 0)),
    }
}

fn rpc_result_body(input: &[u8]) -> Result<&[u8]> {
    let mut cursor = Cursor::new(input);
    match cursor.read_constructor()? {
        RPC_RESULT => {
            let _ = cursor.read_i64()?;
            Ok(cursor.remaining())
        }
        MSG_CONTAINER => {
            // `%Message` is a bare vector in the MTProto core schema, so
            // Telegram sends the count directly (some proxies add VECTOR).
            let first = cursor.read_u32()?;
            let count = if first == VECTOR.get() {
                cursor.read_u32()?
            } else {
                first
            } as usize;
            if count > 16 {
                return Err(Error::new(ErrorKind::LimitExceeded, 4, count as u32));
            }
            for _ in 0..count {
                let _message_id = cursor.read_u64()?;
                let _sequence = cursor.read_u32()?;
                let length = cursor.read_u32()? as usize;
                let message = cursor.take(length)?;
                if let Ok(result) = rpc_result_body(message) {
                    return Ok(result);
                }
            }
            Err(Error::new(ErrorKind::InvalidState, 0, 14))
        }
        _ => Err(Error::new(ErrorKind::UnexpectedConstructor, 0, 0)),
    }
}

fn message_id() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 11))?;
    Ok(((now.as_secs() << 32) | ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000)) & !3)
}

struct OsRandom;
impl RandomSource for OsRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut file =
            File::open("/dev/urandom").map_err(|_| Error::new(ErrorKind::InvalidState, 0, 12))?;
        file.read_exact(bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 13))
    }
}

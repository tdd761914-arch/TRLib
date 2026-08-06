use std::hint::black_box;
use std::mem::size_of;
use std::time::Instant;

#[cfg(feature = "crypto-rustcrypto")]
use trlib_core::crypto::{AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto};
use trlib_core::mtproto::ExternalEnvelope;
#[cfg(not(feature = "transport-intermediate"))]
use trlib_core::mtproto::parse_external;
#[cfg(feature = "tdlib-compat")]
use trlib_core::session::{
    SESSION_DOCUMENT_BYTES, SESSION_RECORD_BYTES, SessionKey, SessionMetadata, SessionRecordRef,
    seal,
};
#[cfg(feature = "tdlib-compat")]
use trlib_core::tdlib::{TdDispatch, parse_request, write_request};
#[cfg(feature = "transport-intermediate")]
use trlib_core::{
    config::GatewayConfig,
    gateway::{CoreGateway, GatewayPoll},
    transport::Intermediate,
};

const ITERATIONS: u64 = 10_000_000;

fn main() {
    let mut packet = [0u8; 44];
    packet[..4].copy_from_slice(&40u32.to_le_bytes());
    packet[4..12].fill(0);
    packet[12..20].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    packet[20..24].copy_from_slice(&20u32.to_le_bytes());
    packet[24..28].copy_from_slice(&0xbe7e_8ef1u32.to_le_bytes());

    let started = Instant::now();
    let mut accumulator = 0u64;
    #[cfg(feature = "transport-intermediate")]
    let gateway = CoreGateway::new(&Intermediate, GatewayConfig::LOW_MEMORY);
    for _ in 0..ITERATIONS {
        #[cfg(feature = "transport-intermediate")]
        {
            if let GatewayPoll::Packet {
                envelope: ExternalEnvelope::Plain(plain),
                ..
            } = black_box(&gateway)
                .poll(black_box(&packet))
                .expect("gateway poll")
            {
                accumulator ^= plain.message_id;
                accumulator ^= u64::from_le_bytes([
                    plain.body[0],
                    plain.body[1],
                    plain.body[2],
                    plain.body[3],
                    0,
                    0,
                    0,
                    0,
                ]);
            }
        }
        #[cfg(not(feature = "transport-intermediate"))]
        {
            if let ExternalEnvelope::Plain(plain) =
                parse_external(black_box(&packet[4..]), 1_048_576).expect("envelope")
            {
                accumulator ^= plain.message_id;
            }
        }
    }
    let elapsed = started.elapsed();
    println!("iterations={ITERATIONS}");
    println!("elapsed_ns={}", elapsed.as_nanos());
    println!(
        "ns_per_frame={:.3}",
        elapsed.as_nanos() as f64 / ITERATIONS as f64
    );
    println!("guard={}", black_box(accumulator));
    println!("sizeof_error={}", size_of::<trlib_core::Error>());
    println!(
        "sizeof_gateway_config={}",
        size_of::<trlib_core::config::GatewayConfig>()
    );
    println!(
        "sizeof_core_gateway={}",
        size_of::<trlib_core::gateway::CoreGateway<'static>>()
    );
    println!(
        "sizeof_replay_window={}",
        size_of::<trlib_core::mtproto::MessageIdWindow>()
    );

    #[cfg(feature = "crypto-rustcrypto")]
    link_crypto_path();
    #[cfg(feature = "tdlib-compat")]
    link_tdlib_compat_path();
}

#[cfg(feature = "crypto-rustcrypto")]
fn link_crypto_path() {
    let auth_key_bytes = [0x5au8; 256];
    let auth_key = AuthKeyRef::new(black_box(&auth_key_bytes)).expect("auth key");
    let mut block = [0x33u8; 64];
    let mut message_key = [0u8; 16];
    RustCrypto
        .seal(
            CryptoDirection::ClientToServer,
            &auth_key,
            black_box(&mut block),
            &mut message_key,
        )
        .expect("seal");
    RustCrypto
        .open(
            CryptoDirection::ClientToServer,
            &auth_key,
            &message_key,
            black_box(&mut block),
        )
        .expect("open");
    println!("crypto_guard={}", black_box(block[0]));
}

#[cfg(feature = "tdlib-compat")]
fn link_tdlib_compat_path() {
    let parameters = parse_request(
        br#"{"@type":"setTdlibParameters","api_id":1,"api_hash":"h","device_model":"d","system_version":"s","application_version":"a","system_language_code":"en"}"#,
    )
    .expect("parameters");
    let mut request_output = [0u8; 128];
    let context = {
        let mut writer = trlib_core::tl::Writer::new(&mut request_output);
        match write_request(&mut writer, parameters, None, None).expect("parameters dispatch") {
            TdDispatch::Parameters(context) => context,
            TdDispatch::Method(_) => panic!("unexpected RPC method"),
        }
    };
    let request =
        parse_request(br#"{"@type":"setAuthenticationPhoneNumber","phone_number":"+12025550123"}"#)
            .expect("phone");
    let mut writer = trlib_core::tl::Writer::new(&mut request_output);
    let method = write_request(&mut writer, request, Some(context), None).expect("send code");

    let auth_key = [7u8; 256];
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
    let key = SessionKey::from_bytes([8; 32]);
    let mut crypto_scratch = [0u8; SESSION_RECORD_BYTES];
    let mut document = [0u8; SESSION_DOCUMENT_BYTES];
    let length = seal(
        &key,
        &[9; 16],
        SessionRecordRef::new(metadata, &auth_key),
        &mut crypto_scratch,
        &mut document,
    )
    .expect("session document");
    println!(
        "tdlib_compat_guard={:?}:{}:{}",
        black_box(method),
        black_box(request_output[0]),
        black_box(length)
    );
}

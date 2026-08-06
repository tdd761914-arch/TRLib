use std::hint::black_box;
use std::mem::size_of;
use std::time::Instant;

#[cfg(feature = "crypto-rustcrypto")]
use trlib_core::crypto::{AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto};
use trlib_core::mtproto::ExternalEnvelope;
#[cfg(not(feature = "transport-intermediate"))]
use trlib_core::mtproto::parse_external;
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

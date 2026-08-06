//! Live, credential-free first-step MTProto handshake against Telegram test DC 2.

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use trlib_core::mtproto::{ExternalEnvelope, parse_external};
use trlib_core::tl::{ConstructorId, Cursor, Writer};
use trlib_core::transport::{FrameStatus, Framing, Intermediate};

const DEFAULT_TEST_DC: &str = "149.154.167.40:80";
const REQ_PQ_MULTI: ConstructorId = ConstructorId::new(0xbe7e_8ef1);
const RES_PQ: ConstructorId = ConstructorId::new(0x0516_2463);
const MAX_ROUNDS: usize = 256;

#[derive(Clone, Copy)]
struct Options {
    address: SocketAddr,
    rounds: usize,
    timeout: Duration,
    json: bool,
}

#[derive(Clone, Copy, Default)]
struct Sample {
    connect_micros: u128,
    response_micros: u128,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tg-test-dc: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_options()?;
    let mut samples = [Sample::default(); MAX_ROUNDS];
    let mut last_pq = [0u8; 32];
    let mut last_pq_length = 0usize;
    let mut last_fingerprint_count = 0u32;

    for sample in &mut samples[..options.rounds] {
        let result = probe_once(options.address, options.timeout)?;
        *sample = result.sample;
        last_pq_length = result.pq_length;
        last_pq[..last_pq_length].copy_from_slice(&result.pq[..last_pq_length]);
        last_fingerprint_count = result.fingerprint_count;
    }

    samples[..options.rounds].sort_unstable_by_key(|sample| sample.response_micros);
    let median = samples[(options.rounds - 1) / 2];
    let p95_index = ((options.rounds * 95).div_ceil(100)).saturating_sub(1);
    let p95 = samples[p95_index];
    if options.json {
        print!(
            "{{\"dc\":\"{}\",\"rounds\":{},\"median_connect_us\":{},\"median_response_us\":{},\"p95_response_us\":{},\"pq_hex\":\"",
            options.address,
            options.rounds,
            median.connect_micros,
            median.response_micros,
            p95.response_micros,
        );
        print_hex(&last_pq[..last_pq_length]);
        println!("\",\"fingerprints\":{last_fingerprint_count}}}");
    } else {
        println!("Telegram test DC: {}", options.address);
        println!("validated: req_pq_multi -> resPQ (nonce matched)");
        println!("rounds: {}", options.rounds);
        println!("median connect: {} us", median.connect_micros);
        println!("median full response: {} us", median.response_micros);
        println!("p95 full response: {} us", p95.response_micros);
        print!("pq: 0x");
        print_hex(&last_pq[..last_pq_length]);
        println!();
        println!("RSA fingerprints advertised: {last_fingerprint_count}");
    }
    Ok(())
}

struct ProbeResult {
    sample: Sample,
    pq: [u8; 32],
    pq_length: usize,
    fingerprint_count: u32,
}

fn probe_once(
    address: SocketAddr,
    timeout: Duration,
) -> Result<ProbeResult, Box<dyn std::error::Error>> {
    let connect_started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    let connected = Instant::now();
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;

    let mut nonce = [0u8; 16];
    fill_nonce(&mut nonce)?;

    let mut body_storage = [0u8; 20];
    let body_length = {
        let mut body = Writer::new(&mut body_storage);
        body.write_constructor(REQ_PQ_MULTI)?;
        body.write_all(&nonce)?;
        body.position()
    };

    let mut envelope_storage = [0u8; 40];
    let envelope_length = {
        let mut envelope = Writer::new(&mut envelope_storage);
        envelope.write_u64(0)?;
        envelope.write_u64(next_message_id()?)?;
        envelope.write_u32(body_length as u32)?;
        envelope.write_all(&body_storage[..body_length])?;
        envelope.position()
    };

    let codec = Intermediate;
    let mut outbound = [0u8; 44];
    let outbound_length = codec.encode(&envelope_storage[..envelope_length], &mut outbound)?;
    stream.write_all(codec.init_bytes())?;
    stream.write_all(&outbound[..outbound_length])?;

    let mut response = [0u8; 4096];
    stream.read_exact(&mut response[..4])?;
    let encoded_length = u32::from_le_bytes(response[..4].try_into()?);
    if encoded_length == 0 || encoded_length & 3 != 0 {
        return Err(format!("invalid response frame length: {encoded_length}").into());
    }
    let total = 4usize
        .checked_add(encoded_length as usize)
        .ok_or("response length overflow")?;
    if total > response.len() {
        return Err(format!("response frame too large: {total}").into());
    }
    stream.read_exact(&mut response[4..total])?;
    let finished = Instant::now();

    let bounds = match codec.decode(&response[..total], 4_092)? {
        FrameStatus::Packet(bounds) => bounds,
        FrameStatus::NeedMore(required) => {
            return Err(format!("short response, need {required} bytes").into());
        }
        FrameStatus::QuickAck { token, .. } => {
            return Err(format!("unexpected quick ack {token:#x}").into());
        }
    };
    let payload = bounds
        .payload(&response[..total])
        .ok_or("invalid response frame bounds")?;
    let plain = match parse_external(payload, 4_096)? {
        ExternalEnvelope::Plain(plain) => plain,
        ExternalEnvelope::Encrypted(_) => return Err("unexpected encrypted resPQ".into()),
    };
    let mut cursor = Cursor::new(plain.body);
    cursor.expect_constructor(RES_PQ)?;
    let echoed_nonce = cursor.read_int128()?;
    if echoed_nonce != &nonce {
        return Err("resPQ nonce mismatch".into());
    }
    let _server_nonce = cursor.read_int128()?;
    let pq = cursor.read_bytes()?.as_slice();
    let fingerprint_count = cursor.read_vector_len(64)?;
    for _ in 0..fingerprint_count {
        let _fingerprint = cursor.read_i64()?;
    }
    cursor.finish()?;

    if pq.len() > 32 {
        return Err("test DC returned unexpectedly large pq".into());
    }
    let mut pq_copy = [0u8; 32];
    pq_copy[..pq.len()].copy_from_slice(pq);
    Ok(ProbeResult {
        sample: Sample {
            connect_micros: connected.duration_since(connect_started).as_micros(),
            response_micros: finished.duration_since(connect_started).as_micros(),
        },
        pq: pq_copy,
        pq_length: pq.len(),
        fingerprint_count,
    })
}

fn parse_options() -> Result<Options, Box<dyn std::error::Error>> {
    let mut address: SocketAddr = DEFAULT_TEST_DC.parse()?;
    let mut rounds = 5usize;
    let mut timeout = Duration::from_secs(5);
    let mut json = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--address" => address = arguments.next().ok_or("missing address")?.parse()?,
            "--rounds" => rounds = arguments.next().ok_or("missing rounds")?.parse()?,
            "--timeout-ms" => {
                let milliseconds: u64 = arguments.next().ok_or("missing timeout")?.parse()?;
                timeout = Duration::from_millis(milliseconds);
            }
            "--json" => json = true,
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    if rounds == 0 || rounds > MAX_ROUNDS {
        return Err(format!("rounds must be in 1..={MAX_ROUNDS}").into());
    }
    Ok(Options {
        address,
        rounds,
        timeout,
        json,
    })
}

fn fill_nonce(nonce: &mut [u8; 16]) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        File::open("/dev/urandom")?.read_exact(nonce)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = nonce;
        Err("secure nonce source is not implemented for this platform".into())
    }
}

fn next_message_id() -> Result<u64, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let fraction = ((u64::from(now.subsec_nanos())) << 32) / 1_000_000_000;
    let mut message_id = (now.as_secs() << 32) | fraction;
    message_id &= !3;
    if message_id & 0xffff_ffff == 0 {
        message_id |= 4;
    }
    Ok(message_id)
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
}

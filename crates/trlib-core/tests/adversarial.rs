use trlib_core::mtproto::{parse_decrypted, parse_external};
use trlib_core::tl::Cursor;

#[cfg(feature = "transport-abridged")]
use trlib_core::transport::Abridged;
#[cfg(any(feature = "transport-abridged", feature = "transport-intermediate"))]
use trlib_core::transport::Framing;
#[cfg(feature = "transport-intermediate")]
use trlib_core::transport::Intermediate;

#[test]
fn bounded_parsers_do_not_panic_on_truncated_or_mutated_prefixes() {
    let mut bytes = [0u8; 256];
    let mut state = 0x6d2b_79f5u32;
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = state as u8;
    }

    for length in 0..=bytes.len() {
        let input = &bytes[..length];
        let _ = parse_external(input, 1_024);
        let _ = parse_decrypted(input, 1_024);
        let _ = Cursor::new(input).read_bytes();
        #[cfg(feature = "transport-abridged")]
        let _ = Abridged.decode(input, 1_024);
        #[cfg(feature = "transport-intermediate")]
        let _ = Intermediate.decode(input, 1_024);
    }
}

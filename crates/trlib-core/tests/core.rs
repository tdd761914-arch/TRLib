#![cfg(all(
    feature = "service",
    feature = "transport-abridged",
    feature = "transport-intermediate"
))]

use trlib_core::config::GatewayConfig;
use trlib_core::error::ErrorKind;
use trlib_core::gateway::{CoreGateway, GatewayPoll};
use trlib_core::mtproto::{
    ExternalEnvelope, MessageDirection, MessageIdWindow, parse_decrypted, parse_external,
    validate_message_id,
};
use trlib_core::service::{
    MESSAGE, MSG_CONTAINER, MessageKind, ServiceObject, UPDATE_NEW_MESSAGE, parse_message_update,
    parse_service,
};
use trlib_core::tl::{ConstructorId, Cursor, Writer};
use trlib_core::transport::{Abridged, FrameStatus, Framing, Intermediate};

#[derive(Debug, Eq, PartialEq)]
struct TestPong {
    message_id: i64,
    ping_id: i64,
}

trlib_core::tl_constructor! {
    fn parse_test_pong<'a>(cursor) -> TestPong {
        id = 0x3477_73c5;
        {
            Ok(TestPong {
                message_id: cursor.read_i64()?,
                ping_id: cursor.read_i64()?,
            })
        }
    }
}

#[test]
fn borrowed_tl_bytes_round_trip_at_both_length_encodings() {
    let short = [0x55u8; 253];
    let long = [0xaau8; 254];
    let mut storage = [0u8; 520];
    let written = {
        let mut writer = Writer::new(&mut storage);
        writer.write_bytes(&short).expect("short bytes");
        writer.write_bytes(&long).expect("long bytes");
        writer.position()
    };
    let mut cursor = Cursor::new(&storage[..written]);
    assert_eq!(cursor.read_bytes().expect("short").as_slice(), &short);
    assert_eq!(cursor.read_bytes().expect("long").as_slice(), &long);
    cursor.finish().expect("exact input");
}

#[test]
fn tl_rejects_noncanonical_lengths_and_padding() {
    let noncanonical = [254, 1, 0, 0, 7, 0, 0, 0];
    let error = Cursor::new(&noncanonical)
        .read_bytes()
        .expect_err("noncanonical");
    assert_eq!(error.kind(), ErrorKind::InvalidLength);

    let nonzero_padding = [1, 7, 9, 0];
    let error = Cursor::new(&nonzero_padding)
        .read_bytes()
        .expect_err("padding");
    assert_eq!(error.kind(), ErrorKind::InvalidPacket);
}

#[test]
fn constructor_macro_reads_directly_from_cursor() {
    let mut packet = [0u8; 20];
    let length = {
        let mut writer = Writer::new(&mut packet);
        writer
            .write_constructor(ConstructorId::new(0x3477_73c5))
            .expect("id");
        writer.write_i64(11).expect("message id");
        writer.write_i64(22).expect("ping id");
        writer.position()
    };
    let mut cursor = Cursor::new(&packet[..length]);
    assert_eq!(
        parse_test_pong(&mut cursor).expect("pong"),
        TestPong {
            message_id: 11,
            ping_id: 22,
        }
    );
    cursor.finish().expect("exact input");
}

#[test]
fn transport_codecs_return_bounds_into_the_original_buffer() {
    let payload = [7u8; 28];
    for codec in [&Abridged as &dyn Framing, &Intermediate as &dyn Framing] {
        let mut frame = [0u8; 40];
        let length = codec.encode(&payload, &mut frame).expect("encode");
        let bounds = match codec.decode(&frame[..length], 1_024).expect("decode") {
            FrameStatus::Packet(bounds) => bounds,
            other => panic!("unexpected status: {other:?}"),
        };
        assert_eq!(bounds.payload(&frame[..length]), Some(payload.as_slice()));
    }
}

#[test]
fn gateway_poll_is_incremental_and_borrows_the_frame() {
    let mut frame = [0u8; 28];
    frame[..4].copy_from_slice(&24u32.to_le_bytes());
    frame[4..12].fill(0);
    frame[12..20].copy_from_slice(&0x1234u64.to_le_bytes());
    frame[20..24].copy_from_slice(&4u32.to_le_bytes());
    frame[24..28].copy_from_slice(&0xbe7e_8ef1u32.to_le_bytes());

    let gateway = CoreGateway::new(&Intermediate, GatewayConfig::LOW_MEMORY);
    assert!(matches!(
        gateway.poll(&frame[..3]).expect("partial"),
        GatewayPoll::NeedMore(4)
    ));
    let body = match gateway.poll(&frame).expect("packet") {
        GatewayPoll::Packet {
            envelope: ExternalEnvelope::Plain(plain),
            consumed: 28,
        } => plain.body,
        _ => panic!("unexpected gateway event"),
    };
    assert_eq!(body.as_ptr(), frame[24..].as_ptr());
}

#[test]
fn parses_plain_and_decrypted_envelopes_without_copying_bodies() {
    let mut plain_storage = [0u8; 24];
    {
        let mut writer = Writer::new(&mut plain_storage);
        writer.write_u64(0).expect("plain marker");
        writer.write_u64(0x1234).expect("message id");
        writer.write_u32(4).expect("length");
        writer.write_u32(0xbe7e_8ef1).expect("body");
    }
    let plain = match parse_external(&plain_storage, 1_024).expect("plain") {
        ExternalEnvelope::Plain(plain) => plain,
        _ => panic!("expected plain envelope"),
    };
    assert_eq!(plain.body.as_ptr(), plain_storage[20..].as_ptr());

    let mut decrypted_storage = [0u8; 48];
    {
        let mut writer = Writer::new(&mut decrypted_storage);
        writer.write_u64(1).expect("salt");
        writer.write_u64(2).expect("session");
        writer.write_u64(3).expect("message");
        writer.write_u32(4).expect("sequence");
        writer.write_u32(4).expect("length");
        writer.write_u32(5).expect("body");
        writer.write_all(&[9; 12]).expect("padding");
    }
    let decrypted = parse_decrypted(&decrypted_storage, 1_024).expect("decrypted");
    assert_eq!(decrypted.body, &[5, 0, 0, 0]);
    assert_eq!(decrypted.padding, &[9; 12]);
}

#[test]
fn parses_container_and_message_update_as_borrowed_objects() {
    let mut container_storage = [0u8; 32];
    let container_length = {
        let mut writer = Writer::new(&mut container_storage);
        writer
            .write_constructor(MSG_CONTAINER)
            .expect("container id");
        writer.write_u32(1).expect("count");
        writer.write_u64(100).expect("message id");
        writer.write_u32(3).expect("sequence");
        writer.write_u32(4).expect("body length");
        writer.write_u32(0x3477_73c5).expect("body");
        writer.position()
    };
    let mut container = match parse_service(
        &container_storage[..container_length],
        GatewayConfig::LOW_MEMORY,
    )
    .expect("service")
    {
        ServiceObject::Container(container) => container,
        _ => panic!("expected container"),
    };
    let nested = container
        .next_message()
        .expect("entry")
        .expect("valid entry");
    assert_eq!(nested.body, 0x3477_73c5u32.to_le_bytes());
    assert!(container.next_message().is_none());
    container.finish().expect("exact container");

    let mut update_storage = [0u8; 16];
    {
        let mut writer = Writer::new(&mut update_storage);
        writer
            .write_constructor(UPDATE_NEW_MESSAGE)
            .expect("update id");
        writer.write_constructor(MESSAGE).expect("message id");
        writer.write_i32(77).expect("pts");
        writer.write_i32(1).expect("pts count");
    }
    let update = parse_message_update(&update_storage).expect("message update");
    assert_eq!(update.message_kind, MessageKind::Message);
    assert_eq!(update.message.body, &[]);
    assert_eq!(update.pts, 77);
}

#[test]
fn message_id_window_rejects_duplicates_and_old_values() {
    let now = 1_800_000_000u64;
    let client_id = (now << 32) | 4;
    validate_message_id(client_id, MessageDirection::ClientToServer, now).expect("client id");
    validate_message_id(client_id | 1, MessageDirection::ServerToClient, now).expect("server id");

    let mut window = MessageIdWindow::new();
    window.insert(client_id).expect("first");
    let error = window.insert(client_id).expect_err("duplicate");
    assert_eq!(error.kind(), ErrorKind::Authentication);
}

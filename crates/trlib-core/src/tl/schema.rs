//! Schema-driven TL serialization.
//!
//! [`serialize`] walks the generated per-namespace [`ConstructorMeta`] tables
//! so any method in the vendored schema can be written without a hand-written
//! serializer.  Field order and flags-bit positions come from the schema, so
//! bumping `schemas/telegram_api.tl` and regenerating `generated.rs` keeps
//! every caller working without manual TL edits.

use crate::Result;
use crate::error::{Error, ErrorKind};
use crate::tl::{ConstructorId, FieldMeta, Writer};

/// A schema-writer peer, mirroring the three `InputPeer` variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peer {
    /// The authenticated account itself.
    Self_,
    /// A known user with its access hash.
    User {
        /// User identifier.
        user_id: i64,
        /// Server-provided access hash.
        access_hash: i64,
    },
    /// A known channel or supergroup with its access hash.
    Channel {
        /// Channel identifier.
        channel_id: i64,
        /// Server-provided access hash.
        access_hash: i64,
    },
    /// A basic group addressed by identifier only.
    Chat {
        /// Basic group identifier.
        chat_id: i64,
    },
}

impl Peer {
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Peer::Self_ => writer.write_constructor(ConstructorId::new(0x7da0_7ec9)),
            Peer::User {
                user_id,
                access_hash,
            } => {
                writer.write_constructor(ConstructorId::new(0xdde8_a54c))?;
                writer.write_i64(user_id)?;
                writer.write_i64(access_hash)
            }
            Peer::Channel {
                channel_id,
                access_hash,
            } => {
                writer.write_constructor(ConstructorId::new(0x27bc_bbfc))?;
                writer.write_i64(channel_id)?;
                writer.write_i64(access_hash)
            }
            Peer::Chat { chat_id } => {
                writer.write_constructor(ConstructorId::new(0x35a9_5cb9))?;
                writer.write_i64(chat_id)
            }
        }
    }
}

/// One argument consumed by [`serialize`], in schema field order.
///
/// Optional fields take `Skip` when absent; the flags word is derived from the
/// supplied values, so a `True`/`Skip` pair can never produce an invalid body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value<'a> {
    /// A signed 32-bit field.
    Int(i32),
    /// A signed 64-bit field.
    Long(i64),
    /// A TL string field.
    Str(&'a str),
    /// A TL byte-sequence field.
    Bytes(&'a [u8]),
    /// Sets a `flags.N?true` bit.
    True,
    /// Clears a `flags.N?true` bit.
    False,
    /// Marks an optional field as absent.
    Skip,
    /// An `InputPeer` family field.
    Peer(Peer),
    /// A `Vector<int>` field.
    Ints(&'a [i32]),
    /// A `Vector<long>` field.
    Longs(&'a [i64]),
    /// A `Vector<InputMessage>` field of `inputMessageID` objects.
    MessageIds(&'a [i32]),
    /// A `Vector<InputUser>` field of `inputUser` objects with a zero access hash.
    UserIds(&'a [i64]),
    /// An `InputReplyTo` field of `inputReplyToMessage` to a message identifier.
    ReplyTo(i32),
    /// A nested boxed object serialized by a recursive [`serialize`] pass.
    ///
    /// This is the fully generic escape hatch: any boxed type in the schema
    /// can be written through the metadata tables, so new TL field types never
    /// require a new `Value` variant.
    Boxed(ConstructorId, &'a [Value<'a>]),
    /// A nested boxed object with no body.
    Empty(ConstructorId),
    /// A nested boxed object with a pre-serialized body.
    Raw(ConstructorId, &'a [u8]),
}

fn schema_error(offset: usize, detail: u32) -> Error {
    Error::new(ErrorKind::Schema, offset as u32, detail)
}

/// Serializes one schema method from its argument list.
///
/// The constructor identifier and its metadata must belong to an enabled
/// namespace; the number of `values` must match the number of schema fields
/// (flags fields and `{X:Type}` parameters are skipped automatically).  Flags
/// words are computed first and written at the position of the `flags:#`
/// declaration, matching hand-written serializers byte for byte.
pub fn serialize(writer: &mut Writer<'_>, id: ConstructorId, values: &[Value<'_>]) -> Result<()> {
    let meta = crate::generated::lookup_schema(id)
        .ok_or_else(|| schema_error(writer.position(), id.get()))?;
    let mut flags = [0u32; 3];
    let mut values_seen = 0usize;
    let mut value_at = |index: usize| -> Option<Value<'_>> { values.get(index).copied() };
    for field in meta.fields {
        if field.ty == "#" {
            continue;
        }
        if field.flags_field != 0xFF && field.ty != "true" && field.ty != "false" {
            if value_at(values_seen).is_some_and(|value| !matches!(value, Value::Skip)) {
                flags[field.flags_field as usize] |= 1 << field.flags_bit;
            }
            values_seen += 1;
        } else if field.flags_field != 0xFF {
            if matches!(value_at(values_seen), Some(Value::True)) {
                flags[field.flags_field as usize] |= 1 << field.flags_bit;
            }
            values_seen += 1;
        } else {
            values_seen += 1;
        }
    }
    if values_seen < values.len() {
        return Err(schema_error(writer.position(), values_seen as u32));
    }

    writer.write_constructor(id)?;
    let mut values_seen = 0usize;
    for field in meta.fields {
        if field.ty == "#" {
            writer.write_u32(flags[field.flags_field as usize])?;
            continue;
        }
        values_seen += 1;
        let value = values.get(values_seen - 1).copied().unwrap_or(Value::Skip);
        if field.flags_field != 0xFF && (field.ty == "true" || field.ty == "false") {
            continue;
        }
        if field.flags_field != 0xFF {
            if matches!(value, Value::Skip) {
                continue;
            }
            write_value(writer, field, value)?;
        } else {
            write_value(writer, field, value)?;
        }
    }
    Ok(())
}

fn write_value(writer: &mut Writer<'_>, field: &FieldMeta, value: Value<'_>) -> Result<()> {
    match (field.ty, value) {
        ("int", Value::Int(value)) => writer.write_i32(value),
        ("int", Value::Long(value)) => writer.write_i32(value as i32),
        ("long", Value::Long(value)) => writer.write_i64(value),
        ("long", Value::Int(value)) => writer.write_i64(i64::from(value)),
        ("string", Value::Str(value)) => writer.write_string(value),
        ("bytes", Value::Bytes(value)) => writer.write_bytes(value),
        ("InputPeer", Value::Peer(peer)) => peer.write(writer),
        ("Vector<int>", Value::Ints(values)) => {
            writer.write_constructor(ConstructorId::new(0x1cb5_c415))?;
            writer.write_i32(values.len() as i32)?;
            for value in values {
                writer.write_i32(*value)?;
            }
            Ok(())
        }
        ("Vector<long>", Value::Longs(values)) => {
            writer.write_constructor(ConstructorId::new(0x1cb5_c415))?;
            writer.write_i32(values.len() as i32)?;
            for value in values {
                writer.write_i64(*value)?;
            }
            Ok(())
        }
        ("Vector<InputMessage>", Value::MessageIds(values)) => {
            writer.write_constructor(ConstructorId::new(0x1cb5_c415))?;
            writer.write_i32(values.len() as i32)?;
            for value in values {
                writer.write_constructor(ConstructorId::new(0xa676_a322))?;
                writer.write_i32(*value)?;
            }
            Ok(())
        }
        ("Vector<InputUser>", Value::UserIds(values)) => {
            writer.write_constructor(ConstructorId::new(0x1cb5_c415))?;
            writer.write_i32(values.len() as i32)?;
            for value in values {
                writer.write_constructor(ConstructorId::new(0xf211_c586))?;
                writer.write_i64(*value)?;
                writer.write_i64(0)?;
            }
            Ok(())
        }
        ("InputReplyTo", Value::ReplyTo(message_id)) => {
            writer.write_constructor(ConstructorId::new(0x3bd4_b7c2))?;
            writer.write_u32(0)?;
            writer.write_i32(message_id)
        }
        ("Bool", Value::Int(value)) => {
            writer.write_constructor(ConstructorId::new(if value != 0 {
                0x9972_75b5
            } else {
                0xbc79_9737
            }))
        }
        (_, Value::Empty(id)) => writer.write_constructor(id),
        (_, Value::Boxed(id, values)) => serialize(writer, id, values),
        (_, Value::Raw(id, body)) => {
            writer.write_constructor(id)?;
            writer.write_all(body)
        }
        (_, Value::Int(value)) => writer.write_i32(value),
        (_, Value::Long(value)) => writer.write_i64(value),
        (_, Value::Str(value)) => writer.write_string(value),
        (_, Value::Bytes(value)) => writer.write_bytes(value),
        (_, _) => Err(schema_error(
            writer.position(),
            field.name.as_bytes().iter().fold(0u32, |acc, byte| {
                acc.wrapping_mul(31).wrapping_add(*byte as u32)
            }),
        )),
    }
}

#[cfg(all(test, feature = "api-messages"))]
mod tests {
    use super::{Peer, Value, serialize};
    use crate::tl::Writer;

    #[test]
    fn read_history_matches_hand_written_bytes() {
        let mut left = [0u8; 64];
        let mut right = [0u8; 64];
        let peer = Peer::User {
            user_id: 42,
            access_hash: 7,
        };
        let mut generic = Writer::new(&mut left);
        serialize(
            &mut generic,
            crate::generated::MESSAGES_READ_HISTORY,
            &[Value::Peer(peer), Value::Int(100)],
        )
        .expect("serialize");
        let mut typed = Writer::new(&mut right);
        crate::api::write_read_history(&mut typed, crate::api::InputPeer::from(peer), 100)
            .expect("typed");
        assert_eq!(generic.written(), typed.written());
    }

    #[test]
    fn delete_messages_flags_and_vector() {
        let mut output = [0u8; 64];
        let mut writer = Writer::new(&mut output);
        serialize(
            &mut writer,
            crate::generated::MESSAGES_DELETE_MESSAGES,
            &[Value::True, Value::Ints(&[5, 6])],
        )
        .expect("serialize");
        let bytes = writer.written();
        assert_eq!(
            &bytes[..12],
            &[
                0xd2, 0x95, 0x8e, 0xe5, // messages.deleteMessages
                0x01, 0x00, 0x00, 0x00, // revoke
                0x15, 0xc4, 0xb5, 0x1c, // vector
            ]
        );
        assert_eq!(&bytes[12..16], &[2, 0, 0, 0]);
        assert_eq!(&bytes[16..20], &[5, 0, 0, 0]);
        assert_eq!(&bytes[20..24], &[6, 0, 0, 0]);
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn absent_optional_does_not_set_flag() {
        let mut output = [0u8; 64];
        let mut writer = Writer::new(&mut output);
        serialize(
            &mut writer,
            crate::generated::MESSAGES_EDIT_MESSAGE,
            &[
                Value::False, // no_webpage
                Value::False, // invert_media
                Value::Peer(Peer::Self_),
                Value::Int(9),
                Value::Str("edited"),
            ],
        )
        .expect("serialize");
        let bytes = writer.written();
        assert_eq!(&bytes[4..8], &[0x00, 0x08, 0x00, 0x00]);
    }

    #[test]
    fn boxed_reply_to_matches_hand_written_send_reply() {
        let mut left = [0u8; 256];
        let mut right = [0u8; 256];
        let peer = Peer::User {
            user_id: 42,
            access_hash: 7,
        };
        let mut generic = Writer::new(&mut left);
        serialize(
            &mut generic,
            crate::generated::MESSAGES_SEND_MESSAGE,
            &[
                Value::Long(0), // ephemeral_receiver_bot_id
                Value::False,   // no_webpage
                Value::False,   // silent
                Value::False,   // background
                Value::False,   // clear_draft
                Value::False,   // noforwards
                Value::False,   // update_stickersets_order
                Value::False,   // invert_media
                Value::False,   // allow_paid_floodskip
                Value::Peer(peer),
                Value::Boxed(crate::generated::INPUT_REPLY_TO_MESSAGE, &[Value::Int(77)]),
                Value::Str("hello"),
                Value::Long(123),
            ],
        )
        .expect("serialize");
        let mut typed = Writer::new(&mut right);
        crate::api::write_send_text_reply(
            &mut typed,
            crate::api::InputPeer::from(peer),
            "hello",
            123,
            crate::api::SendMessageOptions::EMPTY,
            Some(77),
        )
        .expect("typed");
        assert_eq!(generic.written(), typed.written());
        assert_eq!(&typed.written()[..4], &[0x62, 0x8f, 0xf4, 0xfe]);
    }
}

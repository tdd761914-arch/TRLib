//! Borrowed parsers for MTProto service objects and message-carrying updates.

use crate::config::GatewayConfig;
use crate::error::{Error, ErrorKind, Result, narrow};
use crate::tl::{ConstructorId, Cursor, RawObject, TlBytes};

pub use crate::generated::{
    BAD_MSG_NOTIFICATION, BAD_SERVER_SALT, GZIP_PACKED, MSG_CONTAINER, MSGS_ACK,
    NEW_SESSION_CREATED, PONG, RPC_RESULT,
};

/// Current Telegram API constructors carrying a `Message` followed by PTS data.
pub const UPDATE_NEW_MESSAGE: ConstructorId = ConstructorId::new(0x1f2b_0afd);
/// Current Telegram API `updateNewChannelMessage` constructor.
pub const UPDATE_NEW_CHANNEL_MESSAGE: ConstructorId = ConstructorId::new(0x62ba_04d9);
/// Current Telegram API `updateEditMessage` constructor.
pub const UPDATE_EDIT_MESSAGE: ConstructorId = ConstructorId::new(0xe403_70a3);
/// Current Telegram API `updateEditChannelMessage` constructor.
pub const UPDATE_EDIT_CHANNEL_MESSAGE: ConstructorId = ConstructorId::new(0x1b3f_4df7);

/// Current Telegram API `messageEmpty` constructor.
pub const MESSAGE_EMPTY: ConstructorId = ConstructorId::new(0x90a6_ca84);
/// Current Telegram API `message` constructor.
pub const MESSAGE: ConstructorId = ConstructorId::new(0x7600_b9d3);
/// Current Telegram API `messageService` constructor.
pub const MESSAGE_SERVICE: ConstructorId = ConstructorId::new(0x7a80_0e0a);

/// One message nested in an MTProto container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerMessage<'a> {
    /// Nested message identifier.
    pub message_id: u64,
    /// Nested sequence number.
    pub sequence_number: u32,
    /// Exact boxed TL body.
    pub body: &'a [u8],
}

/// Cursor over a length-delimited `msg_container`.
#[derive(Clone, Copy, Debug)]
pub struct MessageContainer<'a> {
    cursor: Cursor<'a>,
    remaining: u16,
}

impl<'a> MessageContainer<'a> {
    /// Returns the number of nested messages not yet read.
    #[inline]
    pub const fn remaining(&self) -> u16 {
        self.remaining
    }

    /// Reads the next nested message without copying its TL body.
    pub fn next_message(&mut self) -> Option<Result<ContainerMessage<'a>>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let message_id = match self.cursor.read_u64() {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let sequence_number = match self.cursor.read_u32() {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let body_length = match self.cursor.read_u32() {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        if body_length & 3 != 0 {
            return Some(Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(self.cursor.position().saturating_sub(4)),
                body_length,
            )));
        }
        let body = match self.cursor.take(body_length as usize) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        Some(Ok(ContainerMessage {
            message_id,
            sequence_number,
            body,
        }))
    }

    /// Checks that all declared entries and bytes were consumed.
    pub fn finish(self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(self.cursor.position()),
                u32::from(self.remaining),
            ));
        }
        self.cursor.finish()
    }
}

/// Borrowed vector of little-endian 64-bit values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongVector<'a> {
    bytes: &'a [u8],
    length: u32,
}

impl<'a> LongVector<'a> {
    /// Number of elements.
    #[inline]
    pub const fn len(self) -> u32 {
        self.length
    }

    /// Returns true for an empty vector.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }

    /// Decodes an element by index.
    pub fn get(self, index: u32) -> Option<i64> {
        if index >= self.length {
            return None;
        }
        let start = index as usize * 8;
        let bytes: &[u8; 8] = self.bytes.get(start..start + 8)?.try_into().ok()?;
        Some(i64::from_le_bytes(*bytes))
    }
}

/// Parsed MTProto service object.
#[derive(Clone, Copy, Debug)]
pub enum ServiceObject<'a> {
    /// An RPC result whose boxed result occupies the rest of the message.
    RpcResult {
        /// Request message identifier.
        request_message_id: u64,
        /// Borrowed boxed result.
        result: RawObject<'a>,
    },
    /// A message container.
    Container(MessageContainer<'a>),
    /// A gzip-compressed boxed object; decompression is intentionally external.
    GzipPacked(TlBytes<'a>),
    /// Acknowledged message identifiers.
    MessagesAck(LongVector<'a>),
    /// Ping response.
    Pong {
        /// Message identifier containing the ping.
        message_id: u64,
        /// Caller-supplied ping identifier.
        ping_id: u64,
    },
    /// A new MTProto session notification.
    NewSession {
        /// First message identifier processed in the session.
        first_message_id: u64,
        /// Unique session notification identifier.
        unique_id: u64,
        /// New server salt.
        server_salt: u64,
    },
    /// Bad message notification.
    BadMessage {
        /// Rejected message identifier.
        bad_message_id: u64,
        /// Rejected sequence number.
        bad_sequence_number: u32,
        /// Telegram error code.
        error_code: u32,
    },
    /// Incorrect server salt notification.
    BadServerSalt {
        /// Rejected message identifier.
        bad_message_id: u64,
        /// Rejected sequence number.
        bad_sequence_number: u32,
        /// Telegram error code.
        error_code: u32,
        /// Replacement server salt.
        new_server_salt: u64,
    },
    /// Object left for an API-layer dispatcher.
    Api(RawObject<'a>),
}

/// Parses known service objects directly from an exact MTProto message body.
pub fn parse_service<'a>(input: &'a [u8], config: GatewayConfig) -> Result<ServiceObject<'a>> {
    let mut cursor = Cursor::new(input);
    let id = cursor.read_constructor()?;
    let object = match id {
        RPC_RESULT => {
            let request_message_id = cursor.read_u64()?;
            let result = RawObject::from_exact(cursor.remaining())?;
            ServiceObject::RpcResult {
                request_message_id,
                result,
            }
        }
        MSG_CONTAINER => {
            let count = cursor.read_u32()?;
            if count > u32::from(config.max_container_messages) {
                return Err(Error::new(ErrorKind::LimitExceeded, 4, count));
            }
            ServiceObject::Container(MessageContainer {
                cursor,
                remaining: count as u16,
            })
        }
        GZIP_PACKED => {
            let bytes = cursor.read_bytes()?;
            cursor.finish()?;
            ServiceObject::GzipPacked(bytes)
        }
        MSGS_ACK => {
            let count = cursor.read_vector_len(u32::from(config.max_vector_elements))?;
            let byte_length = (count as usize).checked_mul(8).ok_or_else(|| {
                Error::new(ErrorKind::InvalidLength, narrow(cursor.position()), count)
            })?;
            let bytes = cursor.take(byte_length)?;
            cursor.finish()?;
            ServiceObject::MessagesAck(LongVector {
                bytes,
                length: count,
            })
        }
        PONG => {
            let message_id = cursor.read_u64()?;
            let ping_id = cursor.read_u64()?;
            cursor.finish()?;
            ServiceObject::Pong {
                message_id,
                ping_id,
            }
        }
        NEW_SESSION_CREATED => {
            let first_message_id = cursor.read_u64()?;
            let unique_id = cursor.read_u64()?;
            let server_salt = cursor.read_u64()?;
            cursor.finish()?;
            ServiceObject::NewSession {
                first_message_id,
                unique_id,
                server_salt,
            }
        }
        BAD_MSG_NOTIFICATION => {
            let bad_message_id = cursor.read_u64()?;
            let bad_sequence_number = cursor.read_u32()?;
            let error_code = cursor.read_u32()?;
            cursor.finish()?;
            ServiceObject::BadMessage {
                bad_message_id,
                bad_sequence_number,
                error_code,
            }
        }
        BAD_SERVER_SALT => {
            let bad_message_id = cursor.read_u64()?;
            let bad_sequence_number = cursor.read_u32()?;
            let error_code = cursor.read_u32()?;
            let new_server_salt = cursor.read_u64()?;
            cursor.finish()?;
            ServiceObject::BadServerSalt {
                bad_message_id,
                bad_sequence_number,
                error_code,
                new_server_salt,
            }
        }
        _ => ServiceObject::Api(RawObject {
            id,
            body: cursor.remaining(),
        }),
    };
    Ok(object)
}

/// Kind of Telegram API `Message` nested in an update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Deleted/unavailable message placeholder.
    Empty,
    /// Ordinary cloud message.
    Message,
    /// Service action message.
    Service,
    /// Layer-specific constructor unknown to this build.
    Unknown(ConstructorId),
}

impl MessageKind {
    /// Classifies a message constructor without parsing its fields.
    pub const fn from_constructor(id: ConstructorId) -> Self {
        match id {
            MESSAGE_EMPTY => Self::Empty,
            MESSAGE => Self::Message,
            MESSAGE_SERVICE => Self::Service,
            other => Self::Unknown(other),
        }
    }
}

/// Zero-copy view of `update{New,Edit}{Channel,}Message`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageUpdate<'a> {
    /// Update constructor, preserving new/edit and channel distinctions.
    pub update_constructor: ConstructorId,
    /// Entire nested boxed `Message` object.
    pub message: RawObject<'a>,
    /// Message constructor classification.
    pub message_kind: MessageKind,
    /// PTS value.
    pub pts: i32,
    /// Number of PTS events.
    pub pts_count: i32,
}

/// Parses a message-carrying update by using its fixed eight-byte tail as the
/// nested message boundary. The nested `Message` remains borrowed and opaque.
pub fn parse_message_update(input: &[u8]) -> Result<MessageUpdate<'_>> {
    let mut cursor = Cursor::new(input);
    let update_constructor = cursor.read_constructor()?;
    if !matches!(
        update_constructor,
        UPDATE_NEW_MESSAGE
            | UPDATE_NEW_CHANNEL_MESSAGE
            | UPDATE_EDIT_MESSAGE
            | UPDATE_EDIT_CHANNEL_MESSAGE
    ) {
        return Err(Error::new(
            ErrorKind::UnexpectedConstructor,
            0,
            update_constructor.get(),
        ));
    }
    let remainder = cursor.remaining();
    if remainder.len() < 12 {
        return Err(Error::new(
            ErrorKind::NeedMore,
            4,
            narrow(12usize.saturating_sub(remainder.len())),
        ));
    }
    let split = remainder.len() - 8;
    let message = RawObject::from_exact(&remainder[..split])?;
    let mut tail = Cursor::new(&remainder[split..]);
    let pts = tail.read_i32()?;
    let pts_count = tail.read_i32()?;
    tail.finish()?;
    Ok(MessageUpdate {
        update_constructor,
        message_kind: MessageKind::from_constructor(message.id),
        message,
        pts,
        pts_count,
    })
}

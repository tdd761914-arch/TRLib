//! Allocation-free Telegram API bindings and direct convenience writers.
//!
//! The constructor metadata is generated from the vendored full
//! `TGScheme/Schema` snapshot. Applications can invoke any enabled schema
//! method through [`RawMethod`], while the high-frequency login, account and
//! text-message calls below have direct writers.

use crate::error::Result;
#[cfg(feature = "auth")]
use crate::error::{Error, ErrorKind, narrow};
#[cfg(feature = "api-users")]
use crate::generated::USERS_GET_FULL_USER;
#[cfg(feature = "auth")]
use crate::generated::{
    ACCOUNT_GET_PASSWORD, AUTH_AUTHORIZATION, AUTH_AUTHORIZATION_SIGN_UP_REQUIRED,
    AUTH_CHECK_PASSWORD, AUTH_CODE_TYPE_CALL, AUTH_CODE_TYPE_FLASH_CALL,
    AUTH_CODE_TYPE_FRAGMENT_SMS, AUTH_CODE_TYPE_MISSED_CALL, AUTH_CODE_TYPE_SMS, AUTH_LOG_OUT,
    AUTH_SEND_CODE, AUTH_SENT_CODE, AUTH_SENT_CODE_PAYMENT_REQUIRED, AUTH_SENT_CODE_SUCCESS,
    AUTH_SENT_CODE_TYPE_APP, AUTH_SENT_CODE_TYPE_CALL, AUTH_SENT_CODE_TYPE_EMAIL_CODE,
    AUTH_SENT_CODE_TYPE_FIREBASE_SMS, AUTH_SENT_CODE_TYPE_FLASH_CALL,
    AUTH_SENT_CODE_TYPE_FRAGMENT_SMS, AUTH_SENT_CODE_TYPE_MISSED_CALL,
    AUTH_SENT_CODE_TYPE_SET_UP_EMAIL_REQUIRED, AUTH_SENT_CODE_TYPE_SMS,
    AUTH_SENT_CODE_TYPE_SMS_PHRASE, AUTH_SENT_CODE_TYPE_SMS_WORD, AUTH_SIGN_IN, AUTH_SIGN_UP,
    CODE_SETTINGS, INPUT_CHECK_PASSWORD_SRP,
};
use crate::generated::{
    INIT_CONNECTION, INPUT_PEER_CHANNEL, INPUT_PEER_CHAT, INPUT_PEER_SELF, INPUT_PEER_USER,
    INPUT_USER_SELF, INVOKE_AFTER_MSG, INVOKE_WITH_LAYER, INVOKE_WITHOUT_UPDATES, RPC_ERROR,
};
#[cfg(feature = "api-messages")]
use crate::generated::{
    INPUT_MESSAGE_ID, INPUT_REPLY_TO_MESSAGE, MESSAGES_DELETE_MESSAGES, MESSAGES_EDIT_MESSAGE,
    MESSAGES_GET_HISTORY, MESSAGES_GET_MESSAGES, MESSAGES_READ_HISTORY, MESSAGES_SEND_MESSAGE,
};
#[cfg(feature = "api-updates")]
use crate::generated::{UPDATES_GET_STATE, UPDATES_STATE};
use crate::tl::{ConstructorId, Cursor, TlString, VECTOR, Writer};
#[cfg(feature = "auth")]
use crate::tl::{RawObject, TlBytes};

/// Telegram API layer represented by the vendored schema snapshot.
pub const TELEGRAM_API_LAYER: i32 = 229;

/// Pinned upstream schema revision used to select the bindings.
pub const TGSCHEME_SCHEMA_REVISION: &str = "5e961c4673acfc5b921dd18ffdd5a02eda0e8143";

/// Stable descriptions of the direct method writers linked in this build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct KnownMethod {
    /// TL method constructor identifier.
    pub id: ConstructorId,
    /// Fully-qualified method name from the schema.
    pub name: &'static str,
}

/// Directly supported typed methods.
pub const KNOWN_METHODS: &[KnownMethod] = &[
    #[cfg(feature = "api-users")]
    KnownMethod {
        id: USERS_GET_FULL_USER,
        name: "users.getFullUser",
    },
    #[cfg(feature = "api-messages")]
    KnownMethod {
        id: MESSAGES_GET_HISTORY,
        name: "messages.getHistory",
    },
    #[cfg(feature = "api-messages")]
    KnownMethod {
        id: MESSAGES_GET_MESSAGES,
        name: "messages.getMessages",
    },
    #[cfg(feature = "api-messages")]
    KnownMethod {
        id: MESSAGES_READ_HISTORY,
        name: "messages.readHistory",
    },
    #[cfg(feature = "api-messages")]
    KnownMethod {
        id: MESSAGES_DELETE_MESSAGES,
        name: "messages.deleteMessages",
    },
    #[cfg(feature = "api-messages")]
    KnownMethod {
        id: MESSAGES_EDIT_MESSAGE,
        name: "messages.editMessage",
    },
    #[cfg(feature = "api-messages")]
    KnownMethod {
        id: MESSAGES_SEND_MESSAGE,
        name: "messages.sendMessage",
    },
    #[cfg(feature = "api-updates")]
    KnownMethod {
        id: UPDATES_GET_STATE,
        name: "updates.getState",
    },
];

/// Direct login-related methods linked only with the `auth` feature.
#[cfg(feature = "auth")]
pub const AUTH_KNOWN_METHODS: &[KnownMethod] = &[
    KnownMethod {
        id: AUTH_SEND_CODE,
        name: "auth.sendCode",
    },
    KnownMethod {
        id: AUTH_SIGN_IN,
        name: "auth.signIn",
    },
    KnownMethod {
        id: AUTH_SIGN_UP,
        name: "auth.signUp",
    },
    KnownMethod {
        id: AUTH_CHECK_PASSWORD,
        name: "auth.checkPassword",
    },
    KnownMethod {
        id: ACCOUNT_GET_PASSWORD,
        name: "account.getPassword",
    },
    KnownMethod {
        id: AUTH_LOG_OUT,
        name: "auth.logOut",
    },
];

/// Authentication and `initConnection` metadata supplied by the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ApiContext<'a> {
    /// API layer to send through `invokeWithLayer`.
    pub layer: i32,
    /// Telegram API identifier registered for the embedding application.
    pub api_id: i32,
    /// Telegram API hash registered for the embedding application.
    pub api_hash: &'a str,
    /// Device model reported to Telegram.
    pub device_model: &'a str,
    /// Host operating-system version reported to Telegram.
    pub system_version: &'a str,
    /// Embedding application version reported to Telegram.
    pub app_version: &'a str,
    /// BCP-47 system language code reported to Telegram.
    pub system_lang_code: &'a str,
    /// Telegram language-pack name, normally an empty string.
    pub lang_pack: &'a str,
    /// BCP-47 UI language code reported to Telegram.
    pub lang_code: &'a str,
}

impl<'a> ApiContext<'a> {
    /// Creates context using the layer represented by this crate's schema.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        api_id: i32,
        api_hash: &'a str,
        device_model: &'a str,
        system_version: &'a str,
        app_version: &'a str,
        system_lang_code: &'a str,
        lang_pack: &'a str,
        lang_code: &'a str,
    ) -> Self {
        Self {
            layer: TELEGRAM_API_LAYER,
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            system_lang_code,
            lang_pack,
            lang_code,
        }
    }
}

/// A raw schema method whose field bytes are already serialized by the caller.
///
/// This is the escape hatch for every non-selected declaration in the upstream
/// schema.  It writes exactly a constructor prefix followed by `fields` and
/// never owns or copies the field representation before serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RawMethod<'a> {
    /// Method constructor identifier.
    pub id: ConstructorId,
    /// Encoded fields after the constructor prefix.
    pub fields: &'a [u8],
}

impl<'a> RawMethod<'a> {
    /// Creates a raw schema method from pre-serialized field bytes.
    #[inline]
    pub const fn new(id: ConstructorId, fields: &'a [u8]) -> Self {
        Self { id, fields }
    }

    /// Writes the complete boxed TL method to a caller-owned buffer.
    #[inline]
    pub fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.write_constructor(self.id)?;
        writer.write_all(self.fields)
    }
}

/// An `InputPeer` accepted by the direct history and text-message writers.
#[cfg(feature = "api-messages")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputPeer {
    /// The authenticated account itself.
    SelfPeer,
    /// A known user and its access hash.
    User {
        /// User identifier.
        user_id: i64,
        /// Server-provided access hash.
        access_hash: i64,
    },
    /// A known channel or supergroup and its access hash.
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

#[cfg(feature = "api-messages")]
impl From<crate::tl::schema::Peer> for InputPeer {
    fn from(peer: crate::tl::schema::Peer) -> Self {
        match peer {
            crate::tl::schema::Peer::Self_ => Self::SelfPeer,
            crate::tl::schema::Peer::User {
                user_id,
                access_hash,
            } => Self::User {
                user_id,
                access_hash,
            },
            crate::tl::schema::Peer::Channel {
                channel_id,
                access_hash,
            } => Self::Channel {
                channel_id,
                access_hash,
            },
            crate::tl::schema::Peer::Chat { chat_id } => Self::Chat { chat_id },
        }
    }
}

#[cfg(feature = "api-messages")]
impl From<InputPeer> for crate::tl::schema::Peer {
    fn from(peer: InputPeer) -> Self {
        match peer {
            InputPeer::SelfPeer => Self::Self_,
            InputPeer::User {
                user_id,
                access_hash,
            } => Self::User {
                user_id,
                access_hash,
            },
            InputPeer::Channel {
                channel_id,
                access_hash,
            } => Self::Channel {
                channel_id,
                access_hash,
            },
            InputPeer::Chat { chat_id } => Self::Chat { chat_id },
        }
    }
}

#[cfg(feature = "api-messages")]
impl InputPeer {
    /// Writes the boxed `InputPeer` directly into a TL writer.
    pub fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::SelfPeer => writer.write_constructor(INPUT_PEER_SELF),
            Self::User {
                user_id,
                access_hash,
            } => {
                writer.write_constructor(INPUT_PEER_USER)?;
                writer.write_i64(user_id)?;
                writer.write_i64(access_hash)
            }
            Self::Channel {
                channel_id,
                access_hash,
            } => {
                writer.write_constructor(INPUT_PEER_CHANNEL)?;
                writer.write_i64(channel_id)?;
                writer.write_i64(access_hash)
            }
            Self::Chat { chat_id } => {
                writer.write_constructor(INPUT_PEER_CHAT)?;
                writer.write_i64(chat_id)
            }
        }
    }
}

/// Writes `users.getFullUser(inputUserSelf)` for a `getMe`-style operation.
#[cfg(feature = "api-users")]
#[inline]
pub fn write_get_me(writer: &mut Writer<'_>) -> Result<()> {
    writer.write_constructor(USERS_GET_FULL_USER)?;
    writer.write_constructor(INPUT_USER_SELF)
}

/// Writes `updates.getState`.
#[cfg(feature = "api-updates")]
#[inline]
pub fn write_updates_get_state(writer: &mut Writer<'_>) -> Result<()> {
    writer.write_constructor(UPDATES_GET_STATE)
}

/// Writes `messages.getHistory` with a direct `InputPeer`.
#[cfg(feature = "api-messages")]
#[allow(clippy::too_many_arguments)]
pub fn write_get_history(
    writer: &mut Writer<'_>,
    peer: InputPeer,
    offset_id: i32,
    offset_date: i32,
    add_offset: i32,
    limit: i32,
    max_id: i32,
    min_id: i32,
    hash: i64,
) -> Result<()> {
    writer.write_constructor(MESSAGES_GET_HISTORY)?;
    peer.write(writer)?;
    writer.write_i32(offset_id)?;
    writer.write_i32(offset_date)?;
    writer.write_i32(add_offset)?;
    writer.write_i32(limit)?;
    writer.write_i32(max_id)?;
    writer.write_i32(min_id)?;
    writer.write_i64(hash)
}

/// Writes `messages.getMessages` for a list of message identifiers.
///
/// Each identifier is boxed as `inputMessageID`, so no chat identifier is
/// required; the server resolves the target from the message ids themselves.
#[cfg(feature = "api-messages")]
pub fn write_get_messages(writer: &mut Writer<'_>, ids: &[i32]) -> Result<()> {
    writer.write_constructor(MESSAGES_GET_MESSAGES)?;
    writer.write_constructor(VECTOR)?;
    writer.write_i32(ids.len() as i32)?;
    for id in ids {
        writer.write_constructor(INPUT_MESSAGE_ID)?;
        writer.write_i32(*id)?;
    }
    Ok(())
}

/// Writes `messages.readHistory`, marking every message up to `max_id` read.
#[cfg(feature = "api-messages")]
pub fn write_read_history(writer: &mut Writer<'_>, peer: InputPeer, max_id: i32) -> Result<()> {
    writer.write_constructor(MESSAGES_READ_HISTORY)?;
    peer.write(writer)?;
    writer.write_i32(max_id)
}

/// Writes `messages.deleteMessages` for a list of message identifiers.
///
/// `revoke` controls the `revoke` flag: true deletes for both sides where
/// Telegram permits it, false removes the messages only for the account.
#[cfg(feature = "api-messages")]
pub fn write_delete_messages(writer: &mut Writer<'_>, ids: &[i32], revoke: bool) -> Result<()> {
    writer.write_constructor(MESSAGES_DELETE_MESSAGES)?;
    writer.write_u32(u32::from(revoke))?;
    writer.write_constructor(VECTOR)?;
    writer.write_i32(ids.len() as i32)?;
    for id in ids {
        writer.write_i32(*id)?;
    }
    Ok(())
}

/// Writes `messages.editMessage` replacing the message text.
#[cfg(feature = "api-messages")]
pub fn write_edit_message_text(
    writer: &mut Writer<'_>,
    peer: InputPeer,
    message_id: i32,
    text: &str,
    no_webpage: bool,
    invert_media: bool,
) -> Result<()> {
    let mut flags = 1u32 << 11;
    if no_webpage {
        flags |= 1 << 1;
    }
    if invert_media {
        flags |= 1 << 16;
    }
    writer.write_constructor(MESSAGES_EDIT_MESSAGE)?;
    writer.write_u32(flags)?;
    peer.write(writer)?;
    writer.write_i32(message_id)?;
    writer.write_string(text)
}

/// Boolean-only `messages.sendMessage` flags that have no trailing payload.
#[cfg(feature = "api-messages")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct SendMessageOptions(u32);

#[cfg(feature = "api-messages")]
impl SendMessageOptions {
    /// No optional behavior.
    pub const EMPTY: Self = Self(0);

    /// Disables web-page previews.
    #[must_use]
    pub const fn no_webpage(self) -> Self {
        Self(self.0 | (1 << 1))
    }

    /// Sends silently.
    #[must_use]
    pub const fn silent(self) -> Self {
        Self(self.0 | (1 << 5))
    }

    /// Sends in the background.
    #[must_use]
    pub const fn background(self) -> Self {
        Self(self.0 | (1 << 6))
    }

    /// Clears the server-side draft.
    #[must_use]
    pub const fn clear_draft(self) -> Self {
        Self(self.0 | (1 << 7))
    }

    /// Prevents forwarding when Telegram permits it.
    #[must_use]
    pub const fn noforwards(self) -> Self {
        Self(self.0 | (1 << 14))
    }

    /// Protects the message content from forwarding when Telegram permits it.
    #[must_use]
    pub const fn protect_content(self) -> Self {
        self.noforwards()
    }

    /// Requests sticker-set-order synchronization.
    #[must_use]
    pub const fn update_stickersets_order(self) -> Self {
        Self(self.0 | (1 << 15))
    }

    /// Mirrors TDLib's `update_order_of_installed_sticker_sets` option.
    #[must_use]
    pub const fn update_sticker_order(self) -> Self {
        self.update_stickersets_order()
    }

    /// Inverts attached media order when Telegram permits it.
    #[must_use]
    pub const fn invert_media(self) -> Self {
        Self(self.0 | (1 << 16))
    }

    /// Allows a paid floodskip when Telegram permits it.
    #[must_use]
    pub const fn allow_paid_floodskip(self) -> Self {
        Self(self.0 | (1 << 19))
    }

    /// Allows a paid broadcast when Telegram permits it.
    #[must_use]
    pub const fn allow_paid_broadcast(self) -> Self {
        self.allow_paid_floodskip()
    }
}

/// Writes `messages.sendMessage` without extra payloads.
///
/// Replies, entities, paid stars and other payload-bearing optional fields are
/// available through [`write_send_text_reply`] or [`RawMethod`]; accepting only
/// flags that require no extra serialized objects makes it impossible to emit
/// an invalid flag/body pair.
#[cfg(feature = "api-messages")]
pub fn write_send_text(
    writer: &mut Writer<'_>,
    peer: InputPeer,
    text: &str,
    random_id: i64,
    options: SendMessageOptions,
) -> Result<()> {
    write_send_text_reply(writer, peer, text, random_id, options, None)
}

/// Writes `messages.sendMessage` with an optional reply.
///
/// `reply_to_message_id` selects `inputReplyToMessage` in the `reply_to` field;
/// the flags bit is set exactly when the reply object is written.
#[cfg(feature = "api-messages")]
pub fn write_send_text_reply(
    writer: &mut Writer<'_>,
    peer: InputPeer,
    text: &str,
    random_id: i64,
    options: SendMessageOptions,
    reply_to_message_id: Option<i32>,
) -> Result<()> {
    let mut flags = options.0;
    writer.write_constructor(MESSAGES_SEND_MESSAGE)?;
    writer.write_i64(0)?;
    if reply_to_message_id.is_some() {
        flags |= 1 << 0;
    }
    writer.write_u32(flags)?;
    peer.write(writer)?;
    if let Some(reply_to_message_id) = reply_to_message_id {
        writer.write_constructor(INPUT_REPLY_TO_MESSAGE)?;
        writer.write_u32(0)?;
        writer.write_i32(reply_to_message_id)?;
    }
    writer.write_string(text)?;
    writer.write_i64(random_id)
}

/// Boolean-only `CodeSettings` flags supported without an auxiliary vector.
#[cfg(feature = "auth")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct CodeSettings(u32);

#[cfg(feature = "auth")]
impl CodeSettings {
    /// Empty settings: no optional code-delivery flags are requested.
    pub const EMPTY: Self = Self(0);

    /// Requests a flash-call when Telegram permits it.
    #[must_use]
    pub const fn allow_flashcall(self) -> Self {
        Self(self.0 | (1 << 0))
    }

    /// Declares that this phone number is currently active on the device.
    #[must_use]
    pub const fn current_number(self) -> Self {
        Self(self.0 | (1 << 1))
    }

    /// Requests application-hash delivery support.
    #[must_use]
    pub const fn allow_app_hash(self) -> Self {
        Self(self.0 | (1 << 4))
    }

    /// Requests missed-call delivery support.
    #[must_use]
    pub const fn allow_missed_call(self) -> Self {
        Self(self.0 | (1 << 5))
    }

    /// Requests Firebase delivery support.
    #[must_use]
    pub const fn allow_firebase(self) -> Self {
        Self(self.0 | (1 << 7))
    }

    /// Declares the number as unknown to the current device.
    #[must_use]
    pub const fn unknown_number(self) -> Self {
        Self(self.0 | (1 << 9))
    }

    /// Returns the serialized flag word.
    #[inline]
    pub const fn flags(self) -> u32 {
        self.0
    }

    /// Writes a boxed `CodeSettings` object.
    pub fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.write_constructor(CODE_SETTINGS)?;
        writer.write_u32(self.0)
    }
}

/// Writes the `invokeWithLayer` and `initConnection` prefixes and fields.
///
/// The caller must immediately append exactly one boxed query method.  Keeping
/// this as a prefix writer avoids an intermediate request buffer and avoids a
/// generic closure monomorphization for each request type.
pub fn write_init_connection_prefix(
    writer: &mut Writer<'_>,
    context: ApiContext<'_>,
) -> Result<()> {
    writer.write_constructor(INVOKE_WITH_LAYER)?;
    writer.write_i32(context.layer)?;
    writer.write_constructor(INIT_CONNECTION)?;
    writer.write_u32(0)?;
    writer.write_i32(context.api_id)?;
    writer.write_string(context.device_model)?;
    writer.write_string(context.system_version)?;
    writer.write_string(context.app_version)?;
    writer.write_string(context.system_lang_code)?;
    writer.write_string(context.lang_pack)?;
    writer.write_string(context.lang_code)
}

/// Writes an `invokeAfterMsg` prefix before a caller-provided boxed query.
pub fn write_invoke_after_msg_prefix(writer: &mut Writer<'_>, message_id: i64) -> Result<()> {
    writer.write_constructor(INVOKE_AFTER_MSG)?;
    writer.write_i64(message_id)
}

/// Writes an `invokeWithoutUpdates` prefix before a caller-provided boxed query.
pub fn write_invoke_without_updates_prefix(writer: &mut Writer<'_>) -> Result<()> {
    writer.write_constructor(INVOKE_WITHOUT_UPDATES)
}

/// Writes `auth.sendCode` with the selected API context and code settings.
#[cfg(feature = "auth")]
pub fn write_send_code(
    writer: &mut Writer<'_>,
    context: ApiContext<'_>,
    phone_number: &str,
    settings: CodeSettings,
) -> Result<()> {
    writer.write_constructor(AUTH_SEND_CODE)?;
    writer.write_string(phone_number)?;
    writer.write_i32(context.api_id)?;
    writer.write_string(context.api_hash)?;
    settings.write(writer)
}

/// Writes `auth.signIn` with a phone code. E-mail verification uses
/// [`RawMethod`] until a caller opts into a typed convenience writer.
#[cfg(feature = "auth")]
pub fn write_sign_in(
    writer: &mut Writer<'_>,
    phone_number: &str,
    phone_code_hash: &str,
    phone_code: &str,
) -> Result<()> {
    writer.write_constructor(AUTH_SIGN_IN)?;
    writer.write_u32(1)?;
    writer.write_string(phone_number)?;
    writer.write_string(phone_code_hash)?;
    writer.write_string(phone_code)
}

/// Writes `auth.signUp` after the server asks for registration.
#[cfg(feature = "auth")]
pub fn write_sign_up(
    writer: &mut Writer<'_>,
    phone_number: &str,
    phone_code_hash: &str,
    first_name: &str,
    last_name: &str,
    no_joined_notifications: bool,
) -> Result<()> {
    writer.write_constructor(AUTH_SIGN_UP)?;
    writer.write_u32(u32::from(no_joined_notifications))?;
    writer.write_string(phone_number)?;
    writer.write_string(phone_code_hash)?;
    writer.write_string(first_name)?;
    writer.write_string(last_name)
}

/// Writes `account.getPassword` for a two-step-verification challenge.
#[cfg(feature = "auth")]
#[inline]
pub fn write_get_password(writer: &mut Writer<'_>) -> Result<()> {
    writer.write_constructor(ACCOUNT_GET_PASSWORD)
}

/// Writes `auth.checkPassword` from host-computed SRP values.
///
/// Telegram's SRP password computation is intentionally host-provided: it
/// avoids pulling a big-integer implementation into every TRLib binary.  The
/// returned `account.Password` object can be passed to a specialized SRP
/// module or another audited implementation to produce `srp_id`, `A` and `M1`.
#[cfg(feature = "auth")]
pub fn write_check_password(
    writer: &mut Writer<'_>,
    srp_id: i64,
    a: &[u8],
    m1: &[u8],
) -> Result<()> {
    writer.write_constructor(AUTH_CHECK_PASSWORD)?;
    writer.write_constructor(INPUT_CHECK_PASSWORD_SRP)?;
    writer.write_i64(srp_id)?;
    writer.write_bytes(a)?;
    writer.write_bytes(m1)
}

/// Writes `auth.logOut`.
#[cfg(feature = "auth")]
#[inline]
pub fn write_log_out(writer: &mut Writer<'_>) -> Result<()> {
    writer.write_constructor(AUTH_LOG_OUT)
}

/// Telegram RPC error borrowed directly from a result body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RpcError<'a> {
    /// Numeric Telegram RPC error code.
    pub code: i32,
    /// Server-supplied symbolic error text.
    pub message: TlString<'a>,
}

impl<'a> RpcError<'a> {
    /// Parses an exact boxed `rpc_error` body.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(input);
        cursor.expect_constructor(RPC_ERROR)?;
        let code = cursor.read_i32()?;
        let message = cursor.read_string()?;
        cursor.finish()?;
        Ok(Self { code, message })
    }

    /// Returns the DC target encoded in a Telegram `*_MIGRATE_<dc>` error.
    pub fn migration_dc(self) -> Option<i32> {
        let message = self.message.as_str();
        for prefix in ["PHONE_MIGRATE_", "NETWORK_MIGRATE_", "USER_MIGRATE_"] {
            if let Some(suffix) = message.strip_prefix(prefix) {
                return parse_positive_i32(suffix);
            }
        }
        None
    }
}

/// One code-delivery mechanism returned by `auth.sentCode`.
#[cfg(feature = "auth")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentCodeDelivery<'a> {
    /// The code is shown in an already-authorized Telegram application.
    App {
        /// Expected code length.
        length: i32,
    },
    /// The code is delivered by SMS.
    Sms {
        /// Expected code length.
        length: i32,
    },
    /// The code is delivered by a telephone call.
    Call {
        /// Expected code length.
        length: i32,
    },
    /// The code is embedded in a flash-call pattern.
    FlashCall {
        /// Expected dialed-number pattern.
        pattern: TlString<'a>,
    },
    /// The code is inferred from a missed call.
    MissedCall {
        /// Expected caller-number prefix.
        prefix: TlString<'a>,
        /// Expected code length.
        length: i32,
    },
    /// The code is delivered by e-mail.
    Email {
        /// Masked e-mail pattern.
        pattern: TlString<'a>,
        /// Expected code length.
        length: i32,
    },
    /// Telegram requires an e-mail address to be set up first.
    SetUpEmailRequired,
    /// The code is delivered through Telegram Fragment SMS.
    FragmentSms {
        /// Fragment delivery URL.
        url: TlString<'a>,
        /// Expected code length.
        length: i32,
    },
    /// The code is delivered through Firebase.
    FirebaseSms {
        /// Expected code length.
        length: i32,
    },
    /// SMS with a suggested leading word.
    SmsWord {
        /// Optional suggested leading word.
        beginning: Option<TlString<'a>>,
    },
    /// SMS with a suggested leading phrase.
    SmsPhrase {
        /// Optional suggested leading phrase.
        beginning: Option<TlString<'a>>,
    },
}

/// Zero-copy result of `auth.sentCode`.
#[cfg(feature = "auth")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentCode<'a> {
    /// The delivery mechanism selected by Telegram.
    pub delivery: SentCodeDelivery<'a>,
    /// Opaque token required by `auth.signIn` or `auth.signUp`.
    pub phone_code_hash: TlString<'a>,
    /// Optional fallback code-delivery constructor.
    pub next_type: Option<ConstructorId>,
    /// Optional timeout in seconds.
    pub timeout: Option<i32>,
}

/// Borrowed `auth.Authorization` result.
#[cfg(feature = "auth")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authorization<'a> {
    /// The account is authorized and its `User` object remains opaque.
    Authorized {
        /// Telegram's temporary-session allowance when supplied.
        tmp_sessions: Option<i32>,
        /// Server-provided automatic-relogin window when supplied.
        otherwise_relogin_days: Option<i32>,
        /// Optional token to retain for future authorization.
        future_auth_token: Option<TlBytes<'a>>,
        /// Exact nested `User` object.
        user: RawObject<'a>,
    },
    /// The code is valid but registration data is still required.
    SignUpRequired {
        /// Optional terms object, borrowed as an opaque tail object.
        terms_of_service: Option<RawObject<'a>>,
    },
}

/// Parsed login-related response, including a server RPC failure.
#[cfg(feature = "auth")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthResponse<'a> {
    /// Telegram asks the client to enter a code or complete another code flow.
    SentCode(SentCode<'a>),
    /// Telegram reports immediate authorization from a sent-code flow.
    Authorized(Authorization<'a>),
    /// Telegram requires a paid login flow.
    PaymentRequired {
        /// Token that identifies the phone-code flow.
        phone_code_hash: TlString<'a>,
        /// Required Premium period in days.
        premium_days: i32,
        /// Payment currency.
        currency: TlString<'a>,
        /// Payment amount in the smallest currency unit.
        amount: i64,
    },
    /// Telegram returned a standard `rpc_error`.
    RpcError(RpcError<'a>),
}

/// Parses an `auth.sendCode`, `auth.signIn`, `auth.signUp`, or password result.
#[cfg(feature = "auth")]
pub fn parse_auth_response(input: &[u8]) -> Result<AuthResponse<'_>> {
    let mut cursor = Cursor::new(input);
    let id = cursor.read_constructor()?;
    match id {
        AUTH_SENT_CODE => parse_sent_code_after_id(cursor).map(AuthResponse::SentCode),
        AUTH_SENT_CODE_SUCCESS => {
            let authorization = parse_authorization_cursor(&mut cursor)?;
            cursor.finish()?;
            Ok(AuthResponse::Authorized(authorization))
        }
        AUTH_SENT_CODE_PAYMENT_REQUIRED => {
            let _store_product = cursor.read_string()?;
            let phone_code_hash = cursor.read_string()?;
            let _support_email_address = cursor.read_string()?;
            let _support_email_subject = cursor.read_string()?;
            let premium_days = cursor.read_i32()?;
            let currency = cursor.read_string()?;
            let amount = cursor.read_i64()?;
            cursor.finish()?;
            Ok(AuthResponse::PaymentRequired {
                phone_code_hash,
                premium_days,
                currency,
                amount,
            })
        }
        AUTH_AUTHORIZATION | AUTH_AUTHORIZATION_SIGN_UP_REQUIRED => {
            let authorization = parse_authorization_after_id(id, &mut cursor)?;
            cursor.finish()?;
            Ok(AuthResponse::Authorized(authorization))
        }
        RPC_ERROR => RpcError::parse(input).map(AuthResponse::RpcError),
        _ => Err(Error::new(ErrorKind::UnexpectedConstructor, 0, id.get())),
    }
}

/// Fixed, borrowed `updates.State` values for update synchronization.
#[cfg(feature = "api-updates")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UpdatesState {
    /// Persistent timestamp sequence counter.
    pub pts: i32,
    /// Secret-chat sequence counter.
    pub qts: i32,
    /// Server date.
    pub date: i32,
    /// Global update sequence counter.
    pub seq: i32,
    /// Unread message count.
    pub unread_count: i32,
}

#[cfg(feature = "api-updates")]
impl UpdatesState {
    /// Parses an exact boxed `updates.state` response.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(input);
        cursor.expect_constructor(UPDATES_STATE)?;
        let state = Self {
            pts: cursor.read_i32()?,
            qts: cursor.read_i32()?,
            date: cursor.read_i32()?,
            seq: cursor.read_i32()?,
            unread_count: cursor.read_i32()?,
        };
        cursor.finish()?;
        Ok(state)
    }
}

#[cfg(feature = "auth")]
fn parse_sent_code_after_id<'a>(mut cursor: Cursor<'a>) -> Result<SentCode<'a>> {
    let flags = cursor.read_u32()?;
    let delivery = parse_sent_code_delivery(&mut cursor)?;
    let phone_code_hash = cursor.read_string()?;
    let next_type = if flags & (1 << 1) != 0 {
        let id = cursor.read_constructor()?;
        if matches!(
            id,
            AUTH_CODE_TYPE_SMS
                | AUTH_CODE_TYPE_CALL
                | AUTH_CODE_TYPE_FLASH_CALL
                | AUTH_CODE_TYPE_MISSED_CALL
                | AUTH_CODE_TYPE_FRAGMENT_SMS
        ) {
            Some(id)
        } else {
            return Err(Error::new(
                ErrorKind::UnexpectedConstructor,
                narrow(cursor.position().saturating_sub(4)),
                id.get(),
            ));
        }
    } else {
        None
    };
    let timeout = if flags & (1 << 2) != 0 {
        Some(cursor.read_i32()?)
    } else {
        None
    };
    cursor.finish()?;
    Ok(SentCode {
        delivery,
        phone_code_hash,
        next_type,
        timeout,
    })
}

#[cfg(feature = "auth")]
fn parse_sent_code_delivery<'a>(cursor: &mut Cursor<'a>) -> Result<SentCodeDelivery<'a>> {
    let at = cursor.position();
    let id = cursor.read_constructor()?;
    match id {
        AUTH_SENT_CODE_TYPE_APP => Ok(SentCodeDelivery::App {
            length: cursor.read_i32()?,
        }),
        AUTH_SENT_CODE_TYPE_SMS => Ok(SentCodeDelivery::Sms {
            length: cursor.read_i32()?,
        }),
        AUTH_SENT_CODE_TYPE_CALL => Ok(SentCodeDelivery::Call {
            length: cursor.read_i32()?,
        }),
        AUTH_SENT_CODE_TYPE_FLASH_CALL => Ok(SentCodeDelivery::FlashCall {
            pattern: cursor.read_string()?,
        }),
        AUTH_SENT_CODE_TYPE_MISSED_CALL => Ok(SentCodeDelivery::MissedCall {
            prefix: cursor.read_string()?,
            length: cursor.read_i32()?,
        }),
        AUTH_SENT_CODE_TYPE_EMAIL_CODE => {
            let flags = cursor.read_u32()?;
            let pattern = cursor.read_string()?;
            let length = cursor.read_i32()?;
            if flags & (1 << 3) != 0 {
                let _reset_available_period = cursor.read_i32()?;
            }
            if flags & (1 << 4) != 0 {
                let _reset_pending_date = cursor.read_i32()?;
            }
            Ok(SentCodeDelivery::Email { pattern, length })
        }
        AUTH_SENT_CODE_TYPE_SET_UP_EMAIL_REQUIRED => {
            let _flags = cursor.read_u32()?;
            Ok(SentCodeDelivery::SetUpEmailRequired)
        }
        AUTH_SENT_CODE_TYPE_FRAGMENT_SMS => Ok(SentCodeDelivery::FragmentSms {
            url: cursor.read_string()?,
            length: cursor.read_i32()?,
        }),
        AUTH_SENT_CODE_TYPE_FIREBASE_SMS => {
            let flags = cursor.read_u32()?;
            if flags & (1 << 0) != 0 {
                let _nonce = cursor.read_bytes()?;
            }
            if flags & (1 << 2) != 0 {
                let _project_id = cursor.read_i64()?;
                let _integrity_nonce = cursor.read_bytes()?;
            }
            if flags & (1 << 1) != 0 {
                let _receipt = cursor.read_string()?;
                let _push_timeout = cursor.read_i32()?;
            }
            Ok(SentCodeDelivery::FirebaseSms {
                length: cursor.read_i32()?,
            })
        }
        AUTH_SENT_CODE_TYPE_SMS_WORD => {
            let flags = cursor.read_u32()?;
            let beginning = if flags & 1 != 0 {
                Some(cursor.read_string()?)
            } else {
                None
            };
            Ok(SentCodeDelivery::SmsWord { beginning })
        }
        AUTH_SENT_CODE_TYPE_SMS_PHRASE => {
            let flags = cursor.read_u32()?;
            let beginning = if flags & 1 != 0 {
                Some(cursor.read_string()?)
            } else {
                None
            };
            Ok(SentCodeDelivery::SmsPhrase { beginning })
        }
        _ => Err(Error::new(
            ErrorKind::UnexpectedConstructor,
            narrow(at),
            id.get(),
        )),
    }
}

#[cfg(feature = "auth")]
fn parse_authorization_cursor<'a>(cursor: &mut Cursor<'a>) -> Result<Authorization<'a>> {
    let id = cursor.read_constructor()?;
    parse_authorization_after_id(id, cursor)
}

#[cfg(feature = "auth")]
fn parse_authorization_after_id<'a>(
    id: ConstructorId,
    cursor: &mut Cursor<'a>,
) -> Result<Authorization<'a>> {
    match id {
        AUTH_AUTHORIZATION => {
            let flags = cursor.read_u32()?;
            let tmp_sessions = if flags & 1 != 0 {
                Some(cursor.read_i32()?)
            } else {
                None
            };
            let otherwise_relogin_days = if flags & (1 << 1) != 0 {
                // In TL, `flags.N?true` is a zero-byte void field: the same
                // bit also gates the following integer in this constructor.
                Some(cursor.read_i32()?)
            } else {
                None
            };
            let future_auth_token = if flags & (1 << 2) != 0 {
                Some(cursor.read_bytes()?)
            } else {
                None
            };
            let user = RawObject::from_exact(cursor.remaining())?;
            cursor.skip(cursor.remaining_len())?;
            Ok(Authorization::Authorized {
                tmp_sessions,
                otherwise_relogin_days,
                future_auth_token,
                user,
            })
        }
        AUTH_AUTHORIZATION_SIGN_UP_REQUIRED => {
            let flags = cursor.read_u32()?;
            let terms_of_service = if flags & 1 != 0 {
                let object = RawObject::from_exact(cursor.remaining())?;
                cursor.skip(cursor.remaining_len())?;
                Some(object)
            } else {
                None
            };
            Ok(Authorization::SignUpRequired { terms_of_service })
        }
        _ => Err(Error::new(
            ErrorKind::UnexpectedConstructor,
            narrow(cursor.position().saturating_sub(4)),
            id.get(),
        )),
    }
}

fn parse_positive_i32(input: &str) -> Option<i32> {
    if input.is_empty() {
        return None;
    }
    let mut value = 0i32;
    for byte in input.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    (value > 0).then_some(value)
}

#[cfg(all(test, feature = "auth"))]
mod tests {
    use super::{
        ApiContext, AuthResponse, CodeSettings, InputPeer, RpcError, SendMessageOptions,
        SentCodeDelivery, TELEGRAM_API_LAYER, parse_auth_response, write_init_connection_prefix,
        write_send_code, write_send_text,
    };
    use crate::generated::{AUTH_AUTHORIZATION, AUTH_SENT_CODE, AUTH_SENT_CODE_TYPE_SMS};
    use crate::tl::{Cursor, Writer};

    #[test]
    fn auth_request_is_composed_without_an_inner_buffer() {
        let context = ApiContext::new(42, "hash", "device", "os", "app", "en", "", "en");
        let mut storage = [0u8; 256];
        let written = {
            let mut writer = Writer::new(&mut storage);
            write_init_connection_prefix(&mut writer, context).expect("prefix");
            write_send_code(&mut writer, context, "+12025550123", CodeSettings::EMPTY)
                .expect("method");
            writer.position()
        };
        let mut cursor = Cursor::new(&storage[..written]);
        assert_eq!(cursor.read_u32().expect("invoke"), 0xda9b_0d0d);
        assert_eq!(cursor.read_i32().expect("layer"), TELEGRAM_API_LAYER);
        assert_eq!(cursor.read_u32().expect("init"), 0xc1cd_5ea9);
        assert_eq!(cursor.read_u32().expect("flags"), 0);
        assert_eq!(cursor.read_i32().expect("api id"), 42);
        for _ in 0..6 {
            let _ = cursor.read_string().expect("context string");
        }
        assert_eq!(cursor.read_u32().expect("send code"), 0xa677_244f);
    }

    #[test]
    fn parses_borrowed_sent_code_and_migration_error() {
        let mut storage = [0u8; 64];
        let written = {
            let mut writer = Writer::new(&mut storage);
            writer.write_constructor(AUTH_SENT_CODE).expect("id");
            writer.write_u32((1 << 1) | (1 << 2)).expect("flags");
            writer
                .write_constructor(AUTH_SENT_CODE_TYPE_SMS)
                .expect("delivery");
            writer.write_i32(5).expect("length");
            writer.write_string("token").expect("hash");
            writer.write_u32(0x72a3_158c).expect("next type");
            writer.write_i32(60).expect("timeout");
            writer.position()
        };
        let parsed = parse_auth_response(&storage[..written]).expect("sent code");
        let AuthResponse::SentCode(code) = parsed else {
            panic!("wrong response");
        };
        assert_eq!(code.phone_code_hash.as_str(), "token");
        assert_eq!(code.timeout, Some(60));
        assert_eq!(code.delivery, SentCodeDelivery::Sms { length: 5 });

        let mut error_storage = [0u8; 48];
        let error_written = {
            let mut writer = Writer::new(&mut error_storage);
            writer.write_u32(0x2144_ca19).expect("id");
            writer.write_i32(303).expect("code");
            writer.write_string("PHONE_MIGRATE_5").expect("message");
            writer.position()
        };
        assert_eq!(
            RpcError::parse(&error_storage[..error_written])
                .expect("rpc error")
                .migration_dc(),
            Some(5)
        );
    }

    #[test]
    fn text_message_writer_never_sets_a_payload_flag() {
        let mut storage = [0u8; 128];
        let written = {
            let mut writer = Writer::new(&mut storage);
            write_send_text(
                &mut writer,
                InputPeer::User {
                    user_id: 7,
                    access_hash: 8,
                },
                "hi",
                9,
                SendMessageOptions::EMPTY.silent().no_webpage(),
            )
            .expect("send text");
            writer.position()
        };
        let mut cursor = Cursor::new(&storage[..written]);
        assert_eq!(cursor.read_u32().expect("method"), 0xfef4_8f62);
        assert_eq!(cursor.read_i64().expect("ephemeral"), 0);
        assert_eq!(cursor.read_u32().expect("flags"), (1 << 1) | (1 << 5));
    }

    #[test]
    fn authorization_true_flags_consume_no_extra_tl_object() {
        let mut storage = [0u8; 32];
        let written = {
            let mut writer = Writer::new(&mut storage);
            writer.write_constructor(AUTH_AUTHORIZATION).expect("id");
            writer.write_u32(1 << 1).expect("flags");
            writer.write_i32(31).expect("relogin days");
            writer.write_u32(1).expect("opaque user id");
            writer.position()
        };
        let AuthResponse::Authorized(super::Authorization::Authorized {
            otherwise_relogin_days,
            user,
            ..
        }) = parse_auth_response(&storage[..written]).expect("authorization")
        else {
            panic!("wrong response");
        };
        assert_eq!(otherwise_relogin_days, Some(31));
        assert_eq!(user.id.get(), 1);
    }
}

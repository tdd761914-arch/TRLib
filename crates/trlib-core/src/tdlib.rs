//! Optional, small TDLib-shaped migration adapter.
//!
//! This is not a second TDLib implementation: TRLib intentionally omits its
//! database, UI model and broad object cache.  Instead, this feature translates
//! the most common TDLib JSON login/request shapes into zero-copy TRLib method
//! writers and emits TDLib-shaped authorization events.  It uses a strict,
//! streaming JSON reader rather than `serde_json`; strings containing JSON
//! escapes are rejected to preserve borrowed zero-copy values.

use crate::api::{
    ApiContext, AuthResponse, Authorization, CodeSettings, InputPeer, RpcError, SendMessageOptions,
    write_get_history, write_get_me, write_send_code, write_send_text, write_send_text_reply,
    write_sign_in, write_sign_up,
};
use crate::error::{Error, ErrorKind, Result, narrow};
use crate::generated::{
    MESSAGES_DELETE_MESSAGES, MESSAGES_EDIT_MESSAGE, MESSAGES_GET_CHATS, MESSAGES_GET_HISTORY,
    MESSAGES_GET_MESSAGES, MESSAGES_READ_HISTORY, MESSAGES_SEND_MESSAGE, USERS_GET_FULL_USER,
    USERS_GET_USERS,
};
use crate::tl::schema::{Value, serialize};
use crate::tl::{ConstructorId, Writer};

/// The chat identifier offset of channel dialogs, matching TDLib `DialogId`.
///
/// A channel dialog id is `-1000000000000 - channel_id`.
pub const CHANNEL_CHAT_ID_OFFSET: i64 = -1_000_000_000_000;

const MAX_INT53: i64 = (1_i64 << 53) - 1;

/// Returns `true` for channel/supergroup TDLib chat identifiers.
#[inline]
pub const fn is_channel_chat_id(chat_id: i64) -> bool {
    chat_id < CHANNEL_CHAT_ID_OFFSET
}

/// Converts a channel identifier into its TDLib dialog chat identifier.
#[inline]
pub const fn channel_chat_id(channel_id: i64) -> i64 {
    CHANNEL_CHAT_ID_OFFSET - channel_id
}

/// Converts a basic-group identifier into TDLib's negative chat identifier.
#[inline]
pub const fn basic_group_chat_id(group_id: i64) -> i64 {
    -group_id
}

/// A bounded list of message identifiers used by bulk `getMessages`/`deleteMessages`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageIdList {
    ids: [i32; Self::MAX_LEN],
    len: u8,
}

impl MessageIdList {
    /// The maximum number of identifiers accepted by the bounded list.
    pub const MAX_LEN: usize = 16;

    /// Builds a bounded list, rejecting inputs longer than [`MAX_LEN`](Self::MAX_LEN).
    pub fn from_slice(ids: &[i32]) -> Option<MessageIdList> {
        if ids.len() > Self::MAX_LEN {
            return None;
        }
        let mut bounded = [0i32; Self::MAX_LEN];
        bounded[..ids.len()].copy_from_slice(ids);
        Some(MessageIdList {
            ids: bounded,
            len: ids.len() as u8,
        })
    }

    /// Builds a bounded list from TDLib's `int53` JSON values.
    ///
    /// MTProto message identifiers are signed 32-bit values. Values outside
    /// that wire range are rejected instead of silently truncating them.
    pub fn from_i64_slice(ids: &[i64]) -> Option<MessageIdList> {
        if ids.len() > Self::MAX_LEN {
            return None;
        }
        let mut bounded = [0i32; Self::MAX_LEN];
        for (index, id) in ids.iter().copied().enumerate() {
            bounded[index] = i32::try_from(id).ok()?;
        }
        Some(MessageIdList {
            ids: bounded,
            len: ids.len() as u8,
        })
    }

    /// The stored identifiers.
    pub fn as_slice(&self) -> &[i32] {
        &self.ids[..self.len as usize]
    }
}

/// A small fixed-size entity cache resolving TDLib chat identifiers.
///
/// Unlike TDLib's full database, TRLib caches at most [`Self::CAPACITY`]
/// peers in a ring; inserts are cheap and lookups are a linear scan, which is
/// fine for the short-lived peer sets of a lightweight adapter.
#[derive(Clone, Copy, Debug)]
pub struct EntityCache {
    slots: [Option<CachedPeer>; Self::CAPACITY],
    next: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedPeer {
    chat_id: i64,
    peer: InputPeer,
}

impl EntityCache {
    /// The number of peers the ring can hold.
    pub const CAPACITY: usize = 16;

    /// An empty cache.
    pub const fn new() -> Self {
        Self {
            slots: [None; Self::CAPACITY],
            next: 0,
        }
    }

    /// Inserts or replaces the peer for a TDLib chat identifier.
    pub fn insert(&mut self, chat_id: i64, peer: InputPeer) {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|cached| cached.chat_id == chat_id))
        {
            *slot = Some(CachedPeer { chat_id, peer });
            return;
        }
        self.slots[self.next] = Some(CachedPeer { chat_id, peer });
        self.next = (self.next + 1) % Self::CAPACITY;
    }

    /// Resolves a TDLib chat identifier into its cached input peer.
    pub fn get(&self, chat_id: i64) -> Option<InputPeer> {
        self.slots.iter().find_map(|slot| {
            slot.and_then(|cached| (cached.chat_id == chat_id).then_some(cached.peer))
        })
    }

    /// Caches a user dialog (chat identifier equals the user identifier).
    pub fn insert_user(&mut self, user_id: i64, access_hash: i64) {
        self.insert(
            user_id,
            InputPeer::User {
                user_id,
                access_hash,
            },
        );
    }

    /// Caches a channel/supergroup dialog from its channel identifier.
    pub fn insert_channel(&mut self, channel_id: i64, access_hash: i64) {
        self.insert(
            channel_chat_id(channel_id),
            InputPeer::Channel {
                channel_id,
                access_hash,
            },
        );
    }

    /// Caches a basic group dialog using TDLib's negative chat identifier.
    pub fn insert_basic_group(&mut self, group_id: i64) {
        self.insert(
            basic_group_chat_id(group_id),
            InputPeer::Chat { chat_id: group_id },
        );
    }
}

/// Parsed TDLib-shaped parameters needed to build TRLib API requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct TdlibParameters<'a> {
    /// Whether TDLib would use Telegram's test data center.
    pub use_test_dc: bool,
    /// TDLib database directory (accepted for API compatibility, not opened by TRLib).
    pub database_directory: &'a str,
    /// TDLib files directory (accepted for API compatibility, not opened by TRLib).
    pub files_directory: &'a str,
    /// Base64-encoded TDLib database encryption key as supplied by JSON.
    pub database_encryption_key: &'a str,
    /// TDLib file database preference, exposed for the host policy.
    pub use_file_database: bool,
    /// TDLib chat-info database preference, exposed for the host policy.
    pub use_chat_info_database: bool,
    /// TDLib message database preference, exposed for the host policy.
    pub use_message_database: bool,
    /// TDLib secret-chat preference, exposed for the host policy.
    pub use_secret_chats: bool,
    /// Telegram API identifier.
    pub api_id: i32,
    /// Telegram API hash.
    pub api_hash: &'a str,
    /// Reported device model.
    pub device_model: &'a str,
    /// Reported system version.
    pub system_version: &'a str,
    /// Reported application version.
    pub application_version: &'a str,
    /// Reported system language code.
    pub system_language_code: &'a str,
}

impl<'a> TdlibParameters<'a> {
    /// Converts TDLib parameters into the compact TRLib initialization context.
    #[inline]
    pub const fn api_context(self) -> ApiContext<'a> {
        ApiContext::new(
            self.api_id,
            self.api_hash,
            self.device_model,
            self.system_version,
            self.application_version,
            self.system_language_code,
            "",
            self.system_language_code,
        )
    }
}

/// Phone-flow values obtained from the previous `auth.sentCode` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct LoginCodeContext<'a> {
    /// Phone number previously submitted to `auth.sendCode`.
    pub phone_number: &'a str,
    /// Server-provided phone code hash.
    pub phone_code_hash: &'a str,
}

/// A zero-copy command parsed from a small supported TDLib JSON request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TdRequest<'a> {
    /// `setTdlibParameters`.
    SetTdlibParameters(TdlibParameters<'a>),
    /// `setAuthenticationPhoneNumber`.
    SetAuthenticationPhoneNumber {
        /// Phone number to submit.
        phone_number: &'a str,
        /// Standard TDLib phone-number authentication settings.
        settings: CodeSettings,
    },
    /// `checkAuthenticationCode`.
    CheckAuthenticationCode {
        /// Code received through Telegram's selected delivery method.
        code: &'a str,
    },
    /// `registerUser`.
    RegisterUser {
        /// Registration first name.
        first_name: &'a str,
        /// Registration last name.
        last_name: &'a str,
        /// Standard TDLib notification preference.
        disable_notification: bool,
    },
    /// `getMe`.
    GetMe,
    /// A lightweight `sendMessage` subset using a resolvable input peer.
    SendMessage {
        /// Server-resolvable peer supplied by the adapter extension.
        peer: InputPeer,
        /// Plain text body.
        text: &'a str,
        /// Optional TRLib extension carrying a host-generated random identifier.
        random_id: Option<i64>,
        /// Supported payload-free send options.
        options: SendMessageOptions,
        /// Optional reply target resolved by the adapter.
        reply_to_message_id: Option<i32>,
    },
    /// A `sendMessage` subset resolving the peer through the entity cache.
    SendMessageToChat {
        /// TDLib chat identifier.
        chat_id: i64,
        /// Plain text body.
        text: &'a str,
        /// Optional TRLib extension carrying a host-generated random identifier.
        random_id: Option<i64>,
        /// Supported payload-free send options.
        options: SendMessageOptions,
        /// Optional message to reply to.
        reply_to_message_id: Option<i32>,
    },
    /// A lightweight `getChatHistory` subset using a resolvable input peer.
    GetChatHistory {
        /// Server-resolvable peer supplied by the adapter extension.
        peer: Option<InputPeer>,
        /// Standard TDLib dialog identifier, resolved through [`EntityCache`].
        chat_id: Option<i64>,
        /// Standard TDLib starting message identifier.
        from_message_id: i64,
        /// Standard TDLib message offset.
        offset: i32,
        /// Maximum number of messages to request.
        limit: i32,
        /// Standard TDLib offline-only flag. The network-only core rejects it.
        only_local: bool,
    },
    /// `getChat`, resolving channel dialogs through `messages.getChats` and
    /// the rest through `users.getUsers`.
    GetChat {
        /// TDLib chat identifier.
        chat_id: i64,
    },
    /// `getUser`, resolving a user through `users.getUsers`.
    GetUser {
        /// TDLib user identifier.
        user_id: i64,
    },
    /// `getMessages`.
    GetMessages {
        /// TDLib chat identifier.
        chat_id: i64,
        /// Message identifiers within the chat.
        message_ids: MessageIdList,
    },
    /// `deleteMessages`.
    DeleteMessages {
        /// TDLib chat identifier.
        chat_id: i64,
        /// Message identifiers within the chat.
        message_ids: MessageIdList,
        /// Whether to remove the messages for the other side too.
        revoke: bool,
    },
    /// `readHistory`.
    ReadHistory {
        /// TDLib chat identifier.
        chat_id: i64,
        /// Mark all messages up to this identifier as read.
        max_id: i32,
    },
    /// `editMessageText`.
    EditMessageText {
        /// TDLib chat identifier.
        chat_id: i64,
        /// Message identifier to edit.
        message_id: i32,
        /// New plain text body.
        text: &'a str,
    },
}

/// Result of translating a TDLib-shaped request into a TL method writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TdDispatch<'a> {
    /// The embedding application should retain this API context for the connection.
    Parameters(ApiContext<'a>),
    /// A complete boxed TL method was written into the supplied buffer.
    Method(ConstructorId),
}

/// Parses a supported TDLib JSON request without allocating a JSON AST.
///
/// Recognized request types are `setTdlibParameters`,
/// `setAuthenticationPhoneNumber`, `checkAuthenticationCode`, `registerUser`,
/// `getMe`, `sendMessage`, `sendMessageToChat`, `getChatHistory`, `getChat`,
/// `getUser`, `getMessages`, `deleteMessages`, `readHistory`, and
/// `editMessageText`. Standard TDLib `chat_id`, nested options/content, and
/// reply objects are accepted; chat identifiers are resolved through an
/// [`EntityCache`]. The explicit `trlib_peer` extension remains available for
/// callers that already have an access hash and do not want to populate a
/// cache.
pub fn parse_request(input: &[u8]) -> Result<TdRequest<'_>> {
    let mut cursor = JsonCursor::new(input);
    cursor.expect(b'{')?;
    let mut kind = None;
    let mut api_id = None;
    let mut api_hash = None;
    let mut use_test_dc = false;
    let mut database_directory = "";
    let mut files_directory = "";
    let mut database_encryption_key = "";
    let mut use_file_database = false;
    let mut use_chat_info_database = false;
    let mut use_message_database = false;
    let mut use_secret_chats = false;
    let mut device_model = None;
    let mut system_version = None;
    let mut application_version = None;
    let mut system_language_code = None;
    let mut phone_number = None;
    let mut code_settings = CodeSettings::EMPTY;
    let mut code = None;
    let mut first_name = None;
    let mut last_name = None;
    let mut register_disable_notification = false;
    let mut peer = None;
    let mut text = None;
    let mut random_id = None;
    let mut limit = None;
    let mut options = SendMessageOptions::EMPTY;
    let mut chat_id = None;
    let mut user_id = None;
    let mut message_ids = None;
    let mut revoke = false;
    let mut max_id = None;
    let mut message_id = None;
    let mut from_message_id = 0i64;
    let mut offset = 0i32;
    let mut only_local = false;
    let mut reply_to_message_id = None;

    if cursor.consume(b'}')? {
        return Err(invalid_json(cursor.position()));
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        match field {
            "@type" => kind = Some(cursor.read_string()?),
            "api_id" => api_id = Some(cursor.read_i32()?),
            "api_hash" => api_hash = Some(cursor.read_string()?),
            "device_model" => device_model = Some(cursor.read_string()?),
            "system_version" => system_version = Some(cursor.read_string()?),
            "application_version" => application_version = Some(cursor.read_string()?),
            "system_language_code" => system_language_code = Some(cursor.read_string()?),
            "use_test_dc" => use_test_dc = cursor.read_bool()?,
            "database_directory" => database_directory = cursor.read_string()?,
            "files_directory" => files_directory = cursor.read_string()?,
            "database_encryption_key" => {
                database_encryption_key = cursor.read_string()?;
            }
            "use_file_database" => use_file_database = cursor.read_bool()?,
            "use_chat_info_database" => use_chat_info_database = cursor.read_bool()?,
            "use_message_database" => use_message_database = cursor.read_bool()?,
            "use_secret_chats" => use_secret_chats = cursor.read_bool()?,
            "phone_number" => phone_number = Some(cursor.read_string()?),
            "settings" => code_settings = parse_code_settings(&mut cursor)?,
            "code" => code = Some(cursor.read_string()?),
            "first_name" => first_name = Some(cursor.read_string()?),
            "last_name" => last_name = Some(cursor.read_string()?),
            "disable_notification" => {
                let value = cursor.read_bool()?;
                register_disable_notification = value;
                if value {
                    options = options.silent();
                }
            }
            "trlib_peer" => peer = Some(parse_peer(&mut cursor)?),
            "input_message_content" => text = Some(parse_message_content(&mut cursor)?),
            "text" => text = Some(cursor.read_string()?),
            "random_id" => random_id = Some(cursor.read_i64()?),
            "options" => options = parse_message_send_options(&mut cursor)?,
            "reply_to" => reply_to_message_id = parse_reply_to(&mut cursor)?,
            "limit" => limit = Some(cursor.read_i32()?),
            "chat_id" => chat_id = Some(cursor.read_int53()?),
            "user_id" => user_id = Some(cursor.read_int53()?),
            "message_ids" => {
                let (ids, len) = cursor.read_i64_array()?;
                message_ids = Some(
                    MessageIdList::from_i64_slice(&ids[..len])
                        .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0, 16))?,
                );
            }
            "revoke" => revoke = cursor.read_bool()?,
            "max_id" => max_id = Some(cursor.read_i32()?),
            "message_id" => message_id = Some(cursor.read_int53()?),
            "from_message_id" => from_message_id = cursor.read_int53()?,
            "offset" => offset = cursor.read_i32()?,
            "only_local" => only_local = cursor.read_bool()?,
            "reply_to_message_id" => reply_to_message_id = Some(cursor.read_i32()?),
            "disable_web_page_preview" => {
                if cursor.read_bool()? {
                    options = options.no_webpage();
                }
            }
            "background" => {
                if cursor.read_bool()? {
                    options = options.background();
                }
            }
            _ => cursor.skip_value(0)?,
        }
        if cursor.consume(b'}')? {
            break;
        }
        cursor.expect(b',')?;
    }
    cursor.finish()?;

    match required(kind, 0)? {
        "setTdlibParameters" => Ok(TdRequest::SetTdlibParameters(TdlibParameters {
            use_test_dc,
            database_directory,
            files_directory,
            database_encryption_key,
            use_file_database,
            use_chat_info_database,
            use_message_database,
            use_secret_chats,
            api_id: required(api_id, 1)?,
            api_hash: required(api_hash, 2)?,
            device_model: required(device_model, 3)?,
            system_version: required(system_version, 4)?,
            application_version: required(application_version, 5)?,
            system_language_code: required(system_language_code, 6)?,
        })),
        "setAuthenticationPhoneNumber" => Ok(TdRequest::SetAuthenticationPhoneNumber {
            phone_number: required(phone_number, 7)?,
            settings: code_settings,
        }),
        "checkAuthenticationCode" => Ok(TdRequest::CheckAuthenticationCode {
            code: required(code, 8)?,
        }),
        "registerUser" => Ok(TdRequest::RegisterUser {
            first_name: required(first_name, 9)?,
            last_name: last_name.unwrap_or(""),
            disable_notification: register_disable_notification,
        }),
        "getMe" => Ok(TdRequest::GetMe),
        "sendMessage" => match peer {
            Some(peer) => Ok(TdRequest::SendMessage {
                peer,
                text: required(text, 11)?,
                random_id,
                options,
                reply_to_message_id,
            }),
            None => Ok(TdRequest::SendMessageToChat {
                chat_id: required(chat_id, 15)?,
                text: required(text, 11)?,
                random_id,
                options,
                reply_to_message_id,
            }),
        },
        "sendMessageToChat" => Ok(TdRequest::SendMessageToChat {
            chat_id: required(chat_id, 15)?,
            text: required(text, 11)?,
            random_id,
            options,
            reply_to_message_id,
        }),
        "getChatHistory" => Ok(TdRequest::GetChatHistory {
            peer,
            chat_id,
            from_message_id,
            offset,
            limit: required(limit, 14)?,
            only_local,
        }),
        "getChat" => Ok(TdRequest::GetChat {
            chat_id: required(chat_id, 15)?,
        }),
        "getUser" => Ok(TdRequest::GetUser {
            user_id: required(user_id, 16)?,
        }),
        "getMessages" => Ok(TdRequest::GetMessages {
            chat_id: required(chat_id, 15)?,
            message_ids: required(message_ids, 17)?,
        }),
        "deleteMessages" => Ok(TdRequest::DeleteMessages {
            chat_id: required(chat_id, 15)?,
            message_ids: required(message_ids, 17)?,
            revoke,
        }),
        "readHistory" => Ok(TdRequest::ReadHistory {
            chat_id: required(chat_id, 15)?,
            max_id: max_id.unwrap_or(0),
        }),
        "editMessageText" => Ok(TdRequest::EditMessageText {
            chat_id: required(chat_id, 15)?,
            message_id: narrow_message_id(required(message_id, 18)?)?,
            text: required(text, 11)?,
        }),
        _ => Err(Error::new(ErrorKind::FeatureDisabled, 0, 0)),
    }
}

/// Writes a TL method corresponding to a parsed TDLib-shaped command.
///
/// `SetTdlibParameters` does not write a network method; it returns the
/// compact [`ApiContext`] that callers can retain for `initConnection` and
/// `auth.sendCode`.  Code and registration requests require the `phone` and
/// `phone_code_hash` previously returned by `auth.sentCode`.  Chat-identifier
/// commands resolve their peers through the supplied [`EntityCache`]. A
/// standard TDLib `sendMessage` omits MTProto's `random_id`; use
/// [`write_request_with_random_id`] or include the `random_id` extension.
pub fn write_request<'request, 'context, 'login>(
    writer: &mut Writer<'_>,
    request: TdRequest<'request>,
    context: Option<ApiContext<'context>>,
    login: Option<LoginCodeContext<'login>>,
    cache: Option<&EntityCache>,
) -> Result<TdDispatch<'request>> {
    write_request_with_random_id(writer, request, context, login, cache, None)
}

/// Writes a TDLib-shaped request while supplying the random identifier that
/// standard TDLib normally generates internally for `sendMessage`.
pub fn write_request_with_random_id<'request, 'context, 'login>(
    writer: &mut Writer<'_>,
    request: TdRequest<'request>,
    context: Option<ApiContext<'context>>,
    login: Option<LoginCodeContext<'login>>,
    cache: Option<&EntityCache>,
    random_id_override: Option<i64>,
) -> Result<TdDispatch<'request>> {
    match request {
        TdRequest::SetTdlibParameters(parameters) => {
            Ok(TdDispatch::Parameters(parameters.api_context()))
        }
        TdRequest::SetAuthenticationPhoneNumber {
            phone_number,
            settings,
        } => {
            let context = context.ok_or_else(invalid_state)?;
            write_send_code(writer, context, phone_number, settings)?;
            Ok(TdDispatch::Method(crate::generated::AUTH_SEND_CODE))
        }
        TdRequest::CheckAuthenticationCode { code } => {
            let login = login.ok_or_else(invalid_state)?;
            write_sign_in(writer, login.phone_number, login.phone_code_hash, code)?;
            Ok(TdDispatch::Method(crate::generated::AUTH_SIGN_IN))
        }
        TdRequest::RegisterUser {
            first_name,
            last_name,
            disable_notification,
        } => {
            let login = login.ok_or_else(invalid_state)?;
            write_sign_up(
                writer,
                login.phone_number,
                login.phone_code_hash,
                first_name,
                last_name,
                disable_notification,
            )?;
            Ok(TdDispatch::Method(crate::generated::AUTH_SIGN_UP))
        }
        TdRequest::GetMe => {
            write_get_me(writer)?;
            Ok(TdDispatch::Method(USERS_GET_FULL_USER))
        }
        TdRequest::SendMessage {
            peer,
            text,
            random_id,
            options,
            reply_to_message_id,
        } => {
            let random_id = random_id.or(random_id_override).ok_or_else(invalid_state)?;
            if let Some(reply_to) = reply_to_message_id {
                write_send_text_reply(writer, peer, text, random_id, options, Some(reply_to))?;
            } else {
                write_send_text(writer, peer, text, random_id, options)?;
            }
            Ok(TdDispatch::Method(MESSAGES_SEND_MESSAGE))
        }
        TdRequest::SendMessageToChat {
            chat_id,
            text,
            random_id,
            options,
            reply_to_message_id,
        } => {
            let peer = resolve(cache, chat_id)?;
            let random_id = random_id.or(random_id_override).ok_or_else(invalid_state)?;
            write_send_text_reply(writer, peer, text, random_id, options, reply_to_message_id)?;
            Ok(TdDispatch::Method(MESSAGES_SEND_MESSAGE))
        }
        TdRequest::GetChatHistory {
            peer,
            chat_id,
            from_message_id,
            offset,
            limit,
            only_local,
        } => {
            if only_local {
                return Err(Error::new(ErrorKind::FeatureDisabled, 0, 0));
            }
            let peer = if let Some(peer) = peer {
                peer
            } else {
                let chat_id = chat_id.ok_or_else(invalid_state)?;
                resolve(cache, chat_id)?
            };
            let from_message_id = narrow_message_id(from_message_id)?;
            write_get_history(writer, peer, from_message_id, 0, offset, limit, 0, 0, 0)?;
            Ok(TdDispatch::Method(MESSAGES_GET_HISTORY))
        }
        TdRequest::GetChat { chat_id } => {
            if is_channel_chat_id(chat_id) {
                let channel_id = CHANNEL_CHAT_ID_OFFSET - chat_id;
                serialize(writer, MESSAGES_GET_CHATS, &[Value::Longs(&[channel_id])])?;
                Ok(TdDispatch::Method(MESSAGES_GET_CHATS))
            } else if chat_id > 0 {
                serialize(writer, USERS_GET_USERS, &[Value::UserIds(&[chat_id])])?;
                Ok(TdDispatch::Method(USERS_GET_USERS))
            } else if chat_id < 0 {
                let basic_group_id = chat_id.checked_neg().ok_or_else(invalid_state)?;
                serialize(
                    writer,
                    MESSAGES_GET_CHATS,
                    &[Value::Longs(&[basic_group_id])],
                )?;
                Ok(TdDispatch::Method(MESSAGES_GET_CHATS))
            } else {
                Err(invalid_state())
            }
        }
        TdRequest::GetUser { user_id } => {
            serialize(writer, USERS_GET_USERS, &[Value::UserIds(&[user_id])])?;
            Ok(TdDispatch::Method(USERS_GET_USERS))
        }
        TdRequest::GetMessages {
            chat_id,
            message_ids,
        } => {
            let _ = chat_id;
            serialize(
                writer,
                MESSAGES_GET_MESSAGES,
                &[Value::MessageIds(message_ids.as_slice())],
            )?;
            Ok(TdDispatch::Method(MESSAGES_GET_MESSAGES))
        }
        TdRequest::DeleteMessages {
            chat_id,
            message_ids,
            revoke,
        } => {
            let _ = chat_id;
            serialize(
                writer,
                MESSAGES_DELETE_MESSAGES,
                &[
                    if revoke { Value::True } else { Value::False },
                    Value::Ints(message_ids.as_slice()),
                ],
            )?;
            Ok(TdDispatch::Method(MESSAGES_DELETE_MESSAGES))
        }
        TdRequest::ReadHistory { chat_id, max_id } => {
            let peer = resolve(cache, chat_id)?;
            serialize(
                writer,
                MESSAGES_READ_HISTORY,
                &[Value::Peer(peer.into()), Value::Int(max_id)],
            )?;
            Ok(TdDispatch::Method(MESSAGES_READ_HISTORY))
        }
        TdRequest::EditMessageText {
            chat_id,
            message_id,
            text,
        } => {
            let peer = resolve(cache, chat_id)?;
            serialize(
                writer,
                MESSAGES_EDIT_MESSAGE,
                &[
                    Value::False, // no_webpage
                    Value::False, // invert_media
                    Value::Peer(peer.into()),
                    Value::Int(message_id),
                    Value::Str(text),
                ],
            )?;
            Ok(TdDispatch::Method(MESSAGES_EDIT_MESSAGE))
        }
    }
}

fn resolve(cache: Option<&EntityCache>, chat_id: i64) -> Result<InputPeer> {
    cache
        .and_then(|cache| cache.get(chat_id))
        .ok_or_else(invalid_state)
}

/// TDLib-shaped event emitted after parsing an authentication response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TdEvent<'a> {
    /// A TDLib authorization-state update.
    AuthorizationState(TdAuthorizationState),
    /// A TDLib-shaped standard error object.
    Error(RpcError<'a>),
}

/// TDLib authorization states represented by the compact adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TdAuthorizationState {
    /// Parameters are required before a connection can be initialized.
    WaitTdlibParameters,
    /// A phone number is required.
    WaitPhoneNumber,
    /// A confirmation code is required.
    WaitCode,
    /// A two-step-verification password proof is required.
    WaitPassword,
    /// Registration details are required.
    WaitRegistration,
    /// A paid authentication flow is required.
    WaitPayment,
    /// The account is authorized.
    Ready,
    /// The session is closed.
    Closed,
}

/// Converts a borrowed TRLib authentication response into a TDLib-shaped event.
pub fn event_from_auth_response(response: AuthResponse<'_>) -> TdEvent<'_> {
    match response {
        AuthResponse::SentCode(code) => {
            let _delivery = code.delivery;
            TdEvent::AuthorizationState(TdAuthorizationState::WaitCode)
        }
        AuthResponse::Authorized(Authorization::Authorized { .. }) => {
            TdEvent::AuthorizationState(TdAuthorizationState::Ready)
        }
        AuthResponse::Authorized(Authorization::SignUpRequired { .. }) => {
            TdEvent::AuthorizationState(TdAuthorizationState::WaitRegistration)
        }
        AuthResponse::PaymentRequired { .. } => {
            TdEvent::AuthorizationState(TdAuthorizationState::WaitPayment)
        }
        AuthResponse::RpcError(error) if error.message.as_str() == "SESSION_PASSWORD_NEEDED" => {
            TdEvent::AuthorizationState(TdAuthorizationState::WaitPassword)
        }
        AuthResponse::RpcError(error) => TdEvent::Error(error),
    }
}

/// Renders a TDLib-shaped event into a caller-owned UTF-8 JSON buffer.
pub fn write_event(event: TdEvent<'_>, output: &mut [u8]) -> Result<usize> {
    let mut writer = Writer::new(output);
    match event {
        TdEvent::AuthorizationState(state) => {
            writer.write_all(
                b"{\"@type\":\"updateAuthorizationState\",\"authorization_state\":{\"@type\":",
            )?;
            write_json_string(&mut writer, state_name(state))?;
            writer.write_all(b"}}")?;
        }
        TdEvent::Error(error) => {
            writer.write_all(b"{\"@type\":\"error\",\"code\":")?;
            write_decimal_i32(&mut writer, error.code)?;
            writer.write_all(b",\"message\":")?;
            write_json_string(&mut writer, error.message.as_str())?;
            writer.write_u8(b'}')?;
        }
    }
    Ok(writer.position())
}

fn parse_peer<'a>(cursor: &mut JsonCursor<'a>) -> Result<InputPeer> {
    cursor.expect(b'{')?;
    let mut kind = None;
    let mut id = None;
    let mut access_hash = None;
    if cursor.consume(b'}')? {
        return Err(invalid_json(cursor.position()));
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        match field {
            "@type" | "type" => kind = Some(cursor.read_string()?),
            "user_id" | "channel_id" | "id" => id = Some(cursor.read_int53()?),
            "access_hash" => access_hash = Some(cursor.read_i64()?),
            _ => cursor.skip_value(0)?,
        }
        if cursor.consume(b'}')? {
            break;
        }
        cursor.expect(b',')?;
    }
    match required(kind, 0)? {
        "inputPeerSelf" | "trlibInputPeerSelf" => Ok(InputPeer::SelfPeer),
        "inputPeerUser" | "trlibInputPeerUser" => Ok(InputPeer::User {
            user_id: required(id, 1)?,
            access_hash: required(access_hash, 2)?,
        }),
        "inputPeerChannel" | "trlibInputPeerChannel" => Ok(InputPeer::Channel {
            channel_id: required(id, 3)?,
            access_hash: required(access_hash, 4)?,
        }),
        _ => Err(Error::new(ErrorKind::FeatureDisabled, 0, 0)),
    }
}

fn parse_code_settings(cursor: &mut JsonCursor<'_>) -> Result<CodeSettings> {
    if cursor.consume_literal(b"null") {
        return Ok(CodeSettings::EMPTY);
    }
    cursor.expect(b'{')?;
    let mut settings = CodeSettings::EMPTY;
    if cursor.consume(b'}')? {
        return Ok(settings);
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        match field {
            "allow_flash_call" => {
                if cursor.read_bool()? {
                    settings = settings.allow_flashcall();
                }
            }
            "allow_missed_call" => {
                if cursor.read_bool()? {
                    settings = settings.allow_missed_call();
                }
            }
            "is_current_phone_number" => {
                if cursor.read_bool()? {
                    settings = settings.current_number();
                }
            }
            "has_unknown_phone_number" => {
                if cursor.read_bool()? {
                    settings = settings.unknown_number();
                }
            }
            "allow_sms_retriever_api" => {
                if cursor.read_bool()? {
                    settings = settings.allow_app_hash();
                }
            }
            _ => cursor.skip_value(0)?,
        }
        if cursor.consume(b'}')? {
            return Ok(settings);
        }
        cursor.expect(b',')?;
    }
}

fn parse_message_send_options(cursor: &mut JsonCursor<'_>) -> Result<SendMessageOptions> {
    if cursor.consume_literal(b"null") {
        return Ok(SendMessageOptions::EMPTY);
    }
    cursor.expect(b'{')?;
    let mut options = SendMessageOptions::EMPTY;
    if cursor.consume(b'}')? {
        return Ok(options);
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        match field {
            "disable_notification" => {
                if cursor.read_bool()? {
                    options = options.silent();
                }
            }
            "from_background" => {
                if cursor.read_bool()? {
                    options = options.background();
                }
            }
            "protect_content" => {
                if cursor.read_bool()? {
                    options = options.protect_content();
                }
            }
            "allow_paid_broadcast" => {
                if cursor.read_bool()? {
                    options = options.allow_paid_broadcast();
                }
            }
            "update_order_of_installed_sticker_sets" => {
                if cursor.read_bool()? {
                    options = options.update_sticker_order();
                }
            }
            _ => cursor.skip_value(0)?,
        }
        if cursor.consume(b'}')? {
            return Ok(options);
        }
        cursor.expect(b',')?;
    }
}

fn parse_reply_to(cursor: &mut JsonCursor<'_>) -> Result<Option<i32>> {
    if cursor.consume_literal(b"null") {
        return Ok(None);
    }
    cursor.expect(b'{')?;
    let mut kind = None;
    let mut message_id = None;
    if cursor.consume(b'}')? {
        return Err(invalid_json(cursor.position()));
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        match field {
            "@type" => kind = Some(cursor.read_string()?),
            "message_id" => message_id = Some(cursor.read_int53()?),
            _ => cursor.skip_value(0)?,
        }
        if cursor.consume(b'}')? {
            break;
        }
        cursor.expect(b',')?;
    }
    match required(kind, 0)? {
        "inputMessageReplyToMessage" | "inputMessageReplyToExternalMessage" => {
            narrow_message_id(required(message_id, 1)?).map(Some)
        }
        _ => Err(Error::new(ErrorKind::FeatureDisabled, 0, 0)),
    }
}

fn narrow_message_id(value: i64) -> Result<i32> {
    i32::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::InvalidLength,
            0,
            core::mem::size_of::<i32>() as u32,
        )
    })
}

fn parse_message_content<'a>(cursor: &mut JsonCursor<'a>) -> Result<&'a str> {
    cursor.expect(b'{')?;
    let mut kind = None;
    let mut text = None;
    if cursor.consume(b'}')? {
        return Err(invalid_json(cursor.position()));
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        match field {
            "@type" => kind = Some(cursor.read_string()?),
            "text" => {
                if cursor.peek()? == b'{' {
                    text = Some(parse_formatted_text(cursor)?);
                } else {
                    text = Some(cursor.read_string()?);
                }
            }
            _ => cursor.skip_value(0)?,
        }
        if cursor.consume(b'}')? {
            break;
        }
        cursor.expect(b',')?;
    }
    match required(kind, 0)? {
        "inputMessageText" => required(text, 1),
        _ => Err(Error::new(ErrorKind::FeatureDisabled, 0, 0)),
    }
}

fn parse_formatted_text<'a>(cursor: &mut JsonCursor<'a>) -> Result<&'a str> {
    cursor.expect(b'{')?;
    let mut text = None;
    if cursor.consume(b'}')? {
        return Err(invalid_json(cursor.position()));
    }
    loop {
        let field = cursor.read_string()?;
        cursor.expect(b':')?;
        if field == "text" {
            text = Some(cursor.read_string()?);
        } else {
            cursor.skip_value(0)?;
        }
        if cursor.consume(b'}')? {
            break;
        }
        cursor.expect(b',')?;
    }
    required(text, 0)
}

fn state_name(state: TdAuthorizationState) -> &'static str {
    match state {
        TdAuthorizationState::WaitTdlibParameters => "authorizationStateWaitTdlibParameters",
        TdAuthorizationState::WaitPhoneNumber => "authorizationStateWaitPhoneNumber",
        TdAuthorizationState::WaitCode => "authorizationStateWaitCode",
        TdAuthorizationState::WaitPassword => "authorizationStateWaitPassword",
        TdAuthorizationState::WaitRegistration => "authorizationStateWaitRegistration",
        TdAuthorizationState::WaitPayment => "authorizationStateWaitOtherDeviceConfirmation",
        TdAuthorizationState::Ready => "authorizationStateReady",
        TdAuthorizationState::Closed => "authorizationStateClosed",
    }
}

fn write_json_string(writer: &mut Writer<'_>, value: &str) -> Result<()> {
    writer.write_u8(b'\"')?;
    for byte in value.bytes() {
        match byte {
            b'\"' => writer.write_all(b"\\\"")?,
            b'\\' => writer.write_all(b"\\\\")?,
            b'\n' => writer.write_all(b"\\n")?,
            b'\r' => writer.write_all(b"\\r")?,
            b'\t' => writer.write_all(b"\\t")?,
            0..=0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                writer.write_all(b"\\u00")?;
                writer.write_u8(HEX[usize::from(byte >> 4)])?;
                writer.write_u8(HEX[usize::from(byte & 0x0f)])?;
            }
            _ => writer.write_u8(byte)?,
        }
    }
    writer.write_u8(b'\"')
}

fn write_decimal_i32(writer: &mut Writer<'_>, value: i32) -> Result<()> {
    let mut encoded = [0u8; 11];
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut cursor = encoded.len();
    loop {
        cursor -= 1;
        encoded[cursor] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if negative {
        cursor -= 1;
        encoded[cursor] = b'-';
    }
    writer.write_all(&encoded[cursor..])
}

fn required<T>(value: Option<T>, detail: u32) -> Result<T> {
    value.ok_or_else(|| Error::new(ErrorKind::InvalidPacket, 0, detail))
}

fn invalid_state() -> Error {
    Error::new(ErrorKind::InvalidState, 0, 0)
}

fn invalid_json(offset: usize) -> Error {
    Error::new(ErrorKind::InvalidPacket, narrow(offset), 0)
}

struct JsonCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> JsonCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn finish(&mut self) -> Result<()> {
        self.skip_whitespace();
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(invalid_json(self.position))
        }
    }

    fn peek(&mut self) -> Result<u8> {
        self.skip_whitespace();
        self.input
            .get(self.position)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NeedMore, narrow(self.position), 1))
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        let actual = self.peek()?;
        if actual != expected {
            return Err(Error::new(
                ErrorKind::InvalidPacket,
                narrow(self.position),
                u32::from(actual),
            ));
        }
        self.position += 1;
        Ok(())
    }

    fn consume(&mut self, expected: u8) -> Result<bool> {
        self.skip_whitespace();
        if self.input.get(self.position) == Some(&expected) {
            self.position += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn read_string(&mut self) -> Result<&'a str> {
        self.expect(b'\"')?;
        let start = self.position;
        loop {
            let byte = *self
                .input
                .get(self.position)
                .ok_or_else(|| Error::new(ErrorKind::NeedMore, narrow(self.position), 1))?;
            match byte {
                b'\"' => {
                    let string =
                        core::str::from_utf8(&self.input[start..self.position]).map_err(|_| {
                            Error::new(
                                ErrorKind::InvalidUtf8,
                                narrow(start),
                                narrow(self.position - start),
                            )
                        })?;
                    self.position += 1;
                    return Ok(string);
                }
                b'\\' | 0..=0x1f => return Err(invalid_json(self.position)),
                _ => self.position += 1,
            }
        }
    }

    fn read_i32(&mut self) -> Result<i32> {
        let value = self.read_i64()?;
        i32::try_from(value)
            .map_err(|_| Error::new(ErrorKind::InvalidLength, narrow(self.position), 4))
    }

    fn read_i64(&mut self) -> Result<i64> {
        self.skip_whitespace();
        let start = self.position;
        let negative = self.input.get(self.position) == Some(&b'-');
        if negative {
            self.position += 1;
        }
        let digit_start = self.position;
        let mut value = 0i64;
        while let Some(byte) = self.input.get(self.position).copied() {
            if !byte.is_ascii_digit() {
                break;
            }
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(i64::from(byte - b'0')))
                .ok_or_else(|| Error::new(ErrorKind::InvalidLength, narrow(start), 8))?;
            self.position += 1;
        }
        if digit_start == self.position {
            return Err(invalid_json(start));
        }
        if negative {
            value = value
                .checked_neg()
                .ok_or_else(|| Error::new(ErrorKind::InvalidLength, narrow(start), 8))?;
        }
        Ok(value)
    }

    fn read_int53(&mut self) -> Result<i64> {
        let value = self.read_i64()?;
        if (-MAX_INT53..=MAX_INT53).contains(&value) {
            Ok(value)
        } else {
            Err(Error::new(
                ErrorKind::InvalidLength,
                narrow(self.position),
                7,
            ))
        }
    }

    fn read_bool(&mut self) -> Result<bool> {
        self.skip_whitespace();
        if self.consume_literal(b"true") {
            return Ok(true);
        }
        if self.consume_literal(b"false") {
            return Ok(false);
        }
        Err(invalid_json(self.position))
    }

    fn read_i64_array(&mut self) -> Result<([i64; 16], usize)> {
        self.expect(b'[')?;
        let mut ids = [0i64; 16];
        let mut len = 0usize;
        if self.consume(b']')? {
            return Ok((ids, 0));
        }
        loop {
            if len == ids.len() {
                return Err(Error::new(
                    ErrorKind::InvalidLength,
                    narrow(self.position()),
                    ids.len() as u32,
                ));
            }
            ids[len] = self.read_int53()?;
            len += 1;
            if self.consume(b']')? {
                return Ok((ids, len));
            }
            self.expect(b',')?;
        }
    }

    fn skip_value(&mut self, depth: u8) -> Result<()> {
        if depth > 32 {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                narrow(self.position),
                32,
            ));
        }
        match self.peek()? {
            b'\"' => {
                let _ = self.read_string()?;
                Ok(())
            }
            b'{' => self.skip_object(depth + 1),
            b'[' => self.skip_array(depth + 1),
            b't' if self.consume_literal(b"true") => Ok(()),
            b'f' if self.consume_literal(b"false") => Ok(()),
            b'n' if self.consume_literal(b"null") => Ok(()),
            b'-' | b'0'..=b'9' => {
                let _ = self.read_i64()?;
                Ok(())
            }
            _ => Err(invalid_json(self.position)),
        }
    }

    fn skip_object(&mut self, depth: u8) -> Result<()> {
        self.expect(b'{')?;
        if self.consume(b'}')? {
            return Ok(());
        }
        loop {
            let _ = self.read_string()?;
            self.expect(b':')?;
            self.skip_value(depth)?;
            if self.consume(b'}')? {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn skip_array(&mut self, depth: u8) -> Result<()> {
        self.expect(b'[')?;
        if self.consume(b']')? {
            return Ok(());
        }
        loop {
            self.skip_value(depth)?;
            if self.consume(b']')? {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn consume_literal(&mut self, literal: &[u8]) -> bool {
        self.skip_whitespace();
        let Some(candidate) = self
            .input
            .get(self.position..self.position.saturating_add(literal.len()))
        else {
            return false;
        };
        if candidate == literal {
            self.position += literal.len();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.input.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EntityCache, LoginCodeContext, TdAuthorizationState, TdDispatch, TdEvent, TdRequest,
        event_from_auth_response, parse_request, write_event, write_request,
        write_request_with_random_id,
    };
    use crate::api::{AuthResponse, RpcError};
    use crate::tl::Writer;

    #[test]
    fn parses_and_writes_tdlib_phone_code_flow_without_serde() {
        let parameters = parse_request(
            br#"{"@type":"setTdlibParameters","api_id":7,"api_hash":"hash","device_model":"dev","system_version":"os","application_version":"app","system_language_code":"en"}"#,
        )
        .expect("parameters");
        let mut storage = [0u8; 128];
        let context = {
            let mut writer = Writer::new(&mut storage);
            match write_request(&mut writer, parameters, None, None, None).expect("dispatch") {
                TdDispatch::Parameters(context) => context,
                _ => panic!("expected parameters"),
            }
        };

        let phone = parse_request(
            br#"{"@type":"setAuthenticationPhoneNumber","phone_number":"+12025550123"}"#,
        )
        .expect("phone");
        let written = {
            let mut writer = Writer::new(&mut storage);
            let dispatch =
                write_request(&mut writer, phone, Some(context), None, None).expect("send code");
            assert_eq!(
                dispatch,
                TdDispatch::Method(crate::generated::AUTH_SEND_CODE)
            );
            writer.position()
        };
        assert_eq!(
            u32::from_le_bytes(storage[..4].try_into().expect("id")),
            0xa677_244f
        );
        assert!(written > 4);

        let code =
            parse_request(br#"{"@type":"checkAuthenticationCode","code":"12345"}"#).expect("code");
        let mut writer = Writer::new(&mut storage);
        let dispatch = write_request(
            &mut writer,
            code,
            Some(context),
            Some(LoginCodeContext {
                phone_number: "+12025550123",
                phone_code_hash: "token",
            }),
            None,
        )
        .expect("sign in");
        assert_eq!(dispatch, TdDispatch::Method(crate::generated::AUTH_SIGN_IN));
    }

    #[test]
    fn maps_password_error_to_tdlib_authorization_state() {
        let response = AuthResponse::RpcError(RpcError {
            code: 401,
            message: crate::tl::Cursor::new(&[
                23, b'S', b'E', b'S', b'S', b'I', b'O', b'N', b'_', b'P', b'A', b'S', b'S', b'W',
                b'O', b'R', b'D', b'_', b'N', b'E', b'E', b'D', b'E', b'D', 0, 0, 0,
            ])
            .read_string()
            .expect("string"),
        });
        assert_eq!(
            event_from_auth_response(response),
            TdEvent::AuthorizationState(TdAuthorizationState::WaitPassword)
        );
        let mut output = [0u8; 128];
        let length = write_event(event_from_auth_response(response), &mut output).expect("event");
        assert_eq!(
            &output[..length],
            b"{\"@type\":\"updateAuthorizationState\",\"authorization_state\":{\"@type\":\"authorizationStateWaitPassword\"}}"
        );
    }

    #[test]
    fn accepts_standard_tdlib_request_shapes_without_extensions() {
        assert_eq!(super::basic_group_chat_id(42), -42);
        assert!(super::is_channel_chat_id(super::channel_chat_id(42)));

        let parameters = parse_request(
            br#"{"@type":"setTdlibParameters","use_test_dc":false,"database_directory":"db","files_directory":"files","database_encryption_key":"","use_file_database":true,"use_chat_info_database":true,"use_message_database":true,"use_secret_chats":false,"api_id":7,"api_hash":"hash","system_language_code":"en","device_model":"dev","system_version":"os","application_version":"app"}"#,
        )
        .expect("full TDLib parameters");
        let TdRequest::SetTdlibParameters(parameters) = parameters else {
            panic!("expected parameters");
        };
        assert_eq!(parameters.database_directory, "db");
        assert!(parameters.use_file_database);

        let settings = parse_request(
            br#"{"@type":"setAuthenticationPhoneNumber","phone_number":"+12025550123","settings":{"@type":"phoneNumberAuthenticationSettings","allow_flash_call":true,"allow_missed_call":true,"is_current_phone_number":true,"has_unknown_phone_number":true,"allow_sms_retriever_api":true,"firebase_authentication_settings":null,"authentication_tokens":[]}}"#,
        )
        .expect("phone settings");
        let TdRequest::SetAuthenticationPhoneNumber { settings, .. } = settings else {
            panic!("expected phone request");
        };
        assert_eq!(settings.flags(), 1 | 2 | 16 | 32 | 512);

        let send = parse_request(
            br#"{"@type":"sendMessage","chat_id":7,"topic_id":null,"reply_to":{"@type":"inputMessageReplyToMessage","message_id":13,"quote":null,"checklist_task_id":0},"options":{"@type":"messageSendOptions","suggested_post_info":null,"disable_notification":true,"from_background":true,"protect_content":true,"allow_paid_broadcast":true,"paid_message_star_count":0,"update_order_of_installed_sticker_sets":true,"scheduling_state":null,"effect_id":0,"sending_id":0,"only_preview":false},"reply_markup":null,"input_message_content":{"@type":"inputMessageText","text":{"@type":"formattedText","text":"hello","entities":[]}}}"#,
        )
        .expect("standard sendMessage");
        let TdRequest::SendMessageToChat {
            chat_id,
            random_id,
            reply_to_message_id,
            ..
        } = send
        else {
            panic!("expected chat-id send request");
        };
        assert_eq!(chat_id, 7);
        assert_eq!(random_id, None);
        assert_eq!(reply_to_message_id, Some(13));

        let mut cache = EntityCache::new();
        cache.insert_user(7, 8);
        let mut output = [0u8; 256];
        let dispatch = write_request_with_random_id(
            &mut Writer::new(&mut output),
            send,
            None,
            None,
            Some(&cache),
            Some(99),
        )
        .expect("standard send writer");
        assert_eq!(
            dispatch,
            TdDispatch::Method(crate::generated::MESSAGES_SEND_MESSAGE)
        );

        let history = parse_request(
            br#"{"@type":"getChatHistory","chat_id":7,"from_message_id":10,"offset":-2,"limit":20,"only_local":false}"#,
        )
        .expect("standard history");
        let TdRequest::GetChatHistory {
            chat_id,
            from_message_id,
            offset,
            limit,
            only_local,
            ..
        } = history
        else {
            panic!("expected history request");
        };
        assert_eq!(
            (chat_id, from_message_id, offset, limit, only_local),
            (Some(7), 10, -2, 20, false)
        );
        assert!(parse_request(br#"{"@type":"getChat","chat_id":9007199254740992}"#).is_err());
        let mut history_cache = EntityCache::new();
        history_cache.insert_user(7, 8);
        let mut history_output = [0u8; 128];
        let history_dispatch = write_request(
            &mut Writer::new(&mut history_output),
            history,
            None,
            None,
            Some(&history_cache),
        )
        .expect("standard history writer");
        assert_eq!(
            history_dispatch,
            TdDispatch::Method(crate::generated::MESSAGES_GET_HISTORY)
        );
    }
}

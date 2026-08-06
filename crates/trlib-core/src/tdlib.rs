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
    write_get_history, write_get_me, write_send_code, write_send_text, write_sign_in,
    write_sign_up,
};
use crate::error::{Error, ErrorKind, Result, narrow};
use crate::generated::{MESSAGES_GET_HISTORY, MESSAGES_SEND_MESSAGE, USERS_GET_FULL_USER};
use crate::tl::{ConstructorId, Writer};

/// Parsed TDLib-shaped parameters needed to build TRLib API requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct TdlibParameters<'a> {
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
    },
    /// `getMe`.
    GetMe,
    /// A lightweight `sendMessage` subset using a resolvable input peer.
    SendMessage {
        /// Server-resolvable peer supplied by the adapter extension.
        peer: InputPeer,
        /// Plain text body.
        text: &'a str,
        /// Client-generated random identifier.
        random_id: i64,
        /// Supported payload-free send options.
        options: SendMessageOptions,
    },
    /// A lightweight `getChatHistory` subset using a resolvable input peer.
    GetChatHistory {
        /// Server-resolvable peer supplied by the adapter extension.
        peer: InputPeer,
        /// Maximum number of messages to request.
        limit: i32,
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
/// `getMe`, `sendMessage`, and `getChatHistory`.  `sendMessage` and
/// `getChatHistory` use the explicit `trlib_peer` extension because a TDLib
/// `chat_id` cannot be resolved without TDLib's large local entity cache.
pub fn parse_request(input: &[u8]) -> Result<TdRequest<'_>> {
    let mut cursor = JsonCursor::new(input);
    cursor.expect(b'{')?;
    let mut kind = None;
    let mut api_id = None;
    let mut api_hash = None;
    let mut device_model = None;
    let mut system_version = None;
    let mut application_version = None;
    let mut system_language_code = None;
    let mut phone_number = None;
    let mut code = None;
    let mut first_name = None;
    let mut last_name = None;
    let mut peer = None;
    let mut text = None;
    let mut random_id = None;
    let mut limit = None;
    let mut options = SendMessageOptions::EMPTY;

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
            "phone_number" => phone_number = Some(cursor.read_string()?),
            "code" => code = Some(cursor.read_string()?),
            "first_name" => first_name = Some(cursor.read_string()?),
            "last_name" => last_name = Some(cursor.read_string()?),
            "trlib_peer" => peer = Some(parse_peer(&mut cursor)?),
            "input_message_content" => text = Some(parse_message_content(&mut cursor)?),
            "text" => text = Some(cursor.read_string()?),
            "random_id" => random_id = Some(cursor.read_i64()?),
            "limit" => limit = Some(cursor.read_i32()?),
            "disable_notification" => {
                if cursor.read_bool()? {
                    options = options.silent();
                }
            }
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
            api_id: required(api_id, 1)?,
            api_hash: required(api_hash, 2)?,
            device_model: required(device_model, 3)?,
            system_version: required(system_version, 4)?,
            application_version: required(application_version, 5)?,
            system_language_code: required(system_language_code, 6)?,
        })),
        "setAuthenticationPhoneNumber" => Ok(TdRequest::SetAuthenticationPhoneNumber {
            phone_number: required(phone_number, 7)?,
        }),
        "checkAuthenticationCode" => Ok(TdRequest::CheckAuthenticationCode {
            code: required(code, 8)?,
        }),
        "registerUser" => Ok(TdRequest::RegisterUser {
            first_name: required(first_name, 9)?,
            last_name: last_name.unwrap_or(""),
        }),
        "getMe" => Ok(TdRequest::GetMe),
        "sendMessage" => Ok(TdRequest::SendMessage {
            peer: required(peer, 10)?,
            text: required(text, 11)?,
            random_id: required(random_id, 12)?,
            options,
        }),
        "getChatHistory" => Ok(TdRequest::GetChatHistory {
            peer: required(peer, 13)?,
            limit: required(limit, 14)?,
        }),
        _ => Err(Error::new(ErrorKind::FeatureDisabled, 0, 0)),
    }
}

/// Writes a TL method corresponding to a parsed TDLib-shaped command.
///
/// `SetTdlibParameters` does not write a network method; it returns the
/// compact [`ApiContext`] that callers can retain for `initConnection` and
/// `auth.sendCode`.  Code and registration requests require the `phone` and
/// `phone_code_hash` previously returned by `auth.sentCode`.
pub fn write_request<'request, 'context, 'login>(
    writer: &mut Writer<'_>,
    request: TdRequest<'request>,
    context: Option<ApiContext<'context>>,
    login: Option<LoginCodeContext<'login>>,
) -> Result<TdDispatch<'request>> {
    match request {
        TdRequest::SetTdlibParameters(parameters) => {
            Ok(TdDispatch::Parameters(parameters.api_context()))
        }
        TdRequest::SetAuthenticationPhoneNumber { phone_number } => {
            let context = context.ok_or_else(invalid_state)?;
            write_send_code(writer, context, phone_number, CodeSettings::EMPTY)?;
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
        } => {
            let login = login.ok_or_else(invalid_state)?;
            write_sign_up(
                writer,
                login.phone_number,
                login.phone_code_hash,
                first_name,
                last_name,
                false,
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
        } => {
            write_send_text(writer, peer, text, random_id, options)?;
            Ok(TdDispatch::Method(MESSAGES_SEND_MESSAGE))
        }
        TdRequest::GetChatHistory { peer, limit } => {
            write_get_history(writer, peer, 0, 0, 0, limit, 0, 0, 0)?;
            Ok(TdDispatch::Method(MESSAGES_GET_HISTORY))
        }
    }
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
            "user_id" | "channel_id" | "id" => id = Some(cursor.read_i64()?),
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
        LoginCodeContext, TdAuthorizationState, TdDispatch, TdEvent, event_from_auth_response,
        parse_request, write_event, write_request,
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
            match write_request(&mut writer, parameters, None, None).expect("dispatch") {
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
                write_request(&mut writer, phone, Some(context), None).expect("send code");
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
}

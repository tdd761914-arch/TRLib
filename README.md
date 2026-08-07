# TRLib

TRLib is a small, runtime-independent Rust Core Gateway for MTProto 2.0. It is
designed for high-RPS Telegram back ends that need borrowed TL parsing, bounded
memory, and feature-level control over binary size — not a full TDLib clone.

[Русская документация](README.ru.md) · [Public repository](https://github.com/tdd761914-arch/TRLib)

## What is included

- Zero-copy TL primitives: `Cursor<'a>`, `TlBytes<'a>`, `TlString<'a>`, raw
  boxed objects, and output into caller-owned buffers.
- Incremental abridged/intermediate TCP framing and plain/encrypted MTProto
  envelope parsing. The core owns neither a socket nor a receive buffer.
- Optional AES-256-IGE/SHA-256 MTProto 2.0 session crypto, with output packets
  encrypted in place after serialization.
- A streaming generator for the vendored full Telegram API schema from
  [`TGScheme/Schema`](https://github.com/TGScheme/Schema), pinned at
  `5e961c4673acfc5b921dd18ffdd5a02eda0e8143` (Layer 229), with per-namespace
  Cargo features.
- Feature-gated writers and zero-copy response views for phone-code login,
  account state, update state, history, direct text messages, and arbitrary raw
  schema methods.
- A lightweight encrypted text session document instead of SQLite.
- An opt-in TDLib-shaped JSON adapter for common login and request flows,
  without `serde` or TDLib's cache/UI/database stack.

## Scope and honest boundaries

TRLib is a Core Gateway. The host application supplies networking, scheduling,
random bytes, API credentials, DC endpoints, and retry policy. It currently
supports API phone-code login once an MTProto authorization key already exists:
`auth.sendCode`, `auth.signIn`, `auth.signUp`, `account.getPassword`, and
host-supplied SRP proof values for `auth.checkPassword`.

The RSA/DH authorization-key handshake, SRP big-integer password proof
calculation, file locking/atomic rename, media transfer, DC migration executor,
and TDLib's full JSON/object/database surface are intentionally outside this
small core. The response parser does expose `*_MIGRATE_<dc>` errors so the host
can implement a migration policy. This split keeps the network hot path small
and makes the missing heavyweight behavior explicit rather than silently
approximating TDLib.

## Build configuration

`trlib.conf` is a plain text build manifest. It is read before Cargo runs:

```ini
package = trlib-core
release = true
std = false
service = true
transport_abridged = false
transport_intermediate = true
crypto_rustcrypto = false
api = false
auth = false
session_document = false
session_file = false
tdlib_compat = false
```

Build it with:

```bash
cargo run --locked -p trlib-build -- --config trlib.conf
```

| Key | Linked code | Dependency implication |
|---|---|---|
| `service` | MTProto service objects and borrowed updates | none |
| `transport_abridged` | abridged TCP framing | none |
| `transport_intermediate` | intermediate TCP framing | none |
| `crypto_rustcrypto` | AES-256-IGE, SHA-256, constant-time verification | four small `no_std` RustCrypto crates |
| `api` | selected non-login Telegram API writers/views | none |
| `auth` | code-login writers and borrowed login result parsers | enables `api` |
| `session_document` | AES-CTR + HMAC encrypted session codec | enables crypto |
| `session_file` | blocking `std::fs` helpers for the text document | enables session document + `std` |
| `tdlib_compat` | strict TDLib-shaped JSON request/event adapter | enables `std`, auth, messages, and session file; unrelated API namespaces stay off |

For example, a native minimal update gateway leaves the last five flags off.
A migration build enables only one top-level switch:

```ini
tdlib_compat = true
```

Cargo resolves its required lower layers automatically. `CompiledFeatures` can
be queried at runtime to report the exact linked feature bitset.

## Zero-copy gateway

```rust
use trlib_core::config::GatewayConfig;
use trlib_core::gateway::{CoreGateway, GatewayPoll};
use trlib_core::transport::Intermediate;

let gateway = CoreGateway::new(&Intermediate, GatewayConfig::LOW_MEMORY);

match gateway.poll(receive_buffer)? {
    GatewayPoll::NeedMore(total) => reserve_until(total),
    GatewayPoll::Packet { envelope, consumed } => {
        handle_borrowed(envelope);
        discard_prefix(consumed);
    }
    GatewayPoll::QuickAck { token, consumed } => handle_ack(token, consumed),
}
# Ok::<(), trlib_core::Error>(())
```

The parser borrows from `receive_buffer`; it does not create `Vec`, `String`,
`Arc`, `Box`, or hidden clones for packet bodies.

## Selected API and login flow

`api` provides a raw escape hatch for every schema declaration:

```rust
use trlib_core::api::RawMethod;
use trlib_core::tl::{ConstructorId, Writer};

let method = RawMethod::new(ConstructorId::new(0x1234_5678), preencoded_fields);
let mut writer = Writer::new(&mut output);
method.write(&mut writer)?;
```

With `auth`, the common phone flow is direct and allocation-free. Compose
`initConnection` and `auth.sendCode` into the final packet buffer, send it over
an existing encrypted MTProto session, parse `auth.sentCode`, retain its
borrowed `phone_code_hash` in application-owned memory, then serialize
`auth.signIn` or `auth.signUp`.

```rust
use trlib_core::api::{ApiContext, CodeSettings, write_init_connection_prefix, write_send_code};
use trlib_core::tl::Writer;

let context = ApiContext::new(
    api_id, api_hash, "gateway", "linux", "1.0", "en", "", "en",
);
let mut writer = Writer::new(&mut packet_body);
write_init_connection_prefix(&mut writer, context)?;
write_send_code(&mut writer, context, phone_number, CodeSettings::EMPTY)?;
```

`write_check_password` accepts server-independent `srp_id`, `A`, and `M1`
bytes generated by an audited external SRP implementation; this is deliberately
not a hidden heavyweight big-integer dependency.

## Encrypted text session document

Enable `session_document` for a fixed-size document such as:

```text
TRLib-session-v1
salt=…32 lowercase-hex characters…
data=…AES-CTR ciphertext in lowercase hex…
tag=…HMAC-SHA-256 in lowercase hex…
```

The codec uses a host-supplied fresh 16-byte salt per write, AES-256-CTR for
encryption, and encrypt-then-HMAC-SHA-256 with independently derived keys.
It accepts caller-owned scratch slices and returns a `SessionRecordRef` that
borrows its 256-byte MTProto auth key from the decrypted scratch buffer. No
database, allocator, or serialization framework is required. For a password,
read the public salt with `document_salt`, then derive a `SessionKey` with
PBKDF2-HMAC-SHA-256; for services, prefer a random 32-byte secret from the
host key store.

`session_file` adds small blocking `save`/`load` helpers. The embedding service
should keep the parent directory private and use its own atomic-replace/locking
policy when multiple writers are possible.

## TDLib compatibility switch

`tdlib_compat` is optional. It parses a strict borrowed JSON subset without
`serde`:

- `setTdlibParameters`
- `setAuthenticationPhoneNumber`
- `checkAuthenticationCode`
- `registerUser`
- `getMe`
- `sendMessage`, `sendMessageToChat` (TRLib extension), `getChatHistory`, `getChat`, `getUser`,
  `getMessages`, `deleteMessages`, `readHistory`, and `editMessageText`

It emits TDLib-shaped `updateAuthorizationState` and `error` JSON. The adapter
rejects escaped JSON strings because returned values remain borrowed. Standard
`chat_id` requests resolve through a host-populated bounded `EntityCache`; use
the explicit `trlib_peer` extension when no cache is available:

The ordinary TDLib shape is accepted (the host supplies the MTProto random id
when writing it):

```json
{
  "@type": "sendMessage",
  "chat_id": 123,
  "options": { "@type": "messageSendOptions", "disable_notification": true },
  "input_message_content": {
    "@type": "inputMessageText",
    "text": { "@type": "formattedText", "text": "hello", "entities": [] }
  }
}
```

When no bounded cache is available, use the explicit peer extension instead:

```json
{
  "@type": "sendMessage",
  "trlib_peer": {
    "@type": "inputPeerUser",
    "user_id": 123,
    "access_hash": 456
  },
  "input_message_content": {
    "@type": "inputMessageText",
    "text": { "text": "hello" }
  },
  "random_id": 9001
}
```

This gives clients using TDLib naming and authorization states a migration
path while keeping the compatibility code completely absent from native builds.

### TDLib API comparison

The adapter is a small command translator, not a replacement for TDLib's
asynchronous client/database contract. The official TDLib API is much wider;
the table below records the exact migration boundary:

| TDLib JSON API | Standard TDLib contract | `tdlib_compat` status |
|---|---|---|
| `setTdlibParameters` | 14 initialization/database/test-DC fields | Input-compatible: all standard fields are parsed and exposed; TRLib does not open TDLib databases or select a DC |
| `setAuthenticationPhoneNumber` | phone plus optional authentication settings | Input-compatible subset: standard settings are parsed; Firebase/tokens are ignored |
| `checkAuthenticationCode` | code-driven auth state machine | Supported for phone-code flow; host supplies saved phone/hash |
| `registerUser` | first name, last name, `disable_notification` | Supported for these fields |
| `getMe` | returns a cached `user` object | Request-compatible: writes MTProto `users.getFullUser`; host decodes the result |
| `sendMessage` | `chat_id`, topic/reply, options, markup, arbitrary content | Text subset: standard `chat_id`, nested options and reply are accepted; cache and host-generated `random_id` are required; no media/topic/markup |
| `getChatHistory` | `chat_id`, `from_message_id`, offset, limit, `only_local` | Network subset: all fields are parsed; `chat_id` needs `EntityCache`, `only_local=true` is rejected |
| `getChat`, `getUser` | offline cache-backed `chat`/`user` result | Request-compatible translator: emits MTProto lookup; host decodes result and maintains cache |
| `getMessages`, `deleteMessages` | int53 chat/message IDs and result objects | Request-compatible for Telegram int32 message IDs (max 16); host handles results |
| `editMessageText` | reply markup plus `inputMessageContent` | Text subset: standard chat/message IDs and `inputMessageText`; no markup |
| `readHistory` | no current 1:1 TDLib JSON method | TRLib extension for MTProto `messages.readHistory` |
| updates, results, `@extra`, `td_send`/`td_receive` | asynchronous responses and ordered cache updates | Absent: the host owns correlation, decoding, networking, and scheduling |

For a minimal migration, keep the TDLib method names and authorization-state
events, populate `EntityCache` from host update handling, and call
`write_request_with_random_id` for standard `sendMessage`. A client
that relies on TDLib's local chat/message database, media constructors, email/
QR/passkey login, or `@extra` correlation still needs a compatibility layer
above TRLib. See the [TDLib getting-started contract](https://core.telegram.org/tdlib/getting-started)
and [current class index](https://core.telegram.org/tdlib/docs/classes.html).

## Streaming schema generation

The generator reads one line at a time and emits constructor IDs plus static
field/flags metadata. It does not build an in-memory TL AST or parse TL at
runtime.

```bash
cargo run --locked -p tl-prefix-gen -- \
  --output crates/trlib-core/src/generated.rs \
  schemas/core.tl schemas/telegram_api.tl
scripts/check-generated.sh
```

`schemas/telegram_api.tl` records the exact upstream source revision. The
generator emits the complete metadata snapshot once; a deployment then leaves
unused namespaces out of the linked binary through `api-<namespace>` features.

## Benchmarks

Measured on **2026-08-07**, Linux `6.17.0-PRoot-Distro` aarch64, Rust
`1.93.1`, release profile `opt-level = "z"`, fat LTO, one codegen unit,
`panic = "abort"`, stripped symbols. Values are measurements, not an SLA.

### Linked size

Command: `scripts/bench-size.sh`. The probe includes `std` and stdout
formatting, so it is a conservative executable-level comparison rather than
the size of the `no_std` parser alone.

| Linked probe | ELF file | `.text + .data + .bss` | Delta from core |
|---|---:|---:|---:|
| intermediate core | 332,496 B | 299,582 B | baseline |
| core + MTProto crypto | 332,496 B | 322,510 B | +22,928 B |
| core + TDLib adapter/session path | 1,184,464 B | 1,176,394 B | +876,812 B |

The identical on-disk ELF lengths are alignment artifacts. `size` reports the
actual linked sections. The TDLib path is intentionally opt-in; a native build
does not absorb that delta.

### Local hot path

The base probe calls `CoreGateway::poll` 10,000,000 times on a 44-byte
intermediate frame (framing + plain envelope + TL prefix). Five runs produced
`49.005`, `48.996`, `48.664`, `48.690`, and `48.618 ns/frame`.

| Metric | Result |
|---|---:|
| median | 48.690 ns/frame |
| estimated single-core throughput | 20.4 M frames/s |

Fixed state sizes on this 64-bit target: `Error` 12 B, `GatewayConfig` 16 B,
`CoreGateway` 32 B, and an optional 32-entry replay window 264 B. Network
buffers and caller-owned session scratch are not included.

### Telegram test DC smoke/latency probe

`tg-test-dc` establishes fresh TCP connections to test DC 2, sends the
official `req_pq_multi#be7e8ef1`, parses `resPQ#05162463` without copying,
checks the echoed nonce, and counts advertised RSA fingerprints. It does not
need an API ID, telephone number, or auth key.

```bash
cargo run --locked --release -p tg-test-dc -- \
  --rounds 10 --timeout-ms 8000 --json
```

Actual run recorded on 2026-08-06 against `149.154.167.40:80`:

| Metric, 10 fresh connections | Result |
|---|---:|
| median TCP connect | 69.445 ms |
| median connect + `resPQ` | 133.805 ms |
| p95 connect + `resPQ` | 152.994 ms |
| verified responses | 10/10 |
| advertised RSA fingerprints | 3 |

## Security and verification

The base crate has no dependencies. Optional MTProto/session crypto uses only
small `no_std` RustCrypto crates: `aes`, `sha2`, `subtle`, and `zeroize`.
There is no `serde`, Tokio, SQL engine, TLS stack, or async runtime.

- `unsafe` is forbidden at crate level.
- TL lengths and offsets are bounds checked; TL bytes require canonical length
  encoding and zero padding.
- Encrypted MTProto bodies require authenticated AES block alignment and
  12–1024 bytes of padding.
- `msg_key` and session-document tags are compared in constant time.
- MTProto plaintext is wiped after failed `msg_key` verification; document
  scratch is wiped after failed authentication.
- The session key, derived document keys, temporary tags, and AES material are
  zeroized.

Run the checks:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check -p trlib-core --no-default-features
cargo test -p trlib-core --no-default-features --features api
cargo test -p trlib-core --no-default-features \
  --features api,crypto-rustcrypto,session-document,session-file,tdlib-compat
scripts/check-generated.sh
```

TRLib is MIT licensed.

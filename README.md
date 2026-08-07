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
- Optional `auth-key` feature with a fixed-memory, `no_std`/`no_alloc` RSA/DH
  MTProto 2.0 authorization-key handshake. Entropy and I/O are supplied by the
  host through `RandomSource`; `std` is not enabled by this feature.
- A streaming generator for the vendored full Telegram API schema from
  [`TGScheme/Schema`](https://github.com/TGScheme/Schema), pinned at
  `5e961c4673acfc5b921dd18ffdd5a02eda0e8143` (Layer 229), with per-namespace
  Cargo features.
- Feature-gated writers and zero-copy response views for phone-code login,
  account state, update state, history, direct text messages, and arbitrary raw
  schema methods.
- A lightweight encrypted text session document instead of SQLite.

## Scope and honest boundaries

TRLib is a Core Gateway. The host application supplies networking, scheduling,
random bytes, API credentials, DC endpoints, and retry policy. It currently
supports API phone-code login once an MTProto authorization key already exists:
`auth.sendCode`, `auth.signIn`, `auth.signUp`, `account.getPassword`, and
host-supplied SRP proof values for `auth.checkPassword`.

SRP big-integer password proof calculation, file locking/atomic rename, media
transfer, DC migration executor, and TDLib's full JSON/object/database surface
are intentionally outside this small core. The response parser does expose
`*_MIGRATE_<dc>` errors so the host can implement a migration policy. The
`auth-key` handshake is complete for the pinned Test DC key and current safe
DH prime; production deployments should pin their own current RSA keys.

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
auth_key = false
api = false
auth = false
session_document = false
session_file = false
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
| `auth_key` | RSA_PAD, PQ factorization, encrypted DH and auth-key verification | adds `crypto-bigint` and `sha1`; still `no_std`/no-alloc |
| `api` | selected non-login Telegram API writers/views | none |
| `auth` | code-login writers and borrowed login result parsers | enables `api` |
| `session_document` | AES-CTR + HMAC encrypted session codec | enables crypto |
| `session_file` | blocking `std::fs` helpers for the text document | enables session document + `std` |

For example, a native minimal update gateway leaves the last five flags off.
`CompiledFeatures` can be queried at runtime to report the exact linked feature
bitset.

The local Test DC login probe is a separate `std` binary. It reads API ID, API
hash, phone number and the one-time code from stdin, creates the authorization
key with `auth-key`, sends `auth.sendCode`/`auth.signIn`, and then calls
`users.getFullUser` (`getMe`):

```bash
cargo run --release -p tg-test-login
```

Set `TRLIB_TEST_DC` to override the Test DC address. The binary does not print
the authorization key; use `session-file` in an embedding application when a
file-backed encrypted session is needed.

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

The identical on-disk ELF lengths are alignment artifacts. `size` reports the
actual linked sections. Optional modules stay out of native builds unless
their Cargo features are explicitly enabled.

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

### Authorization-key/login smoke

The new `auth-key` path was exercised against the same Test DC on 2026-08-07:
the RSA/PQ/DH exchange reached `dh_gen_ok`, the encrypted session was accepted,
and `auth.sendCode` returned the server's phone-code response. The probe then
waits at `Login code:`; the code is never hard-coded or echoed by TRLib. A run
with an intentionally empty code reached Telegram's expected `PHONE_CODE_INVALID`
response, confirming the encrypted `auth.signIn` request path. Enter a real
Test DC code locally to complete login and the follow-up `getMe` call.

## Security and verification

The base crate has no dependencies. Optional MTProto/session crypto and
authorization-key creation use small `no_std` RustCrypto crates: `aes`,
`sha1`, `sha2`, `crypto-bigint`, `subtle`, and `zeroize`.
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
- `auth-key` rejects unknown RSA fingerprints, validates the pinned safe DH
  prime, checks `g_a`/`g_b` bounds, authenticates the encrypted DH answer, and
  zeroizes handshake secrets on drop.

Run the checks:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check -p trlib-core --no-default-features
cargo test -p trlib-core --no-default-features --features api
cargo test -p trlib-core --no-default-features \
  --features api,crypto-rustcrypto,session-document,session-file
scripts/check-generated.sh
```

TRLib is MIT licensed.

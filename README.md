# TRLib

Экспериментальное ultra-low-footprint ядро MTProto 2.0 на Rust. TRLib не
переносит UI, файловый кэш, SQLite и объектную модель TDLib. Ядро получает
буфер от внешнего reactor, разбирает его без копирования и возвращает borrowed
views с временем жизни исходного буфера.

> Статус: foundation/MVP. TCP framing, plain/encrypted envelopes, session
> crypto, MTProto service objects и первый живой шаг auth handshake работают.
> Полный DH/RSA handshake, вход пользователя, DC migration и полный Telegram
> API layer пока не реализованы. Не используйте проект с production auth keys
> до независимого security-аудита и differential fuzzing с TDLib.

## Что уже есть

- `#![no_std]`, `#![forbid(unsafe_code)]` и **0 внешних зависимостей** в базовой сборке;
- zero-copy `Cursor<'a>`, `TlBytes<'a>`, `TlString<'a>` и сериализация в
  предоставленный вызывающей стороной `&mut [u8]`;
- runtime-independent `CoreGateway::poll`: без сокетов, executor и внутреннего
  receive buffer;
- object-safe `dyn Framing`, чтобы выбор transport не размножал generic-код;
- abridged и intermediate TCP transport;
- plain, encrypted и decrypted MTProto 2.0 envelope с проверками размеров;
- `msg_container`, `rpc_result`, `msgs_ack`, `pong`, `bad_server_salt` и другие
  service objects;
- borrowed routing для `updateNewMessage`, `updateNewChannelMessage`, edit
  updates и вложенных `Message`/`MessageService`;
- фиксированное replay window без heap;
- опциональный `crypto-rustcrypto`: MTProto 2.0 SHA-256 KDF/message-key,
  AES-256-IGE in-place, constant-time проверка и zeroize временных ключей;
- streaming TL prefix generator: одна строка схемы на входе, одна константа на
  выходе, без AST схемы в памяти;
- текстовый pre-build конфиг, который физически исключает невыбранные modules.

Путь одного пакета:

```text
caller-owned socket buffer
        │
        ▼
  dyn Framing ──► CoreGateway::poll ──► ExternalEnvelope<'a>
                                              │
                     ┌────────────────────────┴──────────────────────┐
                     ▼                                               ▼
              PlainEnvelope<'a>                       encrypted_data: &'a [u8]
                     │                                               │
                     ▼                                      optional in-place crypto
              auth/TL parser                                         │
                                                                     ▼
                                                     service/update/message view<'a>
```

## Сборка под конкретное приложение

Перед сборкой отредактируйте [`trlib.conf`](trlib.conf):

```ini
package = trlib-core
release = true
std = false
service = true
transport_abridged = false
transport_intermediate = true
crypto_rustcrypto = false
```

Затем:

```bash
cargo build --locked --release -p trlib-build
./target/release/trlib-build --config trlib.conf
```

`trlib-build` — dependency-free parser. Он запускает Cargo с
`--no-default-features` и только выбранными features. Поэтому, например,
`transport_abridged = false` не оставляет abridged dispatch в `.text`, а
`crypto_rustcrypto = false` даже не собирает криптографические зависимости.

Доступные compile-time switches:

| Настройка | Что попадает в сборку |
|---|---|
| `std` | интеграция со стандартной библиотекой; ядру не обязательна |
| `service` | MTProto service objects и message-update routing |
| `transport_abridged` | abridged TCP framing |
| `transport_intermediate` | intermediate TCP framing |
| `crypto_rustcrypto` | AES-256-IGE, SHA-256, constant-time compare, zeroize |

## Использование без async runtime

```rust
use trlib_core::config::GatewayConfig;
use trlib_core::gateway::{CoreGateway, GatewayPoll};
use trlib_core::transport::Intermediate;

let gateway = CoreGateway::new(&Intermediate, GatewayConfig::LOW_MEMORY);

// Один раз отправить gateway.stream_init_bytes(), затем передавать сюда
// текущий непрерывный prefix внешнего receive buffer.
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

`CoreGateway` не владеет буфером: его можно вызывать из epoll/io_uring,
embedded loop, thread-per-core или любого async runtime. В hot path нет
`Vec`, `String`, `Box`, `Arc` и скрытых `.clone()` больших пакетов.

## TL codegen без AST

```bash
cargo run --locked -p tl-prefix-gen -- \
  schemas/core.tl crates/trlib-core/src/generated.rs
scripts/check-generated.sh
```

Генератор читает схему через `BufRead::read_line` и сразу пишет только
`ConstructorId`. Типизированные parsers используют `tl_constructor!` и читают
поля непосредственно из `Cursor<'a>`. Полная схема не хранится в памяти ни как
AST, ни как таблица runtime-reflection.

## Benchmarks

Измерено **2026-08-06** на Linux aarch64
(`6.17.0-PRoot-Distro`, `rustc 1.93.1`). Профиль: `opt-level = "z"`, fat LTO,
`codegen-units = 1`, `panic = "abort"`, stripped symbols. Сетевые числа зависят
от маршрута до Telegram и не являются SLA.

### Размер

Команда: `scripts/bench-size.sh`.

| Конфигурация linked probe | Файл ELF | `.text + .data + .bss` | Разница |
|---|---:|---:|---:|
| intermediate gateway, без crypto | 332,496 B | 299,542 B | baseline |
| intermediate gateway + `crypto-rustcrypto` | 332,496 B | 322,470 B | +22,928 B |

Одинаковый размер ELF на диске вызван выравниванием секций; команда `size`
показывает реальную разницу linked sections. Probe включает Rust `std` и
форматирование stdout, поэтому это верхняя граница для кода, а не размер
самого `no_std` parser.

Размер фиксированного состояния на 64-bit target:

| Тип | Размер |
|---|---:|
| `Error` | 12 B |
| `GatewayConfig` | 16 B |
| `CoreGateway` | 32 B |
| optional 32-entry `MessageIdWindow` | 264 B |

Caller-owned network buffers в эти числа не входят.

### Локальный hot path

`size-probe` выполняет 10,000,000 вызовов `CoreGateway::poll` над 44-byte
intermediate frame: framing + plain MTProto envelope + доступ к TL prefix.

| Метрика | Результат |
|---|---:|
| median пяти запусков | 77.308 ns/frame |
| расчётная пропускная способность одного ядра | 12.9 M frames/s |

Воспроизведение:

```bash
target/size-base/release/size-probe
```

### Живой Telegram test DC

`tg-test-dc` устанавливает новое TCP-соединение с test DC 2, отправляет
официальный `req_pq_multi#be7e8ef1`, zero-copy разбирает
`resPQ#05162463`, проверяет echoed nonce и список RSA fingerprints. API ID,
номер телефона и auth key не нужны.

```bash
cargo run --locked --release -p tg-test-dc -- \
  --rounds 10 --timeout-ms 8000 --json
```

Фактический запуск против `149.154.167.40:80`:

| Метрика, 10 новых соединений | Результат |
|---|---:|
| median TCP connect | 65.979 ms |
| median connect + `resPQ` | 129.052 ms |
| p95 connect + `resPQ` | 151.918 ms |
| проверенных ответов | 10/10 |
| RSA fingerprints в ответе | 3 |

Формат MTProto 2.0 сверяется с официальными документами Telegram:
[protocol description](https://core.telegram.org/mtproto/description) и
[authorization-key handshake](https://core.telegram.org/mtproto/auth_key).

## Зависимости и безопасность

База: ни одной зависимости. Опциональный crypto backend имеет четыре прямые
малые `no_std`-совместимые зависимости: `aes`, `sha2`, `subtle`, `zeroize`.
`serde`, `tokio`, proc-macro runtime и TLS stacks отсутствуют.

Проверяемые invariants:

- все длины и арифметика offsets bounds-checked;
- TL lengths должны иметь canonical encoding, padding проверяется;
- encrypted payload кратен AES block size;
- decrypted payload требует MTProto 2.0 padding 12..1024 bytes;
- входящий `msg_key` сравнивается constant-time после decrypt;
- plaintext обнуляется при authentication failure;
- AES key/IV и временные digest buffers обнуляются;
- message-id parity/time window и fixed replay window доступны ядру;
- production library запрещает `unsafe` на уровне crate lint.

Проверки:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check -p trlib-core --no-default-features
cargo test -p trlib-core --no-default-features --features crypto-rustcrypto
scripts/check-generated.sh
```

## Следующие milestones

1. Feature-gated RSA-PAD + DH auth-key handshake с проверкой safe prime.
2. Streaming codegen parsers для выбранного Telegram API layer вместо полного
   runtime-reflection; неизбранные constructors не генерируются.
3. Fixed-capacity RPC correlation/ACK/session state, storage предоставляется
   приложением.
4. Obfuscated transport, DC migration и reconnect state machine.
5. Differential tests и fuzz corpus против TDLib, затем внешний security audit.

TRLib распространяется по лицензии MIT.

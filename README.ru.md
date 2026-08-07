# TRLib

TRLib — небольшой, независимый от runtime Rust Core Gateway для MTProto 2.0.
Он рассчитан на высоконагруженные Telegram-бэкенды, которым нужны borrowed
TL-парсинг, ограниченная память и контроль размера бинарника через feature,
а не полная копия TDLib.

[English documentation](README.md) · [Публичный репозиторий](https://github.com/tdd761914-arch/TRLib)

## Что реализовано

- Zero-copy TL-примитивы: `Cursor<'a>`, `TlBytes<'a>`, `TlString<'a>`, raw
  boxed-объекты и сериализация в буферы вызывающего кода.
- Инкрементальный abridged/intermediate TCP framing, plain/encrypted MTProto
  envelopes. Ядро не владеет ни сокетом, ни receive-buffer.
- Опциональная MTProto 2.0 crypto: AES-256-IGE/SHA-256 и шифрование готового
  исходящего пакета непосредственно в final buffer.
- Отдельная `auth-key` feature с полным RSA/DH MTProto 2.0 handshake в
  фиксированной памяти, `no_std` и `no_alloc`. Энтропию и I/O передаёт host
  через `RandomSource`; эта feature не включает `std`.
- Потоковый генератор полной vendored Telegram API-схемы из
  [`TGScheme/Schema`](https://github.com/TGScheme/Schema), зафиксированной на
  `5e961c4673acfc5b921dd18ffdd5a02eda0e8143` (Layer 229), с отдельными
  Cargo-фичами по namespace.
- Feature-gated writers и zero-copy views для phone-code login, account/update
  state, history, простых text messages и raw вызова любого метода схемы.
- Лёгкий зашифрованный текстовый документ сессии вместо SQLite.

## Границы реализации

TRLib — Core Gateway. Сеть, планирование, случайные байты, API credentials,
адреса DC и retry-policy передаются embedding-приложением. Сейчас поддержан
phone-code API-login после того, как MTProto authorization key уже существует:
`auth.sendCode`, `auth.signIn`, `auth.signUp`, `account.getPassword` и
`auth.checkPassword` с предоставленными хостом SRP proof values.

Вычисление SRP password proof на big integer, file locking/atomic rename, media
transfer, исполнитель DC migration и полный JSON/object/database surface TDLib
намеренно не входят в малое ядро. Парсер отдаёт `*_MIGRATE_<dc>`, поэтому хост
может реализовать свою миграционную политику. `auth-key` полностью выполняет
handshake для pinned Test DC RSA key и текущего safe DH prime; для production
нужно добавить собственные pinned RSA keys.

## Текстовый конфиг перед сборкой

`trlib.conf` — простой build manifest, читаемый до запуска Cargo:

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

Сборка:

```bash
cargo run --locked -p trlib-build -- --config trlib.conf
```

| Ключ | Что добавляется | Зависимости |
|---|---|---|
| `service` | MTProto service objects и borrowed updates | нет |
| `transport_abridged` | abridged TCP | нет |
| `transport_intermediate` | intermediate TCP | нет |
| `crypto_rustcrypto` | AES-256-IGE, SHA-256, constant-time verify | четыре малых `no_std` RustCrypto crate |
| `auth_key` | RSA_PAD, факторизация PQ, зашифрованный DH и проверка auth key | добавляет `crypto-bigint` и `sha1`, но остаётся `no_std`/no-alloc |
| `api` | выбранные non-login API writers/views | нет |
| `auth` | code-login writers и login response parsers | включает `api` |
| `session_document` | AES-CTR + HMAC текстовая сессия | включает crypto |
| `session_file` | blocking `std::fs` helpers | включает документ + `std` |

Для нативного малого update gateway последние пять ключей остаются `false`.
`CompiledFeatures` позволяет отдать текущий bitset скомпилированных
возможностей в diagnostics/metrics.

Локальный Test DC login probe — отдельный `std` binary. Он читает из stdin API
ID, API hash, телефон и одноразовый код, создаёт auth key через `auth-key`,
вызывает `auth.sendCode`/`auth.signIn`, а после успешного входа вызывает
`users.getFullUser` (`getMe`):

```bash
cargo run --release -p tg-test-login
```

Адрес можно переопределить через `TRLIB_TEST_DC`. Authorization key не печатается;
для файловой сессии используйте `session-file` в embedding-приложении.

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

Парсер заимствует данные из `receive_buffer`: в packet hot path не создаются
`Vec`, `String`, `Arc`, `Box` или скрытые clone body.

## API и login flow

`api` содержит raw escape hatch для каждого конструктора схемы:

```rust
use trlib_core::api::RawMethod;
use trlib_core::tl::{ConstructorId, Writer};

let method = RawMethod::new(ConstructorId::new(0x1234_5678), preencoded_fields);
let mut writer = Writer::new(&mut output);
method.write(&mut writer)?;
```

С `auth` phone-flow строится без аллокации: `initConnection` и
`auth.sendCode` пишутся сразу в final packet body, затем хост отправляет его
через существующую encrypted MTProto session. После `auth.sentCode` хост
сохраняет `phone_code_hash` в своей памяти и сериализует `auth.signIn` либо
`auth.signUp`.

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

`write_check_password` принимает `srp_id`, `A` и `M1`, созданные внешней
проверенной SRP-реализацией. Большая big-integer зависимость не прячется в
каждой сборке TRLib.

## Зашифрованный текстовый документ сессии

При `session_document` создаётся документ фиксированной длины:

```text
TRLib-session-v1
salt=…32 lowercase-hex characters…
data=…AES-CTR ciphertext in lowercase hex…
tag=…HMAC-SHA-256 in lowercase hex…
```

На каждую запись хост передаёт свежий случайный 16-byte salt. Документ
использует AES-256-CTR для шифрования и encrypt-then-HMAC-SHA-256 с разными
производными ключами. Все scratch buffer принадлежат вызывающему коду;
результат `SessionRecordRef` заимствует 256-byte MTProto auth key из
decrypted scratch. Нет SQLite, allocator или framework сериализации.

Для пароля доступен PBKDF2-HMAC-SHA-256 `SessionKey`: сначала прочитайте
публичный salt через `document_salt`, затем выведите ключ. Для сервисов лучше
использовать случайный 32-byte secret из platform key store. `session_file` добавляет
blocking `save`/`load`; владелец приложения отвечает за private directory,
atomic replace и lock при нескольких writers.

## Потоковая генерация схемы

Генератор читает TL-схему построчно и пишет constructor ID вместе со статическими
metadata полей и flags. Он не создаёт in-memory AST и не парсит TL в runtime:

```bash
cargo run --locked -p tl-prefix-gen -- \
  --output crates/trlib-core/src/generated.rs \
  schemas/core.tl schemas/telegram_api.tl
scripts/check-generated.sh
```

`schemas/telegram_api.tl` хранит точную upstream revision. Генератор один раз
создаёт полные metadata, а конкретная сборка исключает ненужные namespace через
фичи `api-<namespace>`.

## Бенчмарки

Измерено **2026-08-07** на Linux `6.17.0-PRoot-Distro` aarch64, Rust `1.93.1`.
Профиль: `opt-level = "z"`, fat LTO, один codegen unit, `panic = "abort"`,
stripped symbols. Это измерения, а не SLA.

### Размер linked binary

Команда: `scripts/bench-size.sh`. Probe включает `std` и stdout formatting,
поэтому это консервативное executable-level сравнение, а не размер одного
`no_std` parser.

| Linked probe | ELF file | `.text + .data + .bss` | Разница от core |
|---|---:|---:|---:|
| intermediate core | 332,496 B | 299,582 B | baseline |
| core + MTProto crypto | 332,496 B | 322,510 B | +22,928 B |

Одинаковый размер ELF на диске — эффект выравнивания. `size` показывает
реальные linked sections. Неиспользуемые модули не попадают в native build без
явного Cargo feature.

### Local hot path

Base probe выполняет 10,000,000 вызовов `CoreGateway::poll` над 44-byte
intermediate frame (framing + plain envelope + TL prefix). Пять запусков:
`49.005`, `48.996`, `48.664`, `48.690`, `48.618 ns/frame`.

| Метрика | Результат |
|---|---:|
| median | 48.690 ns/frame |
| расчётная пропускная способность одного ядра | 20.4 M frames/s |

Фиксированное состояние на 64-bit target: `Error` 12 B, `GatewayConfig` 16 B,
`CoreGateway` 32 B, опциональный 32-entry replay window 264 B. Network buffer
и caller-owned session scratch в эти числа не входят.

### Telegram test DC smoke/latency

`tg-test-dc` открывает новые TCP-соединения с test DC 2, отправляет
`req_pq_multi#be7e8ef1`, zero-copy разбирает `resPQ#05162463`, сверяет nonce и
считает RSA fingerprints. API ID, телефон и auth key не нужны.

```bash
cargo run --locked --release -p tg-test-dc -- \
  --rounds 10 --timeout-ms 8000 --json
```

Фактический запуск 2026-08-06 против `149.154.167.40:80`:

| Метрика, 10 новых соединений | Результат |
|---|---:|
| median TCP connect | 69.445 ms |
| median connect + `resPQ` | 133.805 ms |
| p95 connect + `resPQ` | 152.994 ms |
| проверенных ответов | 10/10 |
| advertised RSA fingerprints | 3 |

### Smoke авторизационного ключа и login

Новый `auth-key` path проверен против того же Test DC 2026-08-07: RSA/PQ/DH
обмен дошёл до `dh_gen_ok`, encrypted session приняла серверная сторона, а
`auth.sendCode` вернул phone-code response. Затем probe останавливается на
`Login code:`; код не зашит и не выводится TRLib. Запуск с намеренно пустым
кодом дошёл до ожидаемого Telegram ответа `PHONE_CODE_INVALID`, то есть
зашифрованный `auth.signIn` path работает. Для полного входа введите реальный
Test DC код локально; после этого вызывается `getMe`.

## Безопасность и проверка

Базовый crate не имеет зависимостей. Опциональные MTProto/session crypto и
создание authorization key используют малые `no_std` RustCrypto crate: `aes`,
`sha1`, `sha2`, `crypto-bigint`, `subtle`, `zeroize`. Нет `serde`, Tokio, SQL
engine, TLS stack или async runtime.

- `unsafe` запрещён на уровне crate.
- TL length/offset bounds-checked; TL bytes требуют canonical length и нулевой
  padding.
- Encrypted MTProto body требует корректный AES block alignment и 12–1024 B
  padding.
- `msg_key` и session-document tags сверяются constant-time.
- MTProto plaintext стирается после неверного `msg_key`; document scratch —
  после failed authentication.
- Session key, derived document keys, временные tags и AES material zeroize.
- `auth-key` отклоняет неизвестные RSA fingerprints, проверяет pinned safe DH
  prime, границы `g_a`/`g_b`, аутентифицирует encrypted DH answer и стирает
  секреты handshake при `drop`.

Проверки:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check -p trlib-core --no-default-features
cargo test -p trlib-core --no-default-features --features api
cargo test -p trlib-core --no-default-features \
  --features api,crypto-rustcrypto,session-document,session-file
scripts/check-generated.sh
```

Лицензия TRLib — MIT.

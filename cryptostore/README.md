# cryptostore

Уніфіковані сховища для шифрованих даних Webitel поверх [cryptobox](../cryptobox).
Ядро описує, **як** значення перетворюється на самопозначений шифр (`Codec`), **де**
він фізично лежить (`Store` + реєстр DSN-схем) і **як** його мігрувати при ротації
ключів (`Migration`) — без розкриття ключів у запитах до сховища.

Шифрування/дешифрування **повністю в коді** — матеріал ключів ніколи не потрапляє у SQL.

Конкретні сховища й record-орієнтований шар — окремі пакети/модулі:

| Пакет | Призначення |
|---|---|
| **`cryptostore`** (це ядро) | `Codec` (шифр значень + inline-кадр + blind-index токени), `Store`/`Migration`, реєстр DSN-схем + `OpenStore`, env-default `Default()` |
| [`cryptostore/schema`](./schema) | record-орієнтований кодек: декларативна схема полів (`unit → field → policy`) над `Codec`; шифрує іменовані поля записів і заповнює `__cs_idx` |
| [`cryptostore/postgres`](./postgres) | `Store` над pgx: `Usage`/`Migrate` через SQL-функції `cryptostore_*`; DSN-схема `postgres` |
| [`cryptostore/blobstore`](./blobstore) (+ [`/gocloud`](./blobstore/gocloud)) | об'єктне сховище: envelope-DEK + потоковий шифр; локальна тека (`blobfs`) + хмара (`s3`/`gs`/`file`/`mem`) |
| [`cmd/cryptoctl`](../cmd/cryptoctl) | CLI-агент над сховищами (`status`/`usage`/`migrate`/`can-retire` + crypto-команди) |

## Встановлення

```bash
go get github.com/webitel/crypto/cryptostore
```

## Модель: inline, self-marking ciphertext

`Codec` віддає шифр, який **сам себе позначає** як шифр, тож шифровані й «легасі»
відкриті значення співіснують в одній колонці/атрибуті, а міграція — поступова (без
окремої companion-колонки). Маркер — лише дешевий фільтр; **арбітр — AEAD-автентифікація**.

Один cryptobox-блоб (несе версію ключа, KID) у двох транспортних кодуваннях:

- **bytea-колонка** — `binTag(\x00 \x01) ‖ blob`. Провідний `NUL` не трапляється у
  значенні з `text`-колонки (текст не містить NUL), тож маркер однозначний; 2-й байт —
  версія формату кадру (**НЕ** алгоритм — він імпліцитний у cryptobox `Box`).
- **json-атрибут / text** — `"cbox:" ‖ base64(blob)`, JSON-безпечний рядок. Тег
  опаковий, без in-band версії: зміна розкладки реєструє **новий** тег, а не бампає цифру.

На читанні: framed-bytea, що не відкривається, — це **помилка** (пошкодження: провідний
NUL не міг бути в колишньому тексті); framed-text, що не відкривається, — **відкат** до
легасі-plaintext (тег `cbox:`, на відміну від NUL, міг би випадково збігтися з валідним
рядком). Розкладка детально — [docs/inline-encryption.md](./docs/inline-encryption.md).

## Codec

`Codec` — storage-agnostic, value-oriented ядро: шифрує/дешифрує **окремі значення**
(з inline-кадром) і дає детерміновані blind-index токени. Він нічого не знає про
таблиці, колонки чи об'єкти — це будують шари вище.

```go
import (
    "github.com/webitel/crypto/cryptobox"
    "github.com/webitel/crypto/cryptostore"
)

// cipher — cryptobox.Box над keyring (значення шифруються ним; KID — у заголовку blob).
ring, _ := cryptobox.ParseKeyring("correct-horse-battery-staple-2025!")
box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)

// index — НЕЗАЛЕЖНИЙ keyring для blind-index (щоб ротація cipher-ключів не ламала
// токени пошуку). nil → пошук вимкнено, SearchToken повертає ErrIndexKey.
indexRing, _ := cryptobox.ParseKeyring(os.Getenv("CRYPTO_SEARCH_KEYRING"))

codec, _ := cryptostore.NewCodec(box, indexRing)
```

- `Encrypt`/`Decrypt` — bytea-кадр (self-marking); `EncryptText`/`DecryptText`/`RecryptText` — json-кадр.
- `Cipher()` — сирий, безкадровий cryptobox (напр. загорнути per-object DEK).
- `SearchToken(ctx, domain, data)` — детермінований токен, scoped до `domain` (різні домени не колізять).
- `PrimaryKID(ctx)` — поточна primary-версія ключа (та, якою шифрує `Encrypt`); `CanIndex()` — чи є index-keyring.

Record-орієнтоване API (шифрування іменованих полів записів + `__cs_idx`) будується
над `Codec` у [`cryptostore/schema`](./schema).

### env-default (без ручного складання keyring'ів)

Щоб сервіс не збирав ланцюг keyring → Box → Codec вручну, ключі беремо з середовища:

```go
codec, err := cryptostore.Default() // процес-глобальний *Codec, меморизований sync.Once
```

| Змінна | Призначення |
|---|---|
| `CRYPTO_CIPHER_{KEYRING,KEYFILE}` | keyring для шифрування значень (**обов'язково**) |
| `CRYPTO_SEARCH_{KEYRING,KEYFILE}` | keyring для blind-index (опційно; відсутній → пошук вимкнено) |
| `CRYPTO_DIR` | системна тека (дефолт `/var/lib/cryptoctl`) |

`_KEYRING` містить ключі inline (розділювач — новий рядок або кома), `_KEYFILE` — шлях
до файлу. **Системний фолбек:** якщо не задано ні env, ні `_KEYFILE`, читаються добре
відомі файли `<CRYPTO_DIR>/.cipher` і `/.search` — тож devops наповнює теку, і сервіс
працює без жодних змінних. Порядок: env → системний файл. (`.cipher`-фолбек живе у
`cryptobox.Default`, тож будь-який сервіс на cryptobox його підхоплює; `.search` —
тут, через `cryptostore.SearchKeys`.) Для нестандартних ключів — `cryptobox.NewKeyring` +
`cryptostore.NewCodec`.

## Store і Migration

`Store` — інтерфейс конкретного сховища (де фізично лежить шифр). Реалізації — у
підмодулях ([`postgres`](./postgres), [`blobstore`](./blobstore)). Спільне для всіх —
метрики по ключах і міграція під єдиним `Migration`:

```go
mig := cryptostore.NewMigration(store)
usage, _ := mig.Usage(ctx)                 // map[KID]KeyUsage{Count} — частка по ключу
mig.Run(ctx, cryptostore.MigrateOptions{BatchSize: 500, RatePerSec: 2000})
ok, _ := mig.CanRetire(ctx, 1)             // true → ключ безпечно вивести (cryptobox ring.Retire(1))
```

Ротація **opportunistic**: `Encrypt` завжди бере primary, тож будь-який природний
`UPDATE`/`INSERT` перешифровує запис безкоштовно; `Migration.Run` доганяє рештки —
батчами, резюмабельно, з CAS по старій версії ключа. **Без contract-фази** — оригінали
не дропимо, plaintext витісняється шифром на місці. `CanRetire(kid)` каже, чи на ключі
ще лишились дані.

## Реєстр сховищ (DSN-схема → драйвер)

`OpenStore` відкриває **одне** сховище за схемою його DSN. DSN має вигляд
`<scheme>[:opaque]` (`postgres://…`, `blobfs:/var/lib/x`, `s3://bucket` чи голий
`postgres`). **Схема** (частина до першого `:`, через `cryptostore.Scheme`) обирає
драйвер; **opaque** — рядок драйвера (ядро його не валідує). Драйвер реєструється у
своєму `init()`, тож його підключають імпортом-для-side-effect:

```go
import (
    "github.com/webitel/crypto/cryptostore"
    _ "github.com/webitel/crypto/cryptostore/postgres"          // схема "postgres"
    _ "github.com/webitel/crypto/cryptostore/blobstore/gocloud" // схеми s3/gs/file/mem
)

codec, _ := cryptostore.Default() // ключі з env
st, _ := cryptostore.OpenStore(ctx, cryptostore.StoreOptions{
    DSN:       "postgres://user:pass@localhost:5432/db",
    Name:      "pg:main",
    Codec:     codec,
    SchemaRaw: []byte(`{"version":1,"units":{"directory.users":{"fields":{"email":{"search":true}}}}}`),
})
```

`StoreOptions` несе `*Codec`, повний `DSN`, сирий конфіг-блок (`ConfigRaw` — параметри
поза DSN), сиру схему (`SchemaRaw`), verbose-прапорець і `BaseDir` (тека конфіг-файлу).
Драйвер прив'язує відносний шлях через `opts.Resolve(path)` — відносно конфіг-файлу, не
CWD. Сховища **з однаковим DSN шерять одне підключення** (див. [`postgres`](./postgres) —
один пул на БД). Багатосховищний агент, що збирає все з конфіг-файлів і веде за єдиною
`Migration`, — окремий CLI [`cmd/cryptoctl`](../cmd/cryptoctl).

## Помилки

```go
errors.Is(err, cryptostore.ErrIndexKey) // index keyring відсутній / матеріал закороткий
```

Помилки схеми полів (`schema.ErrUnmanaged`, `ErrNotSearchable`, …) — у [`schema`](./schema).

## Тести

```bash
go test -race ./...   # ядро + schema
```

Postgres-інтеграційні тести запускаються лише за наявності DSN — див. [`postgres`](./postgres).

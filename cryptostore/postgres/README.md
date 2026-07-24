# cryptostore/postgres

`Store` над [pgx](https://github.com/jackc/pgx) для [`cryptostore`](..): тримає шифр inline
у наявних колонках, рахує розподіл даних по ключах і мігрує при ротації — метрики/міграція
на боці БД, через SQL-функції `cryptostore_*`. Реєструє DSN-схему **`postgres`**.

## Підключення

**In-service** — наявний пул сервісу:

```go
import "github.com/webitel/crypto/cryptostore/postgres"

// codec — *schema.Codec; "public" — Postgres-схема, де лежать SQL-функції.
store := postgres.New("pg:main", pool, codec, "public")
postgres.InstallFunctions(ctx, pool, "public") // один раз, ідемпотентно
```

**З конфігурації** — через реєстр ядра (імпорт-для-side-effect реєструє схему `postgres`):

```go
import _ "github.com/webitel/crypto/cryptostore/postgres"

st, _ := cryptostore.OpenStore(ctx, cryptostore.StoreOptions{
    DSN:  "postgres://user:pass@localhost:5432/db",
    Name: "pg:main", Codec: codec, SchemaRaw: schemaJSON,
})
```

Реєстровий шлях **шерить один reference-counted пул** на всі сховища з тим самим DSN
(багато сервісних схем — через одне підключення до БД) і сам ставить `InstallFunctions`
(ідемпотентно, бо `Config.Schema` може відрізнятися); пул закривається з останнім `Close`.
`pgxConnString` маппить DSN у рядок підключення pgx: порожній opaque (`postgres`/`postgres:`)
→ з libpq-env, `//…` → URL, інше → keyword-рядок.

`postgres.Config` (сирий конфіг-блок): `DSN`, `Name`, `Schema` (де лежать SQL-функції).

## SQL-функції (метрики/міграція на боці БД)

```go
postgres.InstallFunctions(ctx, db, "public")
```

- `cryptostore_kid(bytea)` → KID зі скалярного шифру; **NULL = plaintext** (заразом предикат
  «це шифр?»). Раджу функц.індекс: `CREATE INDEX ON t (cryptostore_kid(col))`.
- `cryptostore_kids(jsonb)` → SETOF KID з усіх шифрованих атрибутів документа.
- `cryptostore_pending(jsonb, primary_kid)` — предикат «треба мігрувати», що дзеркалить
  skip-правила кодека.

Функції розпізнають те саме framing (`\x00\x01` / `cbox:`), що й `frame.go` ядра — тримати
синхронними.

## Usage / Migrate

```go
mig := cryptostore.NewMigration(store)
usage, _ := mig.Usage(ctx) // GROUP BY cryptostore_kid(col) (скаляр) + cryptostore_kids (json); лише count
mig.Run(ctx, cryptostore.MigrateOptions{BatchSize: 500, RatePerSec: 2000}) // резюмабельно; DryRun лише рахує
```

`Migrate` працює по таблиці батчами: прогін рядків через кодек (decode→encode, що
перебудовує `__cs_idx`) + один set-based `UPDATE` через `unnest` з optimistic batch-CAS по
старих значеннях. Шифрує і plaintext (перше шифрування), і не-primary (ротація); пропускає
NULL/порожні; `MigrateResult.Recrypted` рахує рядки.

## Скалярні колонки

Колонки під шифрування заздалегідь переводяться у `bytea` (окремою міграцією БД); `json[b]`
лишається `json[b]`. **Не шифруються** PK / FK / UNIQUE та колонки, на яких тримаються view —
рандомізований AEAD ламає join/identity/uniqueness.

## Тести

```bash
CRYPTOSTORE_PG_DSN="postgres://user:pass@localhost:5432/db" go test ./... -v
```

Без DSN інтеграційні тести пропускаються. Перевірено на PG16.

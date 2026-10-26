# cryptoctl

CLI для експлуатації cryptostore: частка даних по ключах, міграція ключів,
перевірка «чи можна відкликати ключ», а також ручне розшифрування значення
(`decrypt`) і обчислення токена для точного пошуку (`search`).

Власних ключів не має: `Codec` береться з `cryptostore.Default` — той самий keyring
зі середовища, що й у сервісів, тож агент читає й переписує дані рівно тими ключами,
що й сервіс. Уся конфігурація зводиться до **набору сховищ**: по одному JSON/JSONC-файлу
на сховище у теці `store-dir`, кожне відкривається через `cryptostore.OpenStore` за
єдиною `Migration`. Види сховищ умикаються імпортом їхніх пакетів (postgres, blobstore)
заради side-effect реєстрації.

## Збірка

```bash
go build -o cryptoctl .
```

## Конфіг

cryptoctl **не має власного конфіга ключів** — вони приходять зі середовища (див.
«Ключі»). Уся конфігурація — це **набір сховищ**: по одному файлу на сховище у теці
store-dir. Файли — **JSON або JSONC** (коментарі `//`, `/* */` і висячі коми дозволені).

```bash
export CRYPTO_STORE_DIR=/etc/cryptostore/store.d    # прапорець --store-dir
export CRYPTO_SCHEMA_DIR=/etc/cryptostore/schema.d  # прапорець --schema-dir
```

- **`--store-dir`** (дефолт `store.d`) — тека з файлами сховищ, по одному
  `*.json`/`*.jsonc` на сховище. За замовчуванням підключаються **всі** файли теки.
  Зручно: правку роблять біля сервісу, а сюди файл просто копіюють. Якщо `name` не
  заданий — береться з імені файлу.
- **`--store <file>`** (можна повторювати) — підключити лише **вказані** файли з
  `store-dir` (з розширенням чи без: `directory` = `directory.jsonc`), а не всю теку.
  Значення з роздільником шляху / абсолютне береться як файл поза `store-dir`.
- **`--schema-dir`** (дефолт `schema.d`) — спільна тека файлів схем полів для
  record-сховищ (див. нижче).

```bash
cryptoctl status                                  # усі сховища з ./store.d
cryptoctl --store directory --store call_center status   # лише ці два (workflow лишається невживаним)
```

### Ключі

Два keyring-и (формат cryptobox) читаються **лише зі середовища** — так само, як у
сервісів, тож сервіс і агент бачать однаковий keyring:

| | env | системна тека (fallback) |
|---|---|---|
| **cipher** (шифрування значень) | `CRYPTO_CIPHER_{KEYRING,KEYFILE}` | `<SystemDir>/.cipher` |
| **search** (blind-index; primary дає токени пошуку) | `CRYPTO_SEARCH_{KEYRING,KEYFILE}` | `<SystemDir>/.search` |

search-ключ необов'язковий: якщо його немає ніде — пошук вимкнено. Ключі свідомо
**не** конфігуряться у cryptoctl і не шукаються в `$PWD`/поруч-із-бінарником: секрети
надходять з довіреного джерела (env або системна тека).

**Права доступу до файлів ключів.** Файл ключів (`*_KEYFILE`, `.cipher`, `.search`,
`/path`-ключі в keyring) має бути **приватним** — доступ лише власнику (плюс толерований
group-read для k8s `fsGroup`): `0600`, `0400`, `0640`, `0440`. За замовчуванням файл із
ширшими правами **відхиляється**. Послабити до попередження: прапорець **`--unsafe-keys`**
або `CRYPTO_KEYFILE_POLICY=unsafe`.

### Системна тека

`SystemDir` = `CRYPTO_DIR` або дефолт **`/var/lib/cryptoctl`** (на
Debian/systemd — `StateDirectory=cryptoctl`). Наповни її — і все працює без env:

```
/var/lib/cryptoctl/
├── .cipher       # cipher keyring   (фолбек після env)
├── .search       # search keyring   (фолбек після env)
├── store.d/      # конфіги сховищ   (фолбек для --store-dir)
└── schema.d/     # файли схем полів (фолбек для --schema-dir)
```

Порядок пошуку `store.d` / `schema.d` (коли шлях відносний): **поточна тека (`$PWD`)
→ тека cryptoctl → системна тека** (перша наявна). Це конфіг, тож локальне перекриває
системне. Абсолютний шлях у `--store-dir`/`--schema-dir` береться як є. **Ключі так НЕ
шукаються** — лише env або системна тека: секрети мають надходити з довіреного місця.

```jsonc
// store.d/directory.jsonc — одне сховище; name = "directory"
// dsn = <scheme>[:opaque]; схема обирає драйвер. Для порожнього opaque ("postgres:")
// pgx підхопить підключення з libpq-середовища (PGHOST, PGPORT, PGSERVICE, PGPASSFILE, …).
{
  "dsn": "postgres://user:pass@localhost:5432/db",
  "config": { "schema": "public" },
  "schema": {
    "version": 1,
    "units": { "public.users": { "fields": {
      "email":   { "search": true },
      "profile": { "nested": [ { "path": ["ssn"], "search": true }, "$.passport.number" ] }
    } } }
  }
}
```

```jsonc
// store.d/recordings.jsonc — name = "recordings"
{ "dsn": "blobfs:/data/secure" }
```

**Відносні шляхи у драйверах.** Файлові шляхи драйвера (тека `blobfs:<dir>`, шлях
`file://` bucket-URL, sqlite `catalog` у `config`) резолвляться **відносно теки
файлу сховища**, а не поточної робочої теки (`$PWD`). Тобто `blobfs:data/secure` у
`store.d/recordings.jsonc` дасть теку поруч із цим файлом, незалежно від того, звідки
запущено `cryptoctl`. Абсолютні шляхи беруться як є. (Ключі так не резолвляться —
вони лише з довірених джерел.)

### Кілька схем полів на одне підключення

Різні сервіси описують свої БД-схеми окремими `cryptostore/schema.Config` файлами
(лише поля, без підключення). Щоб застосувати їх усі до **однієї фізичної postgres** —
не редагуючи файли — секція `schema` сховища підтримує **include-режим** `{ "dir", "files" }`:
loader вантажить названі файли й зливає їх через `schema.MergeConfig` в одну зведену схему.

```jsonc
// store.d/pg.jsonc — одне підключення, схема зібрана з кількох файлів у --schema-dir
{
  "dsn": "postgres:",                 // підключення з env (PGHOST/…)
  "config": { "schema": "public" },
  "schema": { "files": ["directory.jsonc", "call_center.jsonc", "workflow.jsonc"] }
}
```

Просто скопіюй сервісні файли у `schema.d/` — юніти повнокваліфіковані
(`directory.users`, `call_center.agents`, …), тож злиття = об'єднання. Форми секції `schema`:

- `null` / `{}` — сховище **без схеми**;
- inline `{ "version":1, "units":{…} }` — схема прямо в конфізі;
- include `{ "dir":…, "files":[…] }` — **`files` обов'язкові**; `dir` опційна (дефолт —
  спільна `--schema-dir`, інакше `schema.d` поруч із файлом сховища). Абсолютні шляхи
  беруться як є.

**Baseline (незмінний мінімум).** Ops-збірка cryptoctl може вкомпілювати baseline —
пакет, що в `init()` викликає `schema.Register(cfg)`. Він мерджиться як
**запінена база** під будь-який адмін-overlay (`MergeConfig(Baseline, schema)`), тож
overlay може лише додавати/вмикати `search`, але не послаблює baseline. Драйвер postgres
лишається без baseline — сторонні postgres-сховища підключаються без нав'язаної схеми.

## Команди

```bash
cryptoctl status                               # зведення + частка по ключах (усі сховища з store.d)
cryptoctl --store-dir /etc/cryptostore/store.d status   # або явна тека
cryptoctl usage                                # к-сть значень по ключах (по сховищах, потім агрегат)
cryptoctl migrate [--rate N] [--batch N] [--dry-run]   # перешифрувати на primary
cryptoctl can-retire 1                         # чи безпечно відкликати KID 1
cryptoctl keygen                               # згенерувати новий ключ (без конфігу)
cryptoctl encrypt 'секрет'                     # зашифрувати значення (debug/round-trip)
cryptoctl decrypt '\x0001…'                    # розшифрувати збережене значення
cryptoctl search public.users email a@x.io     # ключ+токен для точного пошуку
```

### `keygen [--kid K] [--file <path> [--bytes N]]` — згенерувати ключ

Генерує свіжий ключ із `crypto/rand`. **Не потребує конфігу** — ним створюють
найперший ключ. За замовчуванням друкує готову keyring-**фразу** випадкової довжини
40–64 символи (алфавіт без керівних символів keyring `, [ ] / - \ " ' \``);
≥256 біт ентропії, придатна для `cipher`/`search`
чи `CRYPTO_*_KEYRING`. `--kid K` додає префікс `[K]` (напр. для наступного KID при
ротації). `--file` пише сирі байти у файл (0600) для форми `*_FILE`/FileMaterial;
`--bytes N` (20–256, лише з `--file`) задає їх кількість.

```bash
cryptoctl keygen                          # → фраза 40–64 симв. (≥256 біт)
cryptoctl keygen --kid 2                  # → [2]<фраза>  (наступний KID)
cryptoctl keygen --file /run/secrets/cipher.key --bytes 32   # сирі байти у файл
# приклад використання:
export CRYPTO_CIPHER_KEYRING="$(cryptoctl keygen)"
```

### `encrypt [--text] [--out fmt] <plaintext|file:path>` — зашифрувати значення

Debug/round-trip інструмент. `--text` — text-framing (`cbox:…`, для json-атрибута)
замість типового binary-bytea. `--out` — кодування виводу: `pgbytea` (типове, `\x`-hex),
`hex`, `base64`, `raw` (сирі байти в stdout) або `file:<path>` (сирі байти у файл).
Plaintext — інлайн або `file:<path>`.

> **Увага:** шифрування рандомізоване (новий nonce щоразу), тож вивід **щоразу
> різний** — ним не можна знайти рядок співставленням (для цього `search`), і він
> **не заповнює** `__cs_idx`. Штатний шлях — застосунок шифрує на запису + `migrate`.

`file:` для inline обмежений (~4 MiB): inline — це один AEAD-blob цілком у пам'яті,
для значень колонок/атрибутів. Більший файл → помилка з підказкою. Для великих
файлів — `encrypt-file`/`decrypt-file` нижче.

### `encrypt-file <src|-> <dst|->` / `decrypt-file <src|-> <dst|->` — великі файли

Потокове (chunked) шифрування з **обмеженою пам'яттю** — той самий STREAM-кодек, що
й у `blobstore` (envelope-DEK + тіло чанками ChaCha20-Poly1305 по 64 KiB). Придатне
для файлів будь-якого розміру. `-` = stdin/stdout.

> **Формат — WBS-потік, а НЕ значення колонки.** Дешифрується лише через
> `decrypt-file` (не `decrypt`). Для об'єктного сховища з каталогом/ротацією — схеми
> `blobfs` / `s3`/`gs`/`file`/`mem`.

```bash
cryptoctl encrypt-file dump.csv dump.csv.enc
cryptoctl decrypt-file dump.csv.enc dump.csv
gzip -c big.log | cryptoctl encrypt-file - big.log.gz.enc   # pipe зі stdin
```

```bash
cryptoctl encrypt 'ann@example.com'                 # → \x0001…  (bytea-літерал)
cryptoctl encrypt --out base64 'ann@example.com'    # → base64
cryptoctl encrypt --text '123-45-6789'              # → cbox:…  (json-атрибут)
cryptoctl encrypt file:/tmp/plain --out file:/tmp/ct.bin   # файл → файл
```

### `decrypt <value>` — розшифрувати одне значення

Приймає форми, у яких дані лежать у БД, плюс явні кодування сирих байтів
(усе — те саме зашифроване значення, форма визначається автоматично):

| форма | звідки |
|---|---|
| `\x…` / `0x…` | значення `bytea`-колонки (psql друкує як `\x`-hex) |
| `hex:…` | явний hex |
| `base64:…` | явний base64 (padded/raw, std/url-алфавіт) |
| `file:<path>` | вміст файлу (сирі байти або `cbox:`-текст) |
| `cbox:…` | значення json/text-атрибута |

Незашифроване (легасі-plaintext) значення повертається як є з поміткою на stderr.
Розшифрований plaintext — у stdout (файл: `decrypt file:ct.bin > plain.bin`).

```bash
cryptoctl decrypt '\x000178f3…'                        # bytea-колонка
cryptoctl decrypt 'hex:6578616d706c65…'                # явний hex
cryptoctl decrypt 'base64:ZXhhbXBsZV92YWx1ZQ=='        # явний base64
cryptoctl decrypt 'file:/tmp/ct.bin'                   # вміст файлу
cryptoctl decrypt 'cbox:q83k…'                        # json-атрибут
```

### `search <unit> <field> [nested...] <plain>` — токен для пошуку

Оскільки значення зашифровані, знайти рядок можна лише через blind-index токен.
Токен **доменно-прив'язаний** (той самий plaintext хешується по-різному в кожному
полі), тож потрібні `unit` і `field`; для json-атрибута між ними й значенням ідуть
сегменти ключа (сегмент може містити крапку). Порядок: спершу все про домен, а
**значення — останнім аргументом**. Друкує ключ слота `__cs_idx`, base64url-токен і
готовий `WHERE`-сніпет:

```bash
cryptoctl search public.users email a@x.io                  # скаляр (без сегментів)
cryptoctl search public.users profile ssn 123-45            # json: $.ssn, значення в кінці
cryptoctl search oauth.tokens data oauth2.refresh_token qwe # ключ із крапкою
# → WHERE __cs_idx @> jsonb_build_object('email', '<token>')
```

`migrate` (без `--dry-run`) показує **живий прогрес** на stderr
(`store [unit.field]: done/total (pct)`, оновлюється на місці). Таблиця результату
йде в stdout, тож прогрес можна відокремити: `... 2>/dev/tty 1>result.txt`.

Шифрування — inline (self-marking ciphertext), міграція **opportunistic**: будь-який
природний запис перешифровує під primary-ключ, а `migrate` доганяє решту. Окремого
expand/contract-розгортання немає (див. `cryptostore/docs/inline-encryption.md`).

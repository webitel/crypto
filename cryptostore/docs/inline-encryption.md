# Inline field encryption — design (cryptostore/postgres)

Статус: **реалізовано і є єдиною моделлю.** Попередній companion/expand-contract
підхід прибрано; усі inline-сутності мають базові імена (`schema.Codec`,
`postgres.Store`, scheme `postgres`).

Реалізовано:
- `cryptostore.FrameBinary/UnframeBinary/FrameText/UnframeText` +
  `Codec.Encrypt/Decrypt` (bytea, помилка на marker+authfail),
  `EncryptText/DecryptText` (json, fallback на plaintext при authfail) і
  `RecryptText` — `frame.go`.
- `postgres.InstallFunctions` → `cryptostore_kid_raw`/`cryptostore_kid`/
  `cryptostore_kids` — `pgfunc.go` (перевірено проти `cryptobox.KIDOf` на PG16).
- `schema.Codec` — `EncodeRecords`/`DecodeRecords`/`SearchToken`, inline-шифр
  скалярів і json-атрибутів, одна `__cs_idx` json-колонка з токенами — `codec.go`.
- `schema.UnitCodec` — кодек на одну одиницю (таблицю/колекцію); `Codec` володіє
  набором `UnitCodec` і делегує. `NewUnitCodec(base,name,*Unit)` будує кодек із
  динамічного `*Unit` повз центральну схему — для шифрування дампу змінних flow
  конфігом, що лежить біля визначення flow (див. «Flow-змінні») — `codec.go`.
- json-атрибутний пошук: `FieldPolicy.Nested` = `[]FieldNested{Path []string, Search}`
  (приймає скорочений рядок `"$.ssn"` або об'єкт `{"path":[...],"search"}`; одноелементний
  `$`-префіксний path — shorthand, інакше літеральні сегменти, тож `["oauth2.refresh_token"]`
  адресує ключ із крапкою в назві); пошукові
  атрибути кладуть токен у `__cs_idx` під ключем `<field>.<seg>...` (крапка в сегменті
  екранується `\.` — див. `escSeg`, тож літеральний ключ не колізить із вкладеним
  шляхом); `SearchToken(unit, field, value, seg...) → (key, token)`.
- `postgres.Store` (scheme `"postgres"`, `New`/`Open`) — `Usage`
  (`cryptostore_kid` GROUP BY для скалярів + `cryptostore_kids` LATERAL для json) і
  `Migrate` (по таблиці, батчами: кодек decode→encode + set-based `UPDATE` через
  `unnest` з batch-CAS; шифрує і plaintext, і не-primary; заповнює `__cs_idx`;
  пропускає NULL/порожні; `Recrypted` рахує рядки). Перевірено на PG16.

## Контекст і чому

Перша ітерація шифрувала колонку через companion-колонки (`<col>__ct/__kid/__bidx`)
і expand/contract-розгортання. На практиці це вперлося в реальну схему БД:

- **Оригінальні колонки не можна видаляти** — на них висять FK, PK, UNIQUE,
  NOT NULL, індекси, view. Тобто `DROP + RENAME` (contract) здебільшого неможливий.
- **Не всі колонки шифрувабельні** — PK, REFERENCES, UNIQUE беруть участь у
  join/identity/uniqueness, а рандомізований AEAD це ламає.
- **Колонко-вибух** — 1 шифрована колонка породжувала до 3 нових.
- **Масштаб** — історія (дзвінки/чати) — мільйони рядків/добу, TimescaleDB.
  Центральна таблиця шифрів стала б мільярдним вузьким місцем і вбила б
  час-секційну локальність.

Звідси нова модель: **inline, self-marking ciphertext** + **одна search-колонка
на таблицю**. Жодних `crypto.store`/`crypto.schema`.

## Governance

- Підтримка шифрування **зашита (baseline) у схему БД** + адміністратору дається
  **обмежений перелік опційних колонок**, які можна шифрувати. Baseline пінниться
  (`Codec.SetBaseline`), overlay адміна накладається через `schema.MergeConfig` —
  джерело overlay: `WatchConfig`-файл або env `WBTL_CRYPTO_SCHEMA[_FILE]`
  (`schema.NewCodec(schema.DefaultOptions())`); overlay лише додає/вмикає `search`, ніколи не послаблює.
- Скалярні колонки під шифрування **заздалегідь переводяться в `bytea`** (окремою
  міграцією БД). `json[b]`-документи лишаються `json[b]`.
- **Не шифруємо** PK / FK(REFERENCES) / UNIQUE / колонки, на яких тримаються view.

## Формат envelope

Один логічний envelope (cryptobox-блоб, що несе KID) у двох транспортних кодуваннях:

| Носій | Кодування | Маркер |
|---|---|---|
| скалярна `bytea`-колонка | `binTag ‖ blob` (raw) | `binTag = \x00 \x01` (NUL + версія формату) |
| атрибут у `json[b]` | JSON-рядок `"cbox:" ‖ base64(blob)` | текстовий префікс `cbox:` |

- `blob` = вихід cryptobox-шифру = `[kid varint 1–3B][nonce][ct+tag]`.
- **Провідний `0x00`** у бінарному маркері — однозначний: колонка походить з `text`,
  а Postgres `text` не містить NUL → жодне колишнє відкрите значення з нього не
  почнеться.
- **2-й байт — версія inline-envelope формату** (НЕ алгоритм: він імпліцитний у
  cryptobox `Box`). Бампаємо лише на зміну розкладки кадру. AEAD усе одно арбітр,
  тож маркер короткий — економимо місце на кожному значенні.
- **AEAD — остаточний арбітр**: на читанні маркер лише фільтр; рішення «шифр?» —
  успіх `Open`. Підробити значення, що автентифікується, без ключа неможливо.
- json: тип атрибута зберігається round-trip (codec робить `Marshal` листа перед
  Seal і `Unmarshal` після Open); у зашифрованому стані атрибут — завжди рядок-тег.
- framing визначається **один раз у `cryptostore`** (спільний хелпер), щоб Go-codec
  і SQL-функції читали однакову розкладку. cryptobox лишається незмінним.

## SQL-функції (для метрик/міграції на стороні БД)

```sql
-- KID зі скалярного bytea-шифру; NULL якщо це не наш шифр (тобто plaintext).
-- Слугує і предикатом "це шифр?".
CREATE FUNCTION cryptostore_kid(v bytea) RETURNS integer
  LANGUAGE sql IMMUTABLE PARALLEL SAFE RETURNS NULL ON NULL INPUT AS $$
  SELECT CASE
    WHEN length(v) < 3 OR substring(v for 2) <> '\x0001' THEN NULL
    -- varint KID починається з offset 2 (через cryptostore_kid_raw(substring(v from 3)))
    ELSE cryptostore_kid_raw(substring(v from 3))
  END
$$;

-- Набір KID з усіх зашифрованих атрибутів jsonb-документа (walk по тег-рядках).
-- Шифри самоідентифіковані тегом → шляхи знати не треба (для метрик/Usage).
CREATE FUNCTION cryptostore_kids(doc jsonb) RETURNS SETOF integer
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$ /* рекурсивний обхід:
    object/array → рекурсія; string з префіксом 'cbox:' →
    decode(substr(s,6),'base64'), читаємо varint KID з offset 0 */ $$;

-- Чи потребує (пере)шифрування конкретний json-атрибут за шляхом (для migrate-
-- предиката). Дзеркалить skip-правила кодека:
CREATE FUNCTION cryptostore_pending(v jsonb, primary_kid integer) RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ /*
    NULL / json-null / порожній рядок → false (кодек пропускає);
    'cbox:'-рядок → kid_raw(...) IS DISTINCT FROM primary_kid (ротація);
    інакше (plaintext: рядок/число/обʼєкт/...) → true (перше шифрування) */ $$;
```

Базовий varint-декодер перевірено проти `cryptobox.KIDOf` на реальних блобах
(1- та 2-байтові KID — збіг).

## Розкладка колонок

На таблицю з K шифрованими полями:
- **скаляри** — шифр inline у самій (вже `bytea`) колонці; `__kid` **не колонка, а
  функціональний індекс**: `CREATE INDEX ON t (cryptostore_kid(col))`;
- **json[b]** — шифр inline в атрибутах документа (`cbox:base64`);
- **пошук** — **одна** колонка на таблицю `__cs_idx jsonb` (незалежно від кількості
  пошукових полів) + GIN:
  ```sql
  ALTER TABLE t ADD COLUMN __cs_idx jsonb;
  CREATE INDEX ON t USING gin (__cs_idx jsonb_path_ops);
  ```
  Ключі в `__cs_idx` — `<field>` для скаляра або `<field>.<seg>.<seg>` для json-
  атрибута (для flow-змінних шлях вкладений, напр. `state.variables.phone`). Кожен
  сегмент екранується: крапка всередині назви ключа стає `\.`, тож літеральний ключ
  `oauth2.refresh_token` (`\.`) не колізить із вкладеним шляхом `oauth2`→`refresh_token`.
  Значення — base64url-токен (32-байтний HMAC-SHA256, `RawURLEncoding`, без padding).
  Сервіс шукає через containment:
  `WHERE __cs_idx @> jsonb_build_object($key, $tok)`, де `$key, $tok = SearchToken(unit, field, val, seg...)`.

Підсумок: **+1 колонка на таблицю** (`__cs_idx`, лише якщо є пошук), решта inline.
Додавання nullable-jsonb не чіпає наявних обмежень/view.

## Потоки

- **Write** (codec — чистий трансформер map→map):
  шифрує налаштовані поля → inline envelope; для пошукових — рахує токени і кладе
  в `__cs_idx`. Завжди під primary-ключем. **Порожні/`nil` не шифруються** (лишаються
  NULL/`''` — економія місця; мінімальний leak «присутності»).
- **Read**: маркер/тег → `Open` → plaintext; інакше (legacy) → значення як є.
- **Search**: `tok := codec.SearchToken(unit, key, value)`; сервіс пише свій SQL
  `WHERE __cs_idx @> jsonb_build_object('email', $tok)`. Ключ у запит не потрапляє.
- **Migrate** (агент `postgres.Store.Migrate`): **по таблиці, батчами**, не по
  колонці й не по рядку. Кожна пачка: `SELECT` рядків, що потребують роботи →
  прогін через кодек (`DecodeRecords`→`EncodeRecords`: нормалізує під primary +
  перебудовує `__cs_idx`) → **один set-based `UPDATE` через `unnest($arrays)`** з
  **optimistic batch-CAS** (`IS NOT DISTINCT FROM` по старих значеннях) — конкурентний
  запис пропускається, не затирається. Предикат відбору:
  - **скаляр**: `length(col) > 0 AND cryptostore_kid(col) IS DISTINCT FROM $primary`;
  - **json**: OR по налаштованих шляхах `cryptostore_pending(col #> '{path}', $primary)`
    — path-aware, тож ловить і **plaintext-атрибут**, який ніколи не шифрувався
    (перше шифрування), а не лише не-primary шифр. `cryptostore_pending` дзеркалить
    skip-правила кодека: `false` для відсутнього / json-null / порожнього рядка /
    вже-primary шифру; `true` для plaintext або не-primary шифру.

  І скаляр, і json ловлять і **plaintext** (перше шифрування), і не-primary
  (ротація), і відсіюють NULL/порожні. **Contract немає** — оригінал не дропимо,
  plaintext витісняється шифром на місці. Окремо лишається лише reindex `__cs_idx`
  при ротації search-ключа (при незмінному cipher предикат рядки не вибере).

## Метрики (частка по ключах)

- **count** — основний показник. Скаляри: `SELECT cryptostore_kid(col) kid,
  count(*) FROM t GROUP BY 1` (майже index-only через функц.індекс), агент агрегує
  по налаштованих колонках. json[b]: через `cryptostore_kids` + `LATERAL` (повний
  скан, рідкісна/фонова ops-операція; одиниця — окремий зашифрований атрибут).
- **volume — прибрано**: не показовий (рахує об'єм шифру, не оригіналу).

## Ключ blind-index (безпека)

- **Секретний, рівня keyring** — НЕ публічний. Витік ключа = офлайн-словникова
  атака на токени → розкриття низькоентропійних пошукових значень (email/телефон).
- **Нерота­ційний** з операційних причин (токени не несуть версію ключа → ротація =
  повний reindex), не через меншу цінність. Витік → ротувати + reindex + вважати
  пошукові значення скомпрометованими.
- Технічно — це окремий `cryptobox.Keyring` (`WBTL_CRYPTO_SEARCH_KEYRING`/`_FILE`),
  токени дає матеріал його **primary**-ключа. Keyring тут — задля єдиного формату/
  завантаження та як ґрунт під майбутні версіоновані токени (беклог), а не для
  буденної ротації.
- Навіть секретний — детерміновані токени **видають рівність/частоту** (невід'ємно).
  Пом'якшення: searchable лише потрібні поля; domain-separation `unit.field`;
  за потреби — обрізання токена (bloom-стиль).

## Flow-змінні (JSON-набір на процес)

Flow — окрема схема (бізнес-процес обробки комунікації) з функ.блоків, що
обмінюються **змінними**. У БД пишемо стан виконання: окрема `jsonb`-колонка
(напр. `state`), всередині якої атрибут `variables` — об'єкт `{ім'я: значення}`.
Частину змінних треба шифрувати.

Набір змінних для шифрування **не статичний і не в центральній схемі** — він
лежить біля визначення flow і завантажується динамічно, коли рушій піднімає схему.
Рушій сам знає, який flow виконує, тож **дискримінатор-колонка не потрібна**:

- Конфіг flow = `schema.Unit` (перевикористання типу): одне json-поле = колонка
  стану, його `Nested` = `["$.variables.<var>", …]` для змінних під шифр.
- На старті схеми рушій будує `schema.UnitCodec` через `NewUnitCodec(base, name,
  unit)` і ним шифрує/дешифрує дамп стану процесу.
- Шифр атрибутів — inline у документі (`cbox:base64`); пошукові токени — у тому ж
  `__cs_idx` під ключем `<col>.variables.<var>` (пошук для flow-змінних поки не
  задіяний, але механізм є через `FieldNested.Search`).

## Беклог / відкриті питання

- **Companion/expand-contract — видалено** (inline стала єдиною моделлю).
- **json-атрибутний пошук + flow — РЕАЛІЗОВАНО**: per-path `FieldNested.Search` (токени
  в `__cs_idx` під ключем `<field>.<path>`), уніфікований `SearchToken(unit,key,val)`,
  динамічний `schema.UnitCodec`/`NewUnitCodec` для flow-конфігу біля визначення flow
  (статичний дискримінатор виявився зайвим). Лишилось: міграція/метрики flow-даних
  не покриті центральним агентом (шифрування flow — на боці рушія, opportunistic);
  пошук flow-змінних механічно є, але поки не задіяний.
- **Агент**: команда `schema install-functions`; вибір inline-codec у конфізі.
- Ротовність index-ключа через версіонування токенів (якщо колись знадобиться).
- json-метрики — повний скан; за потреби оптимізувати (семплінг/матеріалізація).
- Композитні / без-PK таблиці — окремо (поки орієнтир single-column PK).

# cryptostore/schema

Record-орієнтований кодек над ядром [`cryptostore`](..): декларативна **схема полів**
описує, які поля яких «юнітів» (таблиця / колекція документів) шифрувати й за якими з них
дозволено точний пошук, а `Codec` шифрує/дешифрує ці поля прямо в записах (`map[string]any`)
і заповнює одну index-колонку `__cs_idx` blind-index токенами.

Пакет **не є окремим модулем** — це пакет модуля `cryptostore` (тож імпортує
`cryptobox`/`env` без власного `go.mod`).

## Схема полів

JSON/JSONC-файл, окремо від даних (ConfigMap/секрет):

```json
{
  "version": 1,
  "units": {
    "directory.users": {
      "fields": {
        "email":   { "search": true },
        "phone":   {},
        "profile": { "nested": [ { "path": ["ssn"], "search": true }, "$.passport.number" ] }
      }
    }
  }
}
```

- `unit` — таблиця (SQL) / колекція (document); `field` — колонка / атрибут.
- `search: true` → крім шифрування, токен поля кладеться у `__cs_idx` (точний пошук).
- `nested: [...]` → шифрувати **лише вказані вкладені атрибути** документа (несумісне зі
  скалярним `search` на тому ж полі; пошук вмикається per-attribute).

Вкладений атрибут задається bare-рядком-shorthand (`"$.a.b"`) або об'єктом
`{"path": [...], "search": true}`, де `path` — масив сегментів шляху. Одноелементний
`path`, що починається з `$`, трактується як shorthand і ріжеться по крапках
(`["$.a.b"]` == `["a","b"]`); будь-який інший `path` береться **дослівно**. Тож **назва
ключа з крапкою** (`{"oauth2.refresh_token": "..."}`, яку shorthand не виразить) — це просто
окремий літеральний сегмент:

```json
"tokens": { "nested": [ { "path": ["oauth2.refresh_token"], "search": true } ] }
```

Сегменти беруться дослівно; у ключі `__cs_idx` та в HKDF-домені крапка всередині сегмента
екранується (`\.`), тож літеральний ключ ніколи не колізить із вкладеним шляхом.

Завантаження: `LoadConfigFile(path)` / `LoadConfig(r)` / `ParseConfig(raw)`;
`MustParseConfig(raw)` — для baseline-літерала в коді (панікує на помилці).

## Codec

```go
base, _ := cryptostore.Default()          // ядро: *cryptostore.Codec (ключі з env)
cfg, _ := schema.LoadConfigFile("/run/secrets/cryptostore.json")
codec, _ := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(cfg))
```

`NewCodec` збирається з опцій; сам він **нічого не читає зі середовища** — доступ до env
лише через `Default*`-опції (див. нижче).

Запис/читання — батчами, in-place (мутують `[]schema.Record`):

```go
recs := []schema.Record{{"id": 1, "email": "ann@example.com", "phone": "+15551234567"}}
codec.EncodeRecords(ctx, "directory.users", recs)
// email → []byte(маркер+шифр) у тій самій колонці; phone → []byte(шифр);
// + __cs_idx = {"email":"<base64url-токен>"} для пошукових полів. Сервіс будує власний INSERT.

codec.DecodeRecords(ctx, "directory.users", scanned)
// шифр → plaintext; легасі-plaintext проходить наскрізь (поступова міграція).
```

Некерований unit — **no-op**; повторний `EncodeRecords` ідемпотентний (не подвійно-шифрує).
`Codec.Unit(name)` дає кодек однієї одиниці (`*UnitCodec`); версії ключів читаються прямо з
шифру — окремої companion-колонки версії немає.

## Пошук по точному співпадінню

`SearchToken` повертає ключ слота в `__cs_idx` і base64url-токен:

```go
key, tok, _ := codec.SearchToken(ctx, "directory.users", "email", "ann@example.com")
rows, _ := db.Query(ctx,
    `SELECT id FROM directory.users WHERE __cs_idx @> jsonb_build_object($1::text, $2::text)`, key, tok)

// вкладений атрибут: field="profile", сегмент "ssn"
key, tok, _ = codec.SearchToken(ctx, "directory.users", "profile", "123-45-6789", "ssn")
```

## Baseline + overlay (governance)

Мінімум шифрування пінниться **в коді** (baseline), а адміністратору дозволено лише
**розширювати** його через overlay: `MergeConfig(base, overlay)` може додати юніти/поля чи
ввімкнути `search`, але **ніколи не послаблює** baseline.

```go
var baseline = schema.MustParseConfig(`{ "version": 1, "units": {
    "directory.users": { "fields": { "email": {"search": true} } } } }`)

// DefaultOptions() бере все з env; WithBaseline перекриває baseline своїм (пізніша опція виграє).
codec, _ := schema.NewCodec(schema.DefaultOptions(), schema.WithBaseline(baseline))
```

| Змінна | Призначення |
|---|---|
| `CRYPTO_SCHEMA[_FILE]` | overlay-схема адміністратора (опційно; `_FILE` — шлях, має пріоритет) |

`CRYPTO_SCHEMA` приймає **дві форми**: inline `schema.Config`, або include-директиву
з **вибірковим списком файлів** (не вся тека). Відносні `dir`/`files` анкоряться до
`SystemDir` (`CRYPTO_DIR`), `dir` за-замовч. `schema.d`:

```bash
CRYPTO_SCHEMA='{"version":1,"units":{...}}'                       # inline
CRYPTO_SCHEMA='{"dir":"schema.d","files":["directory.json","cases.json"]}'  # include
```

- `schema.DefaultOptions()` — резолвить увесь кодек із середовища: base = `cryptostore.Default()`,
  baseline = `Baseline()` (з `Register`), overlay = `DefaultConfig()` (`CRYPTO_SCHEMA[_FILE]`).
  Для ops-тулів достатньо `schema.NewCodec(schema.DefaultOptions())`.
- Явні опції: `WithBase(core)`, `WithBaseline(cfg)` (запінений мінімум), `WithOverlay(cfg)`
  (розширення). `DefaultConfig()` дає env-overlay для явного `WithOverlay(DefaultConfig())`.
- `Codec.SetBaseline(cfg)` пінить мінімум; `Codec.WatchConfig(ctx, path)` — hot-reload overlay
  з файлу (повертає канал помилок).
- Ops-збірка може вшити baseline через `schema.Register` (init side-effect), і агент змерджить
  його під overlay. (Префікс `Default*` = «беремо з середовища».)

## Помилки

```go
errors.Is(err, schema.ErrUnmanaged)      // unit/field не в схемі
errors.Is(err, schema.ErrNotSearchable)  // SearchToken по полю без "search"
errors.Is(err, schema.ErrValueType)      // значення не string/[]byte/json.RawMessage
errors.Is(err, schema.ErrFieldPath)      // некоректний шлях до вкладеного атрибута
```

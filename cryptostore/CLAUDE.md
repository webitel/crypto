# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go test ./...            # run all tests (per module)
go test -v -run TestName # run a single test
go test -race ./...      # race detector (use before commits)
go build ./...           # verify compilation
gofmt -l .               # list unformatted files
```

Postgres integration tests are gated — they run only with a DSN:

```bash
CRYPTOSTORE_PG_DSN="postgres://user:pass@localhost:5432/db" go test ./... # in cryptostore/postgres
```

**Multi-module workspace.** The repo is a `go.work` workspace; most subdirectories
are their own module (own `go.mod`, wired with local `replace` directives until a
git remote exists). Run `go build`/`go test` **inside each module directory**.
Modules: `cryptostore` (core), `cryptostore/postgres`, `cryptostore/blobstore`,
`cryptostore/blobstore/gocloud`, `cmd/cryptoctl`, plus the shared
`cryptobox`, `env`, `encoding/jsonc`. **`cryptostore/schema` is NOT its own module** —
it is a package of the `cryptostore` module, so it imports `env`/`cryptobox` for free.

## Architecture

cryptostore stores encrypted data on top of [cryptobox](../cryptobox): it defines
**where** ciphertext physically lives, reports **per-key usage**, performs **key-rotation
migration**, and supports **exact-match search** without exposing keys in queries.
All encryption/decryption happens **in code** — keyring material never reaches SQL.

### Packages

| Package | Responsibility |
|---|---|
| `cryptostore` (core) | `Codec` (storage-agnostic, value-oriented crypto codec), inline framing, blind-index search tokens, `Store`/`Migration`, the store registry + `OpenStore`, and the env-default `Default`. (The multi-store config-file agent — `StoreConfig`/`loadStores` — lives in `cmd/cryptoctl`.) |
| `cryptostore/schema` | field-oriented codec: a declarative `Config` (unit→field policy) + `Codec` that encrypts named fields in records and fills the search-index column. **Package of the core module.** |
| `cryptostore/postgres` | `Store` over pgx: `Usage`/`Migrate` via the `cryptostore_*` SQL helper functions; registers DSN scheme `postgres`; registry-opened stores with the same DSN share one refcounted pool (`pool.go`) |
| `cryptostore/blobstore` (+ `/gocloud`) | object storage: envelope-DEK + streaming (`WBS`) file crypto; local dir (scheme `blobfs`) + gocloud (schemes `s3`/`gs`/`file`/`mem`) |
| `cmd/cryptoctl` | the `cryptoctl` CLI binary (operates stores from a config) |

### Core files (`cryptostore`)

| File | Responsibility |
|---|---|
| `codec.go` | `Codec` struct + `NewCodec(cipher, index)`; `Cipher()` (raw), `SearchToken`, `PrimaryKID`, `CanIndex` |
| `frame.go` | inline framing: `FrameBinary`/`UnframeBinary` (bytea), `FrameText`/`UnframeText` (json text tag); `Codec.Encrypt`/`Decrypt` (binary self-marking), `EncryptText`/`DecryptText`/`RecryptText` (json) |
| `bindex.go` | `blindIndex` — HKDF-derived, domain-scoped deterministic search tokens over the index `*cryptobox.Keyring` |
| `crypto.go` | env-backed process defaults: `Default()` (memoized `*Codec` — cipher via `cryptobox.Default`, search via `SearchKeys`), `SearchKeys()` (blind-index keyring from `WBTL_CRYPTO_SEARCH_{KEYRING,KEYFILE}`), `SystemDir()`, `Environment()` |
| `registry.go` | `Register`/`RegisterSchemaless`/`Schemaless`/`Schemes`/`Scheme`/`DriverFunc`/`StoreOptions` + `OpenStore(ctx, opts)` — the DSN-scheme→driver registry and the per-store open primitive |
| `store.go` | `Store` interface, `KeyUsage` |
| `migrate.go` | `Migration` (`NewMigration`, `Usage`, `Run`, `CanRetire`), `MigrateOptions`/`MigrateResult`/`Progress` |

### Files (`cryptostore/schema`)

| File | Responsibility |
|---|---|
| `config.go` | the field-schema data model — `Config`/`Unit`/`FieldPolicy`/`FieldNested` + validation; loaders `ParseConfig`/`LoadConfig`/`LoadConfigFile`; `MergeConfig(base, overlay)` (overlay may add/enable, never relax) |
| `codec.go` | `Codec`/`UnitCodec`: `EncodeRecords`/`DecodeRecords`/`SearchToken`, the `__cs_idx` column, `SetBaseline`, `Unit` |
| `schema.go` | codec assembly: `NewCodec(opts...)` with `WithBase`/`WithBaseline`/`WithOverlay`/`DefaultOptions`; `DefaultConfig` (env overlay `WBTL_CRYPTO_SCHEMA[_FILE]`), `Register`/`Baseline`, `MustParseConfig`. Default* helpers resolve from the environment |
| `watch.go` | `Codec.WatchConfig(ctx, path)` — hot-reload the overlay from a file |
| `include.go` | `IncludeConfig` — the JSON include directive (`{dir, files}`) that merges many schema files into one (used by store configs) |
| `jsonb.go` | `DecryptJSONB` — decrypt a whole jsonb document's encrypted attributes |
| `errors.go` | `ErrUnmanaged`/`ErrNotSearchable`/`ErrValueType`/`ErrFieldPath` |

### Key design decisions

**`Codec` is the storage-agnostic, value-oriented core.** `NewCodec(cipher cryptobox.Cipher, index *cryptobox.Keyring)`
combines value encryption (via a cryptobox `Box`; the KID rides in the blob header)
with an **optional** blind-index keyring. `Codec.Encrypt`/`Decrypt` add the inline
self-marking frame (binary/bytea); `EncryptText`/`DecryptText`/`RecryptText` are the json
transport; raw, unframed crypto is `Cipher()`. Pass a nil index when nothing is searchable;
`SearchToken` then returns `ErrIndexKey`. Keep the index keyring **independent** of the
cipher keyring so data-key rotation never invalidates search tokens.

**Inline, self-marking ciphertext.** A stored value identifies itself as ciphertext, so
encrypted and legacy-plaintext values coexist in one column/attribute and migration is
opportunistic. Two transport encodings wrap the same cryptobox blob:
- **bytea column** — `binTag(\x00 \x01) ‖ blob`. Leading `NUL` can't occur in a value
  from a Postgres `text` column, so it's unambiguous; the 2nd byte is the inline-envelope
  format version (NOT the cipher algorithm — that stays implicit in the `Box`).
- **json attribute / text** — `textTag ‖ base64(blob)`, tag = **`cbox:`** (a JSON-safe,
  opaque scheme marker with **no in-band version field**; a future layout change registers
  a *new* tag rather than bumping a digit).

The marker is only a cheap filter; **AEAD authentication is the real arbiter** of "is this
ciphertext?". A framed bytea value that fails to open is corruption (error); a text value
that fails falls back to legacy plaintext.

**`schema.Config` is the field policy.** It declares `units` (a SQL table / document collection)
→ `fields` (columns/attributes) → `FieldPolicy` (`search` for scalars, `nested` attributes
with per-attribute `search`). Loaded from JSON/JSONC via `ParseConfig`/`LoadConfigFile`;
`MustParseConfig` panics for a baseline literal embedded in code. `MergeConfig(base, overlay)`
overlays an admin config onto a pinned baseline — the overlay may **add** units/fields or
turn on `search`, but **never relax** the baseline.

**`schema.Codec` is a pure map→map transformer.** `EncodeRecords`/`DecodeRecords` mutate
`Record` (`= map[string]any`) in place; the service writes its own SQL. Search tokens for
a whole unit go into **one** `IndexField` json column (`__cs_idx`, GIN-indexed) as
`{searchKey: base64url-token}`; key versions are read back from the ciphertext (no companion
key-version column). `Codec.Schema()` returns the active config; `Codec.WatchConfig` hot-reloads
it; `SetBaseline` pins the immutable minimum. `UnitCodec`/`NewUnitCodec` build a codec for one
unit from a (possibly dynamic) `*Unit`.

**Env-default facade (less integration boilerplate).** A service integrating the library
avoids the manual keyring→Box→Codec→schema.Codec chain:
- `cryptostore.Default()` — a `sync.Once`-memoized process-wide `*Codec` from
  `WBTL_CRYPTO_CIPHER_{KEYRING,KEYFILE}` (+ optional `WBTL_CRYPTO_SEARCH_{KEYRING,KEYFILE}`).
- `schema.NewCodec(opts...)` — options-based assembly. `schema.DefaultOptions()` pulls the
  whole codec from the environment (base `cryptostore.Default()`, baseline `Baseline()`,
  overlay `DefaultConfig()`); a service overrides just its baseline with `WithBaseline`.
  Env access is opt-in: bare `NewCodec` never touches the environment.
- `schema.DefaultConfig()` / `MustParseConfig` are the building blocks (Default* = from env).
  `WBTL_CRYPTO_SCHEMA` is decoded as an `IncludeConfig` — inline `Config` or an `{dir,files}`
  include directive (relative paths anchored to `SystemDir`) — so ops can select overlay files by name.

The agent path — the multi-store, config-file orchestrator — lives in `cmd/cryptoctl`,
not in core: it owns the `StoreConfig` type, the JSON/JSONC loaders, and store discovery
(keys come from the env via `cryptostore.Default`, not from its config), and assembles
stores by calling core `cryptostore.OpenStore` per entry
(sharing one `Codec`, behind one `Migration`). `schema.NewCodec` is the code-first path
for a single service. Core exposes only the primitives: `Codec`, `OpenStore`, `Migration`,
`Default`, `SearchKeys`.

**Store registry (DSN scheme → driver).** A store's `DSN` has the form
`<scheme>[:opaque]` (e.g. `postgres://…`, `blobfs:/var/lib/x`, `s3://bucket`, or bare
`postgres:`). The **scheme** — everything before the first `:`, via `cryptostore.Scheme(dsn)` —
selects the registered `DriverFunc`; the **opaque** remainder is the driver's to parse (core never
validates it). A store implementation calls `cryptostore.Register(scheme, driverFunc)` in its `init()`
(import for side effect, e.g. `_ ".../cryptostore/postgres"`); a driver may register several
schemes (gocloud → `s3`/`gs`/`file`/`mem`). A driver that encrypts whole objects and does
NOT consume a field schema (blob/object storage) registers via `RegisterSchemaless` instead;
`cryptostore.Schemaless(scheme)` reports the declared kind (false for record-oriented and for
unknown schemes — fail-closed), so an agent can decide whether to apply a field-schema baseline
without hardcoding a scheme list (see cryptoctl `resolveSchema`/`recordOriented`). `cryptostore.OpenStore(ctx, StoreOptions)` dispatches by the
DSN scheme to the `DriverFunc(ctx, StoreOptions)`. `StoreOptions` carries the `*Codec`, the full `DSN`, the raw
config block (extras not in the DSN — postgres `schema`, blobstore `catalog`), the raw schema, a verbose flag, and
`BaseDir` (the directory of the config file that declared the store). A driver anchors a relative
filesystem path (a `blobfs` directory, a `file://` bucket path, a sqlite `catalog`) via
`opts.Resolve(path)` — so paths are relative to the config file, not the process CWD; absolute paths
and an empty `BaseDir` (config not from a file) pass through unchanged. (gocloud normalizes the
`file://` URL itself, since gocloud would otherwise resolve a relative `file://` path against the CWD
or misread its first segment as a host.) Opening fails fast when a schema has searchable fields but no
index keyring is configured.

**Shared connections (postgres).** Registry-opened postgres stores with an identical DSN share
one reference-counted `pgxpool` (`postgres/pool.go`), so an agent that gathers many per-service
store configs — each its own schema, all DSN `postgres` — talks to the database over a single
pool; the pool closes when the last store is `Close`d. `pgxConnString` maps the store DSN to the
pgx connection string: an empty opaque (`postgres` / `postgres:`) resolves from the libpq
environment, a `//…` opaque keeps its URL scheme, anything else is a keyword string. The
in-service `postgres.New` constructor takes the caller's own pool directly, outside this
shared-pool machinery.

**Migration is opportunistic + resumable.** `Encrypt` always uses the primary key, so any
natural write re-encrypts a row for free; `Migration.Run` catches up the rest, batched and
resumable, guarding each write against concurrent updates (CAS on the old key version).
**No contract phase** — originals are never dropped; plaintext is displaced in place.
`CanRetire(kid)` reports whether a tombstoned key still has data.

**Postgres SQL helpers** (`InstallFunctions`, installed by `Open`): `cryptostore_kid(bytea)`
(KID of a scalar cipher; NULL = plaintext — doubles as the "is-encrypted?" predicate),
`cryptostore_kids(jsonb)` (walks a document for encrypted-attribute KIDs), and
`cryptostore_pending(jsonb, primary_kid)` (the migrate predicate mirroring the codec's
skip rules). They match the `cbox:` / `\x00\x01` framing; keep them in sync with `frame.go`.

### Environment variables

| Variable | Purpose |
|---|---|
| `WBTL_CRYPTO_CIPHER_{KEYRING,KEYFILE}` | value-encryption keyring (**required**) |
| `WBTL_CRYPTO_SEARCH_{KEYRING,KEYFILE}` | blind-index keyring (optional; absent → search disabled) |
| `WBTL_CRYPTO_SCHEMA[_FILE]` | admin overlay (optional; `_FILE` = path, wins). `SCHEMA` is an inline `Config` **or** an include directive `{dir,files}` (selective file list; relative paths anchor to `SystemDir`) |
| `WBTL_CRYPTO_DIR` | system config dir (default `/var/lib/webitel/crypto`) |

`_FILE` variants hold a path; the keyring format is cryptobox's. Resolution order for keys:
env → **well-known system file**. `SystemDir()` (`crypto.go`) delegates to
`cryptobox.SystemDir()` (the single source of truth) = `WBTL_CRYPTO_DIR` or
`/var/lib/webitel/crypto`. The **cipher** fallback to `<SystemDir>/.cipher` lives in
**cryptobox** — `cryptobox.DefaultKeys` consults it (lazily, once) when neither env source
is set, so any service on cryptobox (not only cryptostore) picks it up; `cryptostore.Default`
goes through it. The **search** fallback to `<SystemDir>/.search` stays here (blind-index is
a cryptostore concept, via `SearchKeys`). cryptoctl has NO key config of its own — it builds
its codec from `cryptostore.Default`, so it uses exactly the services' keys. It falls its
`store.d`/`schema.d` dirs back to `[CWD, exeDir, SystemDir]` (`resolveDir`), so a populated
system dir runs with zero env. Keys are NOT discovered via CWD/exeDir (only SystemDir) —
secrets must come from a trusted location.

### CLI (`cryptoctl`)

`cmd/cryptoctl` (`go install github.com/webitel/crypto/cmd/cryptoctl@latest` → binary `cryptoctl`).
Store commands: `status`, `usage`, `migrate [--rate --batch --dry-run]`, `can-retire <kid>`.
Storeless crypto commands (need only keys, no store config): `keygen`, `encrypt`, `decrypt`,
`encrypt-file`/`decrypt-file`, `search`. cryptoctl has no key config: the codec is
`cryptostore.Default` (env / system files; see `open.go`'s `var openCodec`). Its whole config
is the store set — one JSON/JSONC file per store in `-store-dir` (default `store.d`; env
`WBTL_CRYPTO_STORE_DIR`); `-store <file>` (repeatable) selects specific files there, else all
are loaded (`loadStores`, `config.go`). A store's `schema` section is a `schema.IncludeConfig`
(`schema/include.go`): empty (null/{}), an inline `schema.Config`, or an include directive
`{dir, files}` (files required; dir default the shared `-schema-dir`, env
`WBTL_CRYPTO_SCHEMA_DIR`, else `schema.d` beside the store file) whose files `MergeConfig` into
one — so many services' per-DB-schema files attach to one connection unedited. An ops build can
compile in a pinned baseline via `schema.Register` (init side-effect), which the agent
merges under the overlay (`resolveSchema`); the storage drivers stay baseline-free.

### Errors

`errors.Is` works for the sentinels: `cryptostore.ErrIndexKey` (no/short index keyring);
`schema.ErrUnmanaged`, `schema.ErrNotSearchable`, `schema.ErrValueType`, `schema.ErrFieldPath`.

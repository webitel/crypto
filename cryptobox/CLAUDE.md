# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go test ./...            # run all tests
go test -v -run TestName # run a single test
go test -race ./...      # race detector (use before commits)
go build ./...           # verify compilation
go mod tidy              # sync dependencies
```

## Architecture

Single-package library (`package cryptobox`) with no sub-packages. Public surface is intentionally small.

### Files

| File | Responsibility |
|---|---|
| `key.go` | `KID` type alias, `KeyMaterial` interface, `Key` struct, `TextMaterial`, `FileMaterial`, constructors `NewTextKey`/`NewFileKey` |
| `keyring.go` | `Keyring` struct (thread-safe), `ParseKeyring()`, `Load()`, entry management (`Add`/`Rotate`/`Retire`/`SetPrimary`/`Find`/`List`); `KeyringOptions` + `NewKeyring()` (pure builder, load-once, no Box/watch); `Keyring.Watch`/`WatchFile` |
| `keyfile.go` | `KeyFile` (path + throttle + mtime-guarded reload + `Watch` goroutine); `DefaultPollInterval`; the `KeyFilePolicy` permission hook + `KeyFileRequirePrivate`/`KeyFileWarnUnlessPrivate` |
| `cipher.go` | `Cipher` interface (`Encrypt`/`Decrypt`), `CipherFunc`, `Box` (AEAD cache + ring-version invalidation), `KIDOf`, `encodeKID`/`decodeKID` |
| `chacha.go` | `ChaCha20Poly1305` — a `CipherFunc` that derives a ChaCha20-Poly1305 AEAD via HKDF-SHA256 |
| `crypto.go` | Package defaults & environment: `DefaultAlgo`, `DefaultKeys`/`Default`/`SetDefault`/`Init`, package-level `Encrypt`/`Decrypt`/`Recrypt`, `Environment()`, and `SystemDir`/`systemFile`/`defaultCipherFile` (`<SystemDir>/.cipher` fallback) |
| `insecure.go` | `Insecure()` — pass-through `Cipher`, no encryption |
| `errors.go` | Sentinel errors: `ErrKeyNotFound`, `ErrKeyRetired`, `ErrBlobTooShort`, `ErrInvalidIKM`, `ErrDecrypt`, `ErrFileDir` |

### Key design decisions

**`KeyMaterial` separates identity from material.** `Key` is an exported struct `{ kid KID; src KeyMaterial }`. The `KeyMaterial` interface has a single method `KeyMaterial(ctx context.Context) ([]byte, error)` — the method name matches the interface name intentionally. Implementations: `TextMaterial` (phrase in memory), `FileMaterial` (reads from file on each call). Future implementations can read from Vault, KMS, etc., all using `context.Context` for cancellation and deadlines.

**`type KID = uint16` alias.** Key identifiers are 16-bit; implicit KID = 1-based position in the config string. Explicit KID overrides position via `[42]material` or `[0x2f]material` notation. KID=0 is rejected.

**Blob format:** `[kid: varint 1–3B][nonce 12B][ciphertext+tag N+16B]`. KID is protobuf varint: 1 byte for 0–127, 2 bytes for 128–16383, 3 bytes for 16384–65535. Algorithm is implicit — determined by the `Box`, not stored in the blob.

**Config format (`WBTL_CRYPTO_CIPHER_KEYRING`)**. Comma-separated entries; each entry is `["[" KID "]"] material`:

```
phrase1,[42]phrase2,[0x1f]/run/secrets/key.pem:64:32,-,[100]phrase3
#  KID=1   KID=42          KID=31, file+viewport        KID=2(tomb) KID=100
```

- Material starting with `/` is auto-detected as a file path (`FileMaterial`).
- Material `-` is a tombstone (retired slot).
- Escape sequences: `\\` `\,` `\[` `\/` `\-` (for literal characters that would otherwise be control tokens).
- Last non-tombstone entry is the primary key (used for `Encrypt`).

**File viewport:** `/path[:offset[:length]]` — offset and length are optional. Minimum 20 bytes, maximum 256 bytes.

**HKDF bridges IKM → crypto key.** `KeyMaterial()` returns raw bytes (IKM); `deriveKey()` runs `HKDF-SHA256(ikm, salt=nil, info=...)` to produce the algorithm-specific key. The `info` string is the domain separator — changing it produces a completely different key from the same IKM.

**`CipherFunc`** is `func(ctx context.Context, key Key) (cipher.AEAD, error)` — algorithm selection point. `NewBox(algo CipherFunc, keys *Keyring)` — algo is the first argument, keys is the second.

**`Box` combines `*Keyring` + `CipherFunc`** and implements `Cipher`. `Cipher` interface and `CipherFunc` accept `context.Context` on every call, enabling cancellation and deadlines through the full call stack.

**`Box` AEAD cache with ring-version invalidation.** `Box` caches derived `cipher.AEAD` instances by KID. `Keyring` carries an `atomic.Uint64` version counter incremented under `mu.Lock()` on every `Load()`. `Box.aead()` reads the version atomically; on mismatch it discards the entire cache before deriving a fresh AEAD. This ensures that hot-reload (file change → `ring.Load()`) is correctly reflected even when the same KID receives new key material. Version is initialized in `NewBox` to the ring's current version so the first call never triggers a spurious invalidation.

**`Insecure()`** returns a value-type pass-through `Cipher` (empty struct, zero allocation). Use in tests or when encryption is explicitly disabled.

**`Recrypt(ctx, blob, with ...Cipher)`** (`crypto.go`) re-encrypts a blob (decrypt with src, encrypt with dst). The trailing ciphers pick src/dst: **none** → `src = dst = Default()` (re-encrypt under the default primary); **one** → `src = dst = c` (re-encrypt within one keyring); **two** → `src, dst` (cross-keyring / cross-algorithm migration). More than two is an error. Only the zero-cipher form touches package `Default()`; the rest is a pure primitive over the `Cipher` interface.

**`Load(raw string) error`** atomically replaces `entries`, `primary`, and increments `version` under a single write lock. If `ParseKeyring` fails, the existing state is unchanged. This is the hot-reload primitive.

**`KeyFile` struct** (`keyfile.go`) tracks a keyring file: `Name` (required — the path), `Poll` (min reload interval, 0 → `DefaultPollInterval`). Internal state (`modTime`, `loadTime`, `loadErr`, `mu`) is unexported. `KeyFile.Load(ring)` respects the throttle and mtime guard — returns `(changed bool, err error)` where `changed=true` only when the ring was actually updated. `KeyFile.Watch(ctx, ring)` starts a background goroutine: initial load on start, then a ticker every `poll()`, errors (and nil on a successful reload) forwarded to a buffered channel (capacity 1).

**`Keyring.Watch(ctx, filename)`** is a thin wrapper: `return (&KeyFile{Name: filename}).Watch(ctx, k)` (arbitrary path, default poll). **`Keyring.WatchFile(ctx)`** watches the file the ring was built from (`NewKeyring` stores it on `k.src`, honoring `KeyringOptions.FilePoll`); for an inline ring it is a no-op (closed channel). The polling logic lives on `KeyFile` (`keyfile.go`) — the single implementation.

**`KeyringOptions` + `NewKeyring` (`keyring.go`)** is a **pure** keyring builder — no `Box`, no algorithm, no watch goroutine. Fields: `Keyring` (inline), `Filename` (takes precedence; one key per line and/or comma-separated), `FilePoll` (poll interval for a later `WatchFile`). `NewKeyring` loads **once** and returns a plain `*Keyring`; when built from a file it stores the source so `WatchFile` can hot-reload later. Watch is deliberately opt-in and separate. JSON tags on config fields are snake_case (`file_poll`).

**Package defaults (`crypto.go`), env-backed, read exactly once.** `DefaultKeys()` resolves the cipher keyring from `WBTL_CRYPTO_CIPHER_KEYRING` / `_FILE` (namespace `WBTL_` → `CRYPTO` → `CIPHER`, via `github.com/webitel/crypto/env`), and when neither is set, the **well-known system file** `<SystemDir>/.cipher` (`SystemDir()` = `WBTL_CRYPTO_DIR` or `/var/lib/webitel/crypto`; `defaultCipherFile` is the testable decision). Resolution is a `sync.Once` memoizing `(ring, err)` **for the process life** — a caller needs keys *now*, so a failure is returned to everyone immediately rather than retried (no thundering herd on a broken/absent source). `Default()` returns the `SetDefault` override, else a `Box` over `DefaultKeys` with `DefaultAlgo` (built once). `SetDefault(Cipher)` overrides (tests/`Insecure()`); `Init()` forces the once early for fail-fast. Package-level `Encrypt`/`Decrypt`/`Recrypt` go through `Default()`. A second, independent keyring (e.g. cryptostore's blind-index `WBTL_CRYPTO_SEARCH_KEYRING`) is built with a fresh `NewKeyring` — cryptobox `Default` only knows the cipher namespace. NOTE: `DefaultKeys` is load-once and does **not** auto-hot-reload the `.cipher` file; for that, build a `NewKeyring`+`WatchFile` and install it via `SetDefault`. `defaultSystemDir` is a `var` (not `const`) so an ops build can bake in a different default with `-ldflags -X`.

**`KeyFilePolicy` audits key-file permissions (`keyfile.go`).** A package-level hook
`var KeyFilePolicy = func(path string, info os.FileInfo) error` runs for every key file
read from disk — the keyring file behind `WBTL_CRYPTO_CIPHER_KEYFILE` /
`WBTL_CRYPTO_SEARCH_KEYFILE` and the well-known `.cipher`/`.search` (checked once per
real load in `KeyFile.Load`, after the mtime guard, so watch/poll never spams), plus each
`/path` key inside a keyring (checked once in `NewFileMaterial`). A non-nil return fails
the load; `canTrustKeyFile` is the internal dispatcher. Ready policies: `nil` (off — code
only), `KeyFileWarnUnlessPrivate` (slog a warning, load anyway), `KeyFileRequirePrivate`
(reject — the **default**). "Not private" = any world access or group-write; group-**read**
is tolerated (the standard non-root-container pattern — k8s `fsGroup` → 0640/0440 — where
owner-only 0600 would be unreadable). Private: 0600, 0400, 0640, 0440. No-op on Windows.
The default is resolved once from `WBTL_CRYPTO_KEYFILE_POLICY` (`keyFilePolicyFromEnv`):
`strict`/empty → require, `unsafe` → warn, anything else fails safe to require (only
`unsafe` can relax; a typo never weakens it). `off` is not reachable from the env — it is
a deliberate code decision (`KeyFilePolicy = nil`). Both cipher and search flow through
`cryptobox.NewKeyring`, so one hook covers both; inline/env keys are never checked. Assign
your own func for custom policy (ownership, audit, KMS attestation).

**`Keyring` is thread-safe.** All public methods acquire `sync.RWMutex`. Internal `find()` and `add()` are unlocked helpers. `List()` takes a snapshot under `RLock` before returning the iterator, so the caller's `yield` runs without holding the lock.

**`Retire` refuses to retire the primary key.** The correct workflow is `Rotate(next)` → migrate data with `Recrypt` → `Retire(old)`.

### Keyring lifecycle

```
ParseKeyring → Add/Rotate → SetPrimary → Retire
                  ↑                         ↓
                new key             old key becomes tombstone
```

`Rotate(next)` is the atomic shortcut for Add + SetPrimary under a single lock.

### Adding a new algorithm

1. Write a `CipherFunc`: `func MyAlgo(ctx context.Context, key Key) (cipher.AEAD, error)`.
2. Use a distinct `hkdfInfo` constant (e.g. `"webitel.cryptobox.v1.aes256gcm"`) to isolate derived keys.
3. Pass your function to `NewBox(MyAlgo, ring)`.
4. The algorithm selection stays out of the blob — it is a property of the `Box`, not stored in ciphertext.

### Errors

`errors.Is` works for all sentinel errors in `errors.go`. `ErrKeyRetired` specifically signals that data exists encrypted under a removed key and needs migration before the tombstone can be dropped. `ErrDecrypt` wraps an AEAD `Open` failure in `Box.Decrypt` (the key was resolved by KID but the tag did not verify), naming the KID and keeping the algorithm's error in the chain; it is deliberately ambiguous between a changed/wrong key for that KID and a corrupt/foreign blob (an AEAD must not leak which). Key *resolution* failures are distinct and earlier: `ErrKeyNotFound` (KID absent) / `ErrKeyRetired` (KID tombstoned). `ErrFileDir` reports a keyring path that is a directory.

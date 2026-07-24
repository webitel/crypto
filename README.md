# webitel/crypto

Application-layer encryption for Go services: encrypt data **in code**, before it
reaches your database or object store, with built-in **key versioning**, online
**key-rotation migration**, and exact-match **search over encrypted values** —
without ever exposing key material to SQL.

Ciphertext is **inline and self-marking**: an encrypted value carries a small tag
that says "I am ciphertext", so encrypted and legacy plaintext values coexist in the
same column and migration is gradual — no companion columns, no big-bang cutover.
The tag is only a cheap filter; the real arbiter is AEAD authentication.

## Modules

The repo is a Go multi-module workspace. Each module is versioned and imported
independently; heavier backends live in their own modules so the core stays light.

| Module | Import path | What it is |
|---|---|---|
| **cryptobox** | `github.com/webitel/crypto/cryptobox` | Foundation: keyring, envelope cipher (`Box`), key identity (`KID`). Depends only on `x/crypto`. |
| **cryptostore** | `github.com/webitel/crypto/cryptostore` | Core: value-oriented `Codec`, inline framing, blind-index search tokens, `Store`/`Migration`, DSN registry. |
| ↳ schema | `github.com/webitel/crypto/cryptostore/schema` | Record-oriented codec: declarative field policy over `Codec` (package of the core module). |
| ↳ postgres | `github.com/webitel/crypto/cryptostore/postgres` | A `Store` over pgx: per-key usage + batched rotation via `cryptostore_*` SQL functions. |
| ↳ blobstore | `github.com/webitel/crypto/cryptostore/blobstore` | Object store: envelope-DEK + streaming (WBS) file crypto; local directory backend. |
| ↳ blobstore/gocloud | `github.com/webitel/crypto/cryptostore/blobstore/gocloud` | Cloud backends (S3 / GCS / …) via `gocloud.dev`, kept optional. |
| **cmd/cryptoctl** | `github.com/webitel/crypto/cmd/cryptoctl` | CLI: key generation, encrypt/decrypt, per-store status/usage/migrate. |

## Install

As a library:

```bash
go get github.com/webitel/crypto/cryptostore
```

The CLI:

```bash
go install github.com/webitel/crypto/cmd/cryptoctl@latest
```

## Documentation

Each module carries its own `README.md` with usage and examples; the design and
internals are documented in `cryptostore/CLAUDE.md` and
`cryptostore/docs/inline-encryption.md`. Package references are on
[pkg.go.dev](https://pkg.go.dev/github.com/webitel/crypto/cryptostore).

## License

Copyright 2026 Webitel. Licensed under the [Apache License 2.0](./LICENSE).

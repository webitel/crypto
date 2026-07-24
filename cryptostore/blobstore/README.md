# cryptostore/blobstore

Об'єктне сховище для [`cryptostore`](..): одиниця — **об'єкт** (файл), не рядок. Кожен
об'єкт шифрується власним DEK (data-encryption key), DEK загорнуто cryptobox-шифром (несе
KID), а самі дані — чанковим ChaCha20-Poly1305 STREAM (обмежена пам'ять на об'єкт будь-якого
розміру). Контролер веде sqlite-каталог (`key → kid, size`), тож `Usage` по каталогу — O(1),
а `Migrate` перегортає лише DEK-заголовок (не перешифровує все тіло).

Схеми: **`blobfs`** (локальна тека — цей пакет) і хмара **`s3`/`gs`/`file`/`mem`** через
[`./gocloud`](./gocloud) (Go CDK).

## Використання

```go
import "github.com/webitel/crypto/cryptostore/blobstore"

st, _ := blobstore.Open("blob:main", "/data/secure", codec) // codec — *cryptostore.Codec
st.Put(ctx, "users/42/avatar.png", reader)
rc, _ := st.Get(ctx, "users/42/avatar.png")
defer rc.Close()
st.Delete(ctx, "users/42/avatar.png")
```

- `Open(name, dir, codec)` — локальна тека (scheme `blobfs`); `NewStore(name, bucket, catalogPath, codec)` —
  над довільним `Bucket` (напр. хмарним із `gocloud`).
- `Put`/`Get`/`Delete` — потокові; `Usage`/`Migrate` — під `cryptostore.Migration`;
  `Reindex` — перебудова каталогу зі сховища.

## З конфігурації (реєстр)

```go
import _ "github.com/webitel/crypto/cryptostore/blobstore"          // scheme blobfs
// або: _ "github.com/webitel/crypto/cryptostore/blobstore/gocloud" // schemes s3/gs/file/mem

st, _ := cryptostore.OpenStore(ctx, cryptostore.StoreOptions{DSN: "blobfs:/data/secure", Codec: codec})
```

DSN — `blobfs:<dir>` (opaque — тека; відносний шлях прив'язується до конфіг-файлу через
`opts.Resolve`). Хмарні: `s3://bucket`, `gs://bucket`, `file:///abs/path`, `mem://` — див.
[`gocloud`](./gocloud).

## Формат об'єкта

`[hdr: cryptobox-загорнутий DEK (≤63B у 64B-області)] ‖ [STREAM: чанки ChaCha20-Poly1305]`.
Ротація ключів торкається лише заголовка (`Migrate` перегортає DEK під новий primary) — тіло
не перешифровується.

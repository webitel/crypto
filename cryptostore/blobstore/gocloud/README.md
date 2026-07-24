# cryptostore/blobstore/gocloud

Хмарні бекенди для [`cryptostore/blobstore`](..) через [Go CDK](https://gocloud.dev)
(`gocloud.dev/blob`). Реєструє DSN-схеми **`s3`**, **`gs`**, **`file`**, **`mem`** — один
драйвер, кілька схем. Шифрування те саме, що й у `blobstore` (envelope-DEK + STREAM); цей
пакет лише дає `Bucket`-бекенд.

Підключення — імпорт-для-side-effect + `cryptostore.OpenStore`:

```go
import _ "github.com/webitel/crypto/cryptostore/blobstore/gocloud"

st, _ := cryptostore.OpenStore(ctx, cryptostore.StoreOptions{DSN: "s3://my-bucket", Codec: codec})
```

| DSN | Бекенд |
|---|---|
| `s3://bucket` | AWS S3 (та S3-сумісні) |
| `gs://bucket` | Google Cloud Storage |
| `file:///abs/path` | локальна ФС (Go CDK) |
| `mem://` | in-memory (тести) |

Лише `file` несе шлях, що резолвиться відносно конфіг-файлу (`opts.Resolve`); `s3`/`gs`/`mem`
проходять як є. Прямий доступ до бакета — `gocloud.OpenBucket(ctx, url)`.

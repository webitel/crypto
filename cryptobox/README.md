# cryptobox

Внутрішня Go-бібліотека Webitel для шифрування чутливих даних: паролі, API-ключі, приватні повідомлення та будь-які секретні поля.

**Алгоритм:** ChaCha20-Poly1305 з HKDF-SHA256 для деривації ключів.  
**Ротація ключів:** вбудована, без зупинки сервісу.  
**Конфігурація:** одна змінна середовища або файл.

## Встановлення

```bash
go get github.com/webitel/crypto/cryptobox
```

## Швидкий старт

```go
import (
    "context"
    "github.com/webitel/crypto/cryptobox"
)

ctx := context.Background()

// Використання Default (WBTL_CRYPTO_CIPHER_KEYRING або WBTL_CRYPTO_CIPHER_KEYFILE)
blob, err := cryptobox.Encrypt(ctx, []byte("secret-api-key"))
plain, err := cryptobox.Decrypt(ctx, blob)

// Або явно через Keyring + Box
ring, err := cryptobox.ParseKeyring("correct-horse-battery-staple!")
box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)

blob, err = box.Encrypt(ctx, []byte("secret-api-key"))
plain, err = box.Decrypt(ctx, blob)
```

## Конфігурація

### Змінні середовища

| Змінна | Призначення |
|---|---|
| `WBTL_CRYPTO_CIPHER_KEYRING` | Inline keyring-рядок (один або кілька ключів) |
| `WBTL_CRYPTO_CIPHER_KEYFILE` | Шлях до файлу з keyring-рядком; підтримує hot-reload |
| `WBTL_CRYPTO_DIR` | Системна тека (дефолт `/var/lib/webitel/crypto`); фолбек для `.cipher` |

Можна вказувати лише одну з `*_KEYRING`/`*_KEYFILE`. `WBTL_CRYPTO_CIPHER_KEYFILE` має пріоритет якщо задані обидві.

Namespace — `WBTL_` → `CRYPTO` → `CIPHER` (див. `github.com/webitel/crypto/env`).

**Well-known файл.** Якщо жодна зі змінних `*_KEYRING`/`*_KEYFILE` не задана, `DefaultKeys`
(при першому використанні — `sync.Once`) пробує well-known файл **`<WBTL_CRYPTO_DIR>/.cipher`**
(дефолт `/var/lib/webitel/crypto/.cipher`). Тобто devops кладе keyring туди — і сервіс на
cryptobox працює **без жодних змінних середовища**. Env має пріоритет; файл читається лише
коли існує (інакше поведінка як була). Резолв відбувається **раз** і мемоізується (успіх або
помилка) — для hot-reload файлу-ключа збери власний `NewKeyring`+`WatchFile` і встанови його
через `SetDefault`. На Debian/systemd тека пасує `StateDirectory=webitel/crypto`.

### Права доступу до файлів ключів

Файл ключів (`*_KEYFILE`, well-known `.cipher`, а також `/path`-ключі всередині
keyring) має бути **приватним** — доступ лише власнику (толерується group-read для
Kubernetes `fsGroup`): `0600`, `0400`, `0640`, `0440`. За замовчуванням файл із ширшими
правами при завантаженні **відхиляється**. Керується змінною `WBTL_CRYPTO_KEYFILE_POLICY`:

| Значення | Політика |
|---|---|
| `strict` (дефолт, або порожньо) | відхилити не-приватний файл (`KeyFileRequirePrivate`) |
| `unsafe` | лише попередження в лог, але завантажити (`KeyFileWarnUnlessPrivate`) |

Повністю вимкнути перевірку можна лише з коду: `cryptobox.KeyFilePolicy = nil`. Туди ж
можна підставити власну політику (напр. перевірку власника файлу чи аудит).

### Формат keyring-рядка

```
WBTL_CRYPTO_CIPHER_KEYRING=entry1,entry2,...
```

Кожен запис — ключ або tombstone. Формат запису:

```
["[" KID "]"] material
```

- **KID** — числовий ідентифікатор: `[42]`, `[0x2f]`. За замовчуванням — порядковий номер (1, 2, …).
- **material** — phrase, шлях до файлу або `-` (tombstone).
- Останній не-tombstone запис — **primary** ключ (використовується для `Encrypt`).

#### Типи матеріалу

| Запис | Тип |
|---|---|
| `correct-horse-battery-staple!` | phrase в пам'яті (`TextMaterial`) |
| `/run/secrets/key.pem` | весь файл (до 256 байт) (`FileMaterial`) |
| `/run/secrets/key.pem:64` | файл з offset 64 |
| `/run/secrets/key.pem:64:32` | файл: 32 байти з offset 64 |
| `-` | tombstone (відкликаний слот) |

Шлях до файлу визначається автоматично якщо material починається з `/`.

#### Escape-символи

Якщо phrase містить символи зі спеціальним значенням — екрануйте їх через `\`:

| Escape | Результат |
|---|---|
| `\\` | `\` |
| `\,` | `,` (не розділювач) |
| `\[` | `[` (не початок KID) |
| `\/` | `/` (не файловий шлях) |
| `\-` | `-` (не tombstone) |

#### Приклади

```bash
# Один phrase, KID=1 (implicit)
WBTL_CRYPTO_CIPHER_KEYRING=correct-horse-battery-staple!

# Два ключі: KID=1 (читання), KID=2 (primary)
WBTL_CRYPTO_CIPHER_KEYRING=old-phrase-2024!,new-phrase-2025!

# Явний KID=42, файловий ключ KID=31, tombstone KID=3 (implicit, позиція 3)
WBTL_CRYPTO_CIPHER_KEYRING=[42]my-phrase!,[31]/run/secrets/key.pem,-

# Phrase з комою (потрібен escape)
WBTL_CRYPTO_CIPHER_KEYRING=correct-horse\,battery-staple-2025!
```

#### Роздільники: inline vs файл

Той самий формат читається двома способами:

- **inline** (`WBTL_CRYPTO_CIPHER_KEYRING`) — записи через **кому**, одним рядком;
- **файл** (`WBTL_CRYPTO_CIPHER_KEYFILE`) — через кому, **новий рядок** (по ключу на рядок)
  або мішано. Зовнішні пробіли обрізаються; порожні рядки й кінцевий перенос ігноруються
  (implicit-KID рахує лише непорожні записи).

```bash
# inline: через кому
WBTL_CRYPTO_CIPHER_KEYRING=old-phrase-2024!,new-phrase-2025!
```

```
# файл: той самий keyring, по ключу на рядок
# /run/secrets/keyring.conf   ← WBTL_CRYPTO_CIPHER_KEYFILE
old-phrase-2024!
new-phrase-2025!
```

(Порядок = KID: перший рядок — KID=1, останній не-tombstone — primary. Так само для
`WBTL_CRYPTO_SEARCH_KEYRING` / `WBTL_CRYPTO_SEARCH_KEYFILE`.)

#### Вимоги до phrase

- Мінімум 20 символів
- Тільки printable ASCII: `!` — `~` (0x21–0x7E); пробіл заборонений

#### Вимоги до файлу-ключа

- Мінімум 20 байт у вказаному viewport
- Максимум 256 байт
- offset + length не можуть виходити за межі файлу

### Формат blob

```
[kid: varint 1–3 байти][nonce: 12 байт][ciphertext + tag: N+16 байт]
```

- **kid** — ідентифікатор ключа (protobuf varint): 1 байт для KID 1–127, 2 байти для 128–16383, 3 байти для 16384–65535.
- **nonce** — випадковий, генерується при кожному `Encrypt`.
- Алгоритм у blob **не зберігається** — це властивість `Box`, а не даних.

---

## Ротація ключів

Ротація відбувається без зупинки сервісу та без обов'язкової міграції існуючих даних.

### Крок 1 — Додати новий ключ і зробити його primary

Оновіть `WBTL_CRYPTO_CIPHER_KEYRING` — додайте новий phrase. Новий ключ автоматично стає primary за позицією:

```bash
# Було:
WBTL_CRYPTO_CIPHER_KEYRING=phrase-jan-2025!

# Стало (KID=1 читання, KID=2 primary):
WBTL_CRYPTO_CIPHER_KEYRING=phrase-jan-2025!,phrase-jul-2025!
```

Або програмно, атомарно через `Rotate`:

```go
next, _ := cryptobox.NewTextKey(2, "phrase-jul-2025!")
ring.Rotate(next) // Add + SetPrimary під одним локом
```

Після цього:
- Нові записи шифруються новим ключем (KID=2)
- Старі записи (KID=1) продовжують розшифровуватись

### Крок 2 — Перешифрувати старі дані (опціонально)

```go
// Через Default — найпростіший варіант (без шифрів → src = dst = Default()):
newBlob, err := cryptobox.Recrypt(ctx, oldBlob)

// Або явно, якщо src і dst відрізняються (міграція між keyring):
newBlob, err := cryptobox.Recrypt(ctx, oldBlob, oldBox, newBox)
```

### Крок 3 — Відкликати старий ключ

```go
err := ring.Retire(1) // помилка, якщо спробувати відкликати primary
```

Або через конфіг — замінити старий phrase на tombstone `-`:

```bash
WBTL_CRYPTO_CIPHER_KEYRING=-,phrase-jul-2025!
#                ^ KID=1 відкликано
```

Якщо залишились blob-и з KID=1 — `Decrypt()` поверне `ErrKeyRetired`. Це сигнал, що міграція не завершена.

### Повний цикл

```
Початок:    key1                     → KID=1 primary
+key2:      key1,key2                → KID=1 читання, KID=2 primary
Recrypt all: всі blob-и перешифровані на KID=2
Retire(1):  -,key2                   → KID=1 tombstone, KID=2 primary
+key3:      -,key2,key3              → KID=2 читання, KID=3 primary
```

---

## API

### ParseKeyring

```go
ring, err := cryptobox.ParseKeyring("phrase-1!,phrase-2!")
```

### NewBox

```go
// NewBox(algo CipherFunc, keys *Keyring)
box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)
```

### Encrypt / Decrypt

```go
blob, err := box.Encrypt(ctx, plaintext)
plain, err := box.Decrypt(ctx, blob)
```

### Package-level Encrypt / Decrypt (через Default)

```go
// Читає WBTL_CRYPTO_CIPHER_KEYRING або WBTL_CRYPTO_CIPHER_KEYFILE; ініціалізується один раз.
blob, err := cryptobox.Encrypt(ctx, plaintext)
plain, err := cryptobox.Decrypt(ctx, blob)
```

### Recrypt

Перешифрувати наявний blob. Хвостові шифри задають src (decrypt) і dst (encrypt):

```go
// Без шифрів → src = dst = Default(): перешифрувати під поточний primary дефолта.
newBlob, err := cryptobox.Recrypt(ctx, oldBlob)

// Один шифр → src = dst = box: міграція під primary у межах одного keyring.
newBlob, err := cryptobox.Recrypt(ctx, oldBlob, box)

// Два → src, dst: міграція між keyring/алгоритмами.
newBlob, err := cryptobox.Recrypt(ctx, oldBlob, oldBox, newBox)

// Більше двох шифрів — помилка.
```

### Load / Watch (hot-reload)

```go
// Атомарно замінити стан keyring з рядка.
// При помилці стан не змінюється. Скидає кеш AEAD у всіх Box.
err := ring.Load("phrase-v1!,phrase-v2!")

// Стежити за файлом і перезавантажувати при зміні mtime.
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

errc := ring.Watch(ctx, "/run/secrets/keyring.conf")
go func() {
    for err := range errc {
        log.Printf("keyring reload error: %v", err)
    }
}()
```

`Watch` читає файл одразу при запуску, потім поллить через `KeyFile.Poll` (default 5s).  
При невдалому перезавантаженні попередній стан зберігається і спроба повторюється на наступному тіку.

**Формат файлу** — той самий, що і в `WBTL_CRYPTO_CIPHER_KEYRING`, але у файлі записи можна
розділяти **новим рядком** (по ключу на рядок), комою, або мішано; порожні рядки й
кінцевий перенос ігноруються:

```
# /run/secrets/keyring.conf
phrase-v1!
phrase-v2!
```

### Keyring management

```go
// Переглянути всі ключі зі статусом
for key, retired := range ring.List() {
    fmt.Printf("KID=%d retired=%v\n", key.Kid(), retired)
}

// Знайти ключ за KID
key, err := ring.Find(42)

// Атомарно додати і зробити primary
next, _ := cryptobox.NewTextKey(2, "new-phrase!")
err := ring.Rotate(next)

// Додати без зміни primary
err := ring.Add(key)

// Змінити primary вручну
err := ring.SetPrimary(2)

// Відкликати (тільки не-primary)
err := ring.Retire(1)
```

### KeyringOptions / NewKeyring (програмна побудова)

`KeyringOptions` описує **лише** як зібрати `Keyring` (без `Box`/алгоритму): inline-рядок
(`Keyring`) або файл (`Filename`, має пріоритет). `NewKeyring` завантажує **один раз** і
повертає чистий `*Keyring` — без горутин. Hot-reload — окремо й явно, через
`Keyring.WatchFile(ctx)` (див. приклад нижче).

```go
ring, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{
    Keyring:  "phrase-v1!,phrase-v2!",     // АБО:
    Filename: "/run/secrets/keyring.conf", // файл (пріоритет); one-key-per-line або через кому
    FilePoll: 5 * time.Second,             // період для WatchFile (0 → дефолт)
})
box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)

// Авто-watch файлу (опційно): NewKeyring не стартує його сам.
errc := ring.WatchFile(ctx) // ctx скасовує watch; для inline-ключа — no-op
go func() {
    for err := range errc {
        log.Printf("keyring reload: %v", err)
    }
}()
```

### Default / DefaultKeys / SetDefault (env-конфігурація)

Читають env **рівно один раз** (`sync.Once`) і мемоізують результат (успіх *або* помилку):

```go
ring, err := cryptobox.DefaultKeys() // env cipher keyring + фолбек на <SystemDir>/.cipher
enc,  err := cryptobox.Default()      // Cipher (Box над DefaultKeys), або override з SetDefault

cryptobox.SetDefault(cryptobox.Insecure()) // підмінити Default (тести); nil — скинути
err := cryptobox.Init()                     // форсувати розбір env зараз (fail-fast на старті)
```

Package-level `Encrypt`/`Decrypt`/`Recrypt` ідуть через `Default()`.

**Hot-reload дефолтного cipher** (опційно — сам собою watch не вмикається). `Default()`
будує `Box` над тим самим `*Keyring`, що повертає `DefaultKeys()`, тож достатньо watch-нути
його: перезавантаження мутує ring і скидає AEAD-кеш `Box`. Для inline-ключа (без `_FILE`) —
no-op:

```go
ring, _ := cryptobox.DefaultKeys()
go func() {
    for err := range ring.WatchFile(ctx) { // читає WBTL_CRYPTO_CIPHER_KEYFILE / <SystemDir>/.cipher
        log.Printf("cipher keyring reload: %v", err)
    }
}()
```

> Другий незалежний keyring (напр. blind-index `WBTL_CRYPTO_SEARCH_KEYRING` у cryptostore)
> будується окремим `NewKeyring(...)` — cryptobox `Default` знає лише про cipher-namespace.

### Insecure (dev/test)

```go
box := cryptobox.Insecure()
// Encrypt/Decrypt повертають дані без змін
```

---

## Розгортання

### Docker Compose

```yaml
services:
  app:
    image: webitel/app
    environment:
      WBTL_CRYPTO_CIPHER_KEYRING: "my-strong-dev-phrase-2024!"
```

### Kubernetes Secret (inline)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: webitel-cryptobox
type: Opaque
stringData:
  WBTL_CRYPTO_CIPHER_KEYRING: "phrase-v1!,phrase-v2!"
```

```yaml
spec:
  containers:
    - name: app
      envFrom:
        - secretRef:
            name: webitel-cryptobox
```

### Hot-reload без перезапуску (Kubernetes Secret як файл + Watch)

Kubernetes оновлює примонтовані Secret-файли автоматично при зміні Secret. `Watch` виявляє зміну mtime і перезавантажує keyring без зупинки сервісу.

```yaml
# Secret зберігає весь keyring-рядок одним полем
apiVersion: v1
kind: Secret
metadata:
  name: webitel-cryptobox
type: Opaque
stringData:
  keyring.conf: "phrase-v1!,phrase-v2!"
```

```yaml
spec:
  containers:
    - name: app
      env:
        - name: WBTL_CRYPTO_CIPHER_KEYFILE
          value: /run/secrets/cryptobox/keyring.conf
      volumeMounts:
        - name: cryptobox-secret
          mountPath: /run/secrets/cryptobox
          readOnly: true
  volumes:
    - name: cryptobox-secret
      secret:
        secretName: webitel-cryptobox
```

```go
// Найпростіший варіант — Default підхоплює WBTL_CRYPTO_CIPHER_KEYFILE автоматично.
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

blob, err := cryptobox.Encrypt(ctx, []byte("secret"))
// При оновленні Secret файл зміниться → ring.Load() → Box cache скинеться → новий AEAD
```

> Vault Agent і AWS Secrets Manager Agent теж пишуть секрети у файли — схема та сама.

### Файл-ключ (Kubernetes Secret як файл)

```yaml
spec:
  containers:
    - name: app
      env:
        - name: WBTL_CRYPTO_CIPHER_KEYRING
          value: "/run/secrets/cryptobox/key.bin"
      volumeMounts:
        - name: cryptobox-secret
          mountPath: /run/secrets/cryptobox
          readOnly: true
  volumes:
    - name: cryptobox-secret
      secret:
        secretName: webitel-cryptobox-key
```

---

## Обробка помилок

```go
plain, err := box.Decrypt(ctx, blob)
switch {
case err == nil:
    // ок
case errors.Is(err, cryptobox.ErrKeyRetired):
    // дані зашифровані відкликаним ключем — потрібна міграція через Recrypt
case errors.Is(err, cryptobox.ErrKeyNotFound):
    // blob з невідомим KID — можливо, дані з іншого keyring
case errors.Is(err, cryptobox.ErrDecrypt):
    // ключ знайдено, але автентифікація не пройшла — змінений/невірний ключ або пошкоджені дані
case errors.Is(err, cryptobox.ErrBlobTooShort):
    // пошкоджені або некоректні дані
}
```

### Таблиця помилок

| Ситуація | Помилка |
|---|---|
| Phrase коротший за 20 символів | `ErrInvalidIKM` |
| Phrase містить пробіл або non-ASCII | `ErrInvalidIKM` |
| Файл-ключ: viewport занадто малий або виходить за межі файлу | `ErrInvalidIKM` |
| Спроба відкликати primary ключ | помилка з описом |
| Дублікат KID у keyring | помилка з описом |
| KID=0 | помилка з описом |
| Остання позиція — tombstone | помилка при `ParseKeyring` |
| Файл ключів не приватний (політика `strict`) | помилка з описом (mode + причина) |
| blob зашифрований відкликаним ключем | `ErrKeyRetired` |
| blob з невідомим KID | `ErrKeyNotFound` |
| blob не проходить автентифікацію (змінений ключ / пошкоджені дані) | `ErrDecrypt` |
| blob занадто короткий | `ErrBlobTooShort` |

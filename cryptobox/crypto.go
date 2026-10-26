package cryptobox

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/webitel/crypto/env"
)

// Init forces the one-time environment resolution now and returns any error building
// the default keyring. Call it at startup for fail-fast instead of on first use.
func Init() error {
	_, err := DefaultKeys()
	return err
}

// Encrypt seals data with the Default cipher (env keyring, or the SetDefault override).
func Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	c, err := Default()
	if err != nil {
		return nil, err
	}
	return c.Encrypt(ctx, data)
}

// Decrypt opens blob with the Default cipher.
func Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	c, err := Default()
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ctx, blob)
}

// Recrypt decrypts blob and re-encrypts it. The trailing ciphers select src (decrypt)
// and dst (encrypt):
//
//   - none    → src = dst = Default() (re-encrypt under the default primary key)
//   - c       → src = dst = c          (re-encrypt within one keyring/cipher)
//   - s, d    → src = s, dst = d        (migrate across keyrings or algorithms)
//
// More than two ciphers is an error. Use it to migrate existing blobs after a key
// rotation (with(none)/one) or to move between keyrings (with two).
func Recrypt(ctx context.Context, blob []byte, with ...Cipher) ([]byte, error) {
	var src, dst Cipher
	switch len(with) {
	case 0:
		c, err := Default()
		if err != nil {
			return nil, err
		}
		src, dst = c, c
	case 1:
		src, dst = with[0], with[0]
	case 2:
		src, dst = with[0], with[1]
	default:
		return nil, fmt.Errorf("cryptobox: Recrypt takes at most 2 ciphers (src, dst), got %d", len(with))
	}
	data, err := src.Decrypt(ctx, blob)
	if err != nil {
		return nil, err
	}
	return dst.Encrypt(ctx, data)
}

// DefaultAlgo is the CipherFunc Default() uses to build its Box.
var DefaultAlgo = ChaCha20Poly1305

// Default returns the process-wide default Cipher: the one set by SetDefault, or —
// absent an override — a Box over DefaultKeys with DefaultAlgo, built once. It backs
// the package-level Encrypt/Decrypt/Recrypt.
func Default() (Cipher, error) {
	if use := mod.ciph.set.Load(); use != nil {
		return use.Cipher, nil
	}
	mod.ciph.init.Do(func() {
		ring, err := DefaultKeys()
		if err != nil {
			mod.ciph.err = err
			return
		}
		mod.ciph.box = NewBox(DefaultAlgo, ring)
	})
	return mod.ciph.box, mod.ciph.err
}

// SetDefault overrides the Cipher returned by Default (and used by Encrypt/Decrypt/
// Recrypt) — e.g. Insecure() in tests, or a Box over a custom keyring. Passing nil
// clears the override, restoring the env-backed default.
func SetDefault(use Cipher) {
	if use == nil {
		mod.ciph.set.Store(nil)
		return
	}
	mod.ciph.set.Store(&cipherRef{use})
}

// DefaultKeys returns the process-wide cipher keyring, resolved from the environment
// exactly once (sync.Once): CRYPTO_CIPHER_KEYRING / _KEYFILE, and when neither is set,
// the well-known system file <SystemDir>/.cipher. The result (ring or error) is
// memoized for the life of the process — a caller that needs keys needs them now, so
// a resolution failure is returned to every caller immediately rather than retried
// (which under load would mean many callers hammering an unavailable/broken source).
//
// CRYPTO_CIPHER_KEYFILE_POLL (a time.Duration, e.g. "5s") enables hot-reload: when
// positive, a background watcher polls the file-backed keyring at that interval and swaps
// in rotated keys WITHOUT a process restart (rotation = add a higher-KID key to the file;
// old keys stay for decrypt — do not delete keys still protecting data). It is clamped up
// to MinKeyFilePoll; 0/unset (the default) disables watching; a malformed value fails the
// whole default keyring (loud, so a typo never silently leaves rotation un-watched). It is
// ignored for an inline keyring (nothing to watch).
func DefaultKeys() (*Keyring, error) {
	mod.keys.init.Do(func() {
		var (
			err   error
			setup KeyringOptions
		)
		Environment("CIPHER").Apply(
			env.String("KEYRING", func(v string, _ bool) { setup.Keyring = v }),
			env.String("KEYFILE", func(v string, _ bool) { setup.Filename = v }),
			env.String("KEYFILE_POLL", func(v string, _ bool) {
				var re error
				setup.FilePoll, re = parseKeyFilePoll(v)
				err = errors.Join(err, re)
			}),
		)
		// bad arguments ?
		if err != nil {
			mod.keys.err = err
			return // err
		}
		// try system keyfile if none specified
		setup.Filename = defaultCipherFile(
			setup.Keyring, setup.Filename,
		)
		// try to load cipher key(s) material ..
		mod.keys.ring, mod.keys.err = NewKeyring(setup)
		if mod.keys.err != nil {
			return // err
		}
		// Opt-in hot-reload. The watcher runs for the life of the process (the default
		// keyring is a process-wide singleton), so context.Background is deliberate — there
		// is nothing to cancel. For explicit lifecycle control, build a NewKeyring +
		// WatchFile(ctx) and install it via SetDefault instead.
		if setup.FilePoll > 0 {
			if setup.Filename == "" {
				slog.Warn("cryptobox: CRYPTO_CIPHER_KEYFILE_POLL set but the cipher keyring is inline; ignoring (nothing to watch)")
			} else {
				go drainKeyFileWatch(mod.keys.ring.WatchFile(context.Background()))
			}
		}
	})
	return mod.keys.ring, mod.keys.err
}

// MinKeyFilePoll is the smallest accepted CRYPTO_CIPHER_KEYFILE_POLL interval: a
// positive value below it is raised to this floor so a misconfiguration cannot hammer the
// filesystem. 0 (the default) disables watching entirely.
const MinKeyFilePoll = time.Second

// parseKeyFilePoll interprets the CRYPTO_CIPHER_KEYFILE_POLL value: "" or "0" → 0
// (no watch); a positive duration is clamped up to MinKeyFilePoll; a negative or malformed
// value is an error (fail loud rather than silently skip the watch).
func parseKeyFilePoll(text string) (time.Duration, error) {
	if text == "" {
		return 0, nil // unset → no watch
	}
	every, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("cryptobox: CRYPTO_CIPHER_KEYFILE_POLL %q: %w", text, err)
	}
	if every < 0 {
		return 0, fmt.Errorf("cryptobox: CRYPTO_CIPHER_KEYFILE_POLL must not be negative: %q", text)
	}
	if every == 0 {
		return 0, nil // explicit 0 → no watch
	}
	every = max(MinKeyFilePoll, every)
	return every, nil
}

// DefaultKeysOnUpdate is the hook invoked for every reload outcome of the default
// keyring's file watcher (started by DefaultKeys when CRYPTO_CIPHER_KEYFILE_POLL is
// set): err == nil means a successful reload (rotated keys are now in effect), a non-nil
// err means the reload failed and the previous keys stay in effect (see KeyFile.Load).
// The default implementation logs the outcome via slog.
//
// Replace it to route reloads elsewhere (metrics, a custom logger, an alert); set it to
// nil to silence them. It is read once when the watcher starts, so assign it BEFORE the
// first DefaultKeys/Default call (e.g. in an init or at startup) — a later change does not
// affect an already-running watcher. The hook runs on the watcher goroutine and must not
// block; keep it quick (offload slow work to another goroutine).
var DefaultKeysOnUpdate = func(err error) {
	if err != nil {
		slog.Error("cryptobox: cipher keyring reload failed; keeping previous keys", "error", err)
		return // err
	}
	slog.Info("cryptobox: cipher keyring reloaded")
}

// drainKeyFileWatch consumes the WatchFile error channel of the process-wide default
// keyring, logging each reload outcome: nil = a successful reload (rotated keys picked up),
// non-nil = a reload failure (the previous keys stay in effect — see KeyFile.Load). Without
// a reader the channel's non-blocking sends would drop these silently, blinding operators
// to a broken rotation. It ends when the channel closes (process exit for the default watch).
func drainKeyFileWatch(errc <-chan error) {
	hook := DefaultKeysOnUpdate
	if hook == nil {
		hook = func(_ error) {}
	}
	for err := range errc {
		hook(err)
	}
}

func Environment(namespace ...string) env.Options {
	return mod.env.WithNamespace(namespace...)
}

// defaultSystemDir is the well-known system directory for crypto configuration when
// CRYPTO_DIR is unset. On Debian/systemd it pairs with StateDirectory=cryptoctl.
//
// It is a var (not a const) so an ops build can bake in a different default with no code
// change and no environment variable, via the linker:
//
//	go build -ldflags="-X 'github.com/webitel/crypto/cryptobox.defaultSystemDir=/opt/myapp/crypto'"
//
// CRYPTO_DIR still overrides it at runtime; cryptostore.SystemDir delegates here, so
// this single symbol sets the default for the whole stack.
var defaultSystemDir = "/var/lib/cryptoctl"

// systemCipherFile is the well-known cipher keyring file within SystemDir, tried by
// Default when neither CRYPTO_CIPHER_KEYRING nor _FILE is set. The leading dot
// marks it as secret material. Higher layers (cryptostore) keep their own well-known
// files in the same dir (e.g. .search for the blind-index keyring).
const systemCipherFile = ".cipher"

// SystemDir is the well-known directory for system-level crypto configuration:
// CRYPTO_DIR, or /var/lib/cryptoctl by default. DevOps populates it (the
// .cipher keyring here; higher layers add their own files) so a deployment can run
// with no environment variables at all. It is the single source of truth for the
// directory — cryptostore.SystemDir delegates here.
func SystemDir() string {
	// CRYPTO_DIR
	dir := mod.env.Getenv("DIR")
	if dir != "" {
		return dir
	}
	return defaultSystemDir
}

// systemFile returns <SystemDir>/name when it exists as a regular file, else "".
func systemFile(name string) string {
	if !filepath.IsAbs(name) {
		name = filepath.Join(SystemDir(), name)
	}
	info, err := os.Stat(name)
	if err == nil && !info.IsDir() {
		return name
	}
	return ""
}

// defaultCipherFile reports the well-known .cipher path to use as the Default
// keyring source: empty when either key source is already set (env/inline take
// precedence) or the file does not exist, else <SystemDir>/.cipher. init() applies
// it to Default; kept as a pure helper so the decision is testable without depending
// on package-init timing.
func defaultCipherFile(keyring, filename string) string {
	// input: specified ?
	if cmp.Or(keyring, filename) != "" {
		return filename // so use input
	}
	// default CRYPTO_CIPHER_KEYFILE
	return systemFile(systemCipherFile)
}

// global (module) configuration
var mod = struct {
	env  env.Options
	keys struct {
		init sync.Once
		ring *Keyring
		err  error
	}
	ciph struct {
		init sync.Once
		box  Cipher
		err  error
		set  atomic.Pointer[cipherRef] // set by SetDefault
	}
}{
	env: env.Environment("CRYPTO"),
}

type cipherRef struct{ Cipher }

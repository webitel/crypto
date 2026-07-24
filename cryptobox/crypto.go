package cryptobox

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

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
// exactly once (sync.Once): WBTL_CRYPTO_CIPHER_KEYRING / _KEYFILE, and when neither is set,
// the well-known system file <SystemDir>/.cipher. The result (ring or error) is
// memoized for the life of the process — a caller that needs keys needs them now, so
// a resolution failure is returned to every caller immediately rather than retried
// (which under load would mean many callers hammering an unavailable/broken source).
func DefaultKeys() (*Keyring, error) {
	mod.keys.init.Do(func() {
		var keyring, filename string
		Environment("CIPHER").Apply(
			env.String("KEYRING", func(v string, _ bool) { keyring = v }),
			env.String("KEYFILE", func(v string, _ bool) { filename = v }),
			// env.String("ALGORITHM", func(string, bool) {}), // DefaultAlog == ChaCha20Poly1305
		)
		if f := defaultCipherFile(keyring, filename); f != "" {
			filename = f
		}
		mod.keys.ring, mod.keys.err = NewKeyring(KeyringOptions{Keyring: keyring, Filename: filename})
	})
	return mod.keys.ring, mod.keys.err
}

func Environment(namespace ...string) env.Options {
	return mod.env.WithNamespace(namespace...)
}

// defaultSystemDir is the well-known system directory for crypto configuration when
// WBTL_CRYPTO_DIR is unset. On Debian/systemd it pairs with StateDirectory=webitel/crypto.
//
// It is a var (not a const) so an ops build can bake in a different default with no code
// change and no environment variable, via the linker:
//
//	go build -ldflags="-X 'github.com/webitel/crypto/cryptobox.defaultSystemDir=/opt/webitel/crypto'"
//
// WBTL_CRYPTO_DIR still overrides it at runtime; cryptostore.SystemDir delegates here, so
// this single symbol sets the default for the whole stack.
var defaultSystemDir = "/var/lib/webitel/crypto"

// systemCipherFile is the well-known cipher keyring file within SystemDir, tried by
// Default when neither WBTL_CRYPTO_CIPHER_KEYRING nor _FILE is set. The leading dot
// marks it as secret material. Higher layers (cryptostore) keep their own well-known
// files in the same dir (e.g. .search for the blind-index keyring).
const systemCipherFile = ".cipher"

// SystemDir is the well-known directory for system-level crypto configuration:
// WBTL_CRYPTO_DIR, or /var/lib/webitel/crypto by default. DevOps populates it (the
// .cipher keyring here; higher layers add their own files) so a deployment can run
// with no environment variables at all. It is the single source of truth for the
// directory — cryptostore.SystemDir delegates here.
func SystemDir() string {
	// WBTL_CRYPTO_DIR
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
		return "" // so use input
	}
	// default WBTL_CRYPTO_CIPHER_KEYFILE
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

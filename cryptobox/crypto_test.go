package cryptobox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemDir(t *testing.T) {
	t.Setenv("CRYPTO_DIR", "") // force default
	if got := SystemDir(); got != defaultSystemDir {
		t.Fatalf("default SystemDir = %q, want %q", got, defaultSystemDir)
	}
	t.Setenv("CRYPTO_DIR", "/etc/cryptoctl")
	if got := SystemDir(); got != "/etc/cryptoctl" {
		t.Fatalf("override SystemDir = %q", got)
	}
}

// TestDefaultCipherFile: the well-known .cipher is used only when no env/inline key
// is set and the file exists — env/inline take precedence, a missing file yields "".
func TestDefaultCipherFile(t *testing.T) {
	dir := t.TempDir()
	cipher := filepath.Join(dir, systemCipherFile)
	if err := os.WriteFile(cipher, []byte("correct-horse-battery-staple-001!"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CRYPTO_DIR", dir)

	if got := defaultCipherFile("", ""); got != cipher {
		t.Errorf("no keys set: fallback = %q, want %q", got, cipher)
	}
	if got := defaultCipherFile("some-inline-keyring", ""); got != "" {
		t.Errorf("inline keyring set: fallback = %q, want empty", got)
	}
	if got := defaultCipherFile("", "/some/file"); got != "/some/file" {
		t.Errorf("keys file set: got %q, want the given file (pass-through)", got)
	}

	t.Setenv("CRYPTO_DIR", t.TempDir()) // dir without a .cipher
	if got := defaultCipherFile("", ""); got != "" {
		t.Errorf("missing file: fallback = %q, want empty", got)
	}
}

// TestDefaultIgnoresLegacyWBTLPrefix: the former WBTL_CRYPTO_* names are not read at all,
// so a stale deployment env fails loudly (no keys) instead of half-working.
func TestDefaultIgnoresLegacyWBTLPrefix(t *testing.T) {
	t.Setenv("WBTL_CRYPTO_CIPHER_KEYRING", "legacy")
	if got := Environment("CIPHER").Getenv("KEYRING"); got != "" {
		t.Fatalf("legacy WBTL_CRYPTO_CIPHER_KEYRING read as %q; want ignored", got)
	}
	t.Setenv("CRYPTO_CIPHER_KEYRING", "current")
	if got := Environment("CIPHER").Getenv("KEYRING"); got != "current" {
		t.Fatalf("CRYPTO_CIPHER_KEYRING = %q, want %q", got, "current")
	}
}

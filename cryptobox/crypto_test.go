package cryptobox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemDir(t *testing.T) {
	t.Setenv("WBTL_CRYPTO_DIR", "") // force default
	if got := SystemDir(); got != defaultSystemDir {
		t.Fatalf("default SystemDir = %q, want %q", got, defaultSystemDir)
	}
	t.Setenv("WBTL_CRYPTO_DIR", "/etc/webitel/crypto")
	if got := SystemDir(); got != "/etc/webitel/crypto" {
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
	t.Setenv("WBTL_CRYPTO_DIR", dir)

	if got := defaultCipherFile("", ""); got != cipher {
		t.Errorf("no keys set: fallback = %q, want %q", got, cipher)
	}
	if got := defaultCipherFile("some-inline-keyring", ""); got != "" {
		t.Errorf("inline keyring set: fallback = %q, want empty", got)
	}
	if got := defaultCipherFile("", "/some/file"); got != "" {
		t.Errorf("keys file set: fallback = %q, want empty", got)
	}

	t.Setenv("WBTL_CRYPTO_DIR", t.TempDir()) // dir without a .cipher
	if got := defaultCipherFile("", ""); got != "" {
		t.Errorf("missing file: fallback = %q, want empty", got)
	}
}

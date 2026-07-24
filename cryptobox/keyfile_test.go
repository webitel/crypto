package cryptobox_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/webitel/crypto/cryptobox"
)

// keyfile writes a keyring file at the given mode and returns its path.
func keyfile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cipher.keyring")
	if err := os.WriteFile(p, []byte(key1pass), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile mode is umask-masked; force it
		t.Fatal(err)
	}
	return p
}

// TestKeyFileRequirePrivate: the strict policy fails a world-readable keyring file and
// accepts an owner-only one; the error flows out of NewKeyring.
func TestKeyFileRequirePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	restore := cryptobox.KeyFilePolicy
	cryptobox.KeyFilePolicy = cryptobox.KeyFileRequirePrivate
	t.Cleanup(func() { cryptobox.KeyFilePolicy = restore })

	notPriv := keyfile(t, 0o644)
	if _, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: notPriv}); err == nil ||
		!strings.Contains(err.Error(), "not private") {
		t.Fatalf("strict must reject 0644 keyring, got %v", err)
	}

	priv := keyfile(t, 0o600)
	if _, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: priv}); err != nil {
		t.Fatalf("strict must accept 0600 keyring: %v", err)
	}
}

// TestKeyFileWarnAndOff: the warn policy logs but never fails; nil (off) is a silent
// no-op. Both load a world-readable file successfully.
func TestKeyFileWarnAndOff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	notPriv := keyfile(t, 0o644)

	// Capture slog to prove the warn policy actually fires.
	var buf bytes.Buffer
	restoreLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restoreLog) })

	restore := cryptobox.KeyFilePolicy
	t.Cleanup(func() { cryptobox.KeyFilePolicy = restore })

	cryptobox.KeyFilePolicy = cryptobox.KeyFileWarnUnlessPrivate
	if _, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: notPriv}); err != nil {
		t.Fatalf("warn must not fail: %v", err)
	}
	if !strings.Contains(buf.String(), "not private") {
		t.Fatalf("warn should have logged; got %q", buf.String())
	}

	buf.Reset()
	cryptobox.KeyFilePolicy = nil // off
	if _, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: notPriv}); err != nil {
		t.Fatalf("off must not fail: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("off must be silent; got %q", buf.String())
	}
}

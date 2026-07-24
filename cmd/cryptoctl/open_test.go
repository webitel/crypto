package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

const testCipher = "correct-horse-battery-staple-001!"

// injectCodec makes openCodec return a fixed codec (built from testCipher, no search),
// so store-open tests need no env keyring. It restores openCodec on cleanup.
func injectCodec(t *testing.T) {
	t.Helper()
	codec, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, mustRing(t, testCipher)), nil)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	old := openCodec
	openCodec = func() (*cryptostore.Codec, error) { return codec, nil }
	t.Cleanup(func() { openCodec = old })
}

// TestOpenStoresInjectedCodec: openCodec is a var, so a test can supply a codec without
// env/keyfiles; openStores opens every configured store with it, behind one Migration.
func TestOpenStoresInjectedCodec(t *testing.T) {
	injectCodec(t)
	dir := t.TempDir()

	stores, mig, err := openStores(context.Background(), []StoreConfig{
		{DSN: "blobfs:" + filepath.Join(dir, "blobs"), Name: "blobs", BaseDir: dir},
	}, false)
	if err != nil {
		t.Fatalf("openStores: %v", err)
	}
	defer closeStores(stores)
	if len(stores) != 1 {
		t.Fatalf("stores = %d, want 1", len(stores))
	}
	if mig == nil {
		t.Fatal("migration is nil")
	}
}

// TestOpenStoresUnknownScheme: an unregistered DSN scheme is a clear open error.
func TestOpenStoresUnknownScheme(t *testing.T) {
	injectCodec(t)
	if _, _, err := openStores(context.Background(), []StoreConfig{
		{DSN: "nope:whatever", Name: "x"},
	}, false); err == nil {
		t.Fatal("expected error for unregistered scheme")
	}
}

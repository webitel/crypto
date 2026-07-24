package blobstore_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/blobstore"
)

func newCodec(t *testing.T, keys string) *cryptostore.Codec {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(keys)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// payloads of sizes that exercise empty, sub-chunk, exact-chunk and multi-chunk.
func payloads() map[string][]byte {
	const chunk = 64 * 1024
	return map[string][]byte{
		"empty":     {},
		"small":     []byte("hello, encrypted world"),
		"exact":     bytes.Repeat([]byte("A"), chunk),
		"multi":     bytes.Repeat([]byte("B"), chunk*2+777),
		"dir/inner": bytes.Repeat([]byte{0x00, 0x7f, 0xff}, 5000),
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")
	s, err := blobstore.Open("blob:test", t.TempDir(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	want := payloads()
	for key, data := range want {
		if err := s.Put(ctx, key, bytes.NewReader(data)); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	for key, data := range want {
		rc, err := s.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s round-trip mismatch: got %d bytes, want %d", key, len(got), len(data))
		}
	}

	usage, err := s.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].KID != 1 || usage[0].Count != int64(len(want)) {
		t.Fatalf("usage = %+v, want kid=1 count=%d", usage, len(want))
	}
}

func TestTamperDetected(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")
	dir := t.TempDir()
	s, err := blobstore.Open("blob:test", dir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Put(ctx, "k", bytes.NewReader(bytes.Repeat([]byte("x"), 200000))); err != nil {
		t.Fatal(err)
	}

	// Flip a byte deep in the ciphertext body; the read must fail authentication.
	p := filepath.Join(dir, "k")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rc, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext, got nil")
	}
}

func TestMigrateRewrapsHeaderOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	c1 := newCodec(t, "correct-horse-battery-staple-001!")
	s1, err := blobstore.Open("blob:test", dir, c1)
	if err != nil {
		t.Fatal(err)
	}
	want := payloads()
	for key, data := range want {
		if err := s1.Put(ctx, key, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	s1.Close() // release the catalog before reopening under the rotated key

	// Rotate the keyring; reopen the same directory.
	c2 := newCodec(t, "correct-horse-battery-staple-001!,fresh-rotated-phrase-2026-xyz!")
	s2, err := blobstore.Open("blob:test", dir, c2)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	res, err := s2.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if res.Recrypted != int64(len(want)) {
		t.Fatalf("migrate recrypted = %d, want %d", res.Recrypted, len(want))
	}

	usage, err := s2.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].KID != 2 {
		t.Fatalf("usage after migrate = %+v, want kid=2", usage)
	}

	mig := cryptostore.NewMigration(s2)
	if ok, _ := mig.CanRetire(ctx, 1); !ok {
		t.Fatal("CanRetire(1) = false after full migration")
	}

	// Bodies still decrypt correctly under the new key (only the DEK was rewrapped).
	for key, data := range want {
		rc, err := s2.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %s after migrate: %v", key, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, data) {
			t.Fatalf("%s mismatch after migrate", key)
		}
	}
}

func TestReindexRebuildsCatalog(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")
	dir := t.TempDir()
	s, err := blobstore.Open("blob:test", dir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	want := payloads()
	for key, data := range want {
		if err := s.Put(ctx, key, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete(ctx, "small"); err != nil {
		t.Fatal(err)
	}

	if err := s.Reindex(ctx); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	usage, err := s.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].Count != int64(len(want)-1) {
		t.Fatalf("usage after reindex = %+v, want count=%d", usage, len(want)-1)
	}
}

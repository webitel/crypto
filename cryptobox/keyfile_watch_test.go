package cryptobox_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/webitel/crypto/cryptobox"
)

func init() {
	cryptobox.DefaultPollInterval = 10 * time.Millisecond
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// waitPrimary polls until ring.Primary().Kid() == want or the deadline expires.
func waitPrimary(t *testing.T, ring *cryptobox.Keyring, want uint16) bool {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ring.Primary().Kid() == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// --- Box cache invalidation on Load ---

func TestBox_CacheInvalidatedOnLoad(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass)
	if err != nil {
		t.Fatal(err)
	}
	box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)

	data := []byte("secret")

	// Encrypt with key1pass — AEAD is derived and cached for KID=1.
	blob1, err := box.Encrypt(ctx, data)
	if err != nil {
		t.Fatal("initial seal:", err)
	}

	// Replace material for KID=1 (same KID, different IKM).
	if err := ring.Load("[1]" + key2pass); err != nil {
		t.Fatal("Load:", err)
	}

	// Encrypt again: cache must be invalidated, new AEAD derived from key2pass.
	blob2, err := box.Encrypt(ctx, data)
	if err != nil {
		t.Fatal("seal after reload:", err)
	}

	// blob2 must decrypt correctly (key2pass AEAD).
	got, err := box.Decrypt(ctx, blob2)
	if err != nil {
		t.Fatal("open blob2 failed — cache not invalidated?", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("plaintext mismatch after reload")
	}

	// blob1 was sealed with key1pass AEAD; the box now uses key2pass — must fail.
	if _, err := box.Decrypt(ctx, blob1); err == nil {
		t.Fatal("expected error opening blob1 after material change; stale AEAD returned from cache")
	}
}

// --- Load ---

func TestLoad_ReplacesState(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Load(key1pass + "," + key2pass); err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary after Load: got %d, want 2", ring.Primary().Kid())
	}
}

func TestLoad_InvalidInput_PreservesState(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Load("bad-key"); err == nil {
		t.Fatal("expected error for invalid input")
	}
	if ring.Primary().Kid() != 1 {
		t.Fatalf("state changed after failed Load: primary=%d, want 1", ring.Primary().Kid())
	}
}

// --- Watch ---

func TestWatch_InitialLoad(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, key1pass+","+key2pass) // primary = kid 2

	ring, _ := cryptobox.ParseKeyring(key1pass) // starts with kid 1

	ctx, cancel := context.WithCancel(context.Background())
	errc := ring.Watch(ctx, path)

	ok := waitPrimary(t, ring, 2)
	cancel()
	for range errc {
	}

	if !ok {
		t.Fatal("Watch did not load file on startup: primary never became 2")
	}
}

func TestWatch_ReloadOnChange(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, key1pass) // kid 1

	ring, _ := cryptobox.ParseKeyring(key1pass)

	ctx, cancel := context.WithCancel(context.Background())
	errc := ring.Watch(ctx, path)

	// Let initial load settle, then change the file.
	time.Sleep(50 * time.Millisecond)
	writeFile(t, path, key1pass+","+key2pass) // primary becomes kid 2

	ok := waitPrimary(t, ring, 2)
	cancel()
	for range errc {
	}

	if !ok {
		t.Fatal("Watch did not reload after file changed: primary never became 2")
	}
}

func TestWatch_InvalidContent_PreservesState(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, "bad-key") // too short, Parse will reject

	ring, _ := cryptobox.ParseKeyring(key1pass) // primary = kid 1

	ctx, cancel := context.WithCancel(context.Background())
	errc := ring.Watch(ctx, path)

	var gotErr bool
	select {
	case err := <-errc:
		gotErr = err != nil
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	for range errc {
	}

	if !gotErr {
		t.Fatal("expected error for invalid file content")
	}
	if ring.Primary().Kid() != 1 {
		t.Fatalf("state changed after bad file: primary=%d, want 1", ring.Primary().Kid())
	}
}

func TestWatch_FileNotFound(t *testing.T) {
	ring, _ := cryptobox.ParseKeyring(key1pass)

	ctx, cancel := context.WithCancel(context.Background())
	errc := ring.Watch(ctx, t.TempDir()+"/nonexistent.conf")

	var gotErr bool
	select {
	case err := <-errc:
		gotErr = err != nil
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	for range errc {
	}

	if !gotErr {
		t.Fatal("expected error for missing file")
	}
}

func TestWatch_CtxCancel_ClosesChannel(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, key1pass)

	ring, _ := cryptobox.ParseKeyring(key1pass)

	ctx, cancel := context.WithCancel(context.Background())
	errc := ring.Watch(ctx, path)

	time.Sleep(50 * time.Millisecond)
	cancel()

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case _, ok := <-errc:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel not closed within 500ms of context cancel")
		}
	}
}

func TestWatch_ErrorRecovery(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, "bad-key") // invalid — too short

	ring, _ := cryptobox.ParseKeyring(key1pass) // primary = kid 1

	ctx, cancel := context.WithCancel(context.Background())
	errc := ring.Watch(ctx, path)

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected non-nil error for invalid content")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected error, got none within timeout")
	}

	// Fix the file; sleep ensures mtime advances.
	time.Sleep(20 * time.Millisecond)
	writeFile(t, path, key1pass+","+key2pass) // primary becomes kid 2

	ok := waitPrimary(t, ring, 2)
	cancel()
	for range errc {
	}

	if !ok {
		t.Fatal("Watch did not recover after file was fixed")
	}
}

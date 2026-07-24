package cryptobox_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/webitel/crypto/cryptobox"
)

const (
	key1pass = "correct-horse-battery-staple-1!"
	key2pass = "correct-horse-battery-staple-2!"
	key3pass = "correct-horse-battery-staple-3!"
)

var ctx = context.Background()

// newBox is a test helper: parses a keyring from passphrase strings and returns a Box.
func newBox(t *testing.T, passes ...string) *cryptobox.Box {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(strings.Join(passes, ","))
	if err != nil {
		t.Fatal(err)
	}
	return cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)
}

// --- Insecure ---

func TestInsecure_PassThrough(t *testing.T) {
	c := cryptobox.Insecure()
	msg := []byte("hello world")

	blob, err := c.Encrypt(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, msg) {
		t.Fatal("Insecure.Encrypt must return data as-is")
	}
	data, err := c.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, msg) {
		t.Fatal("Insecure.Open must return input as-is")
	}
}

// --- Encrypt / Decrypt round-trip ---

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	box := newBox(t, key1pass)
	msg := []byte("sensitive data")

	blob, err := box.Encrypt(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(blob, msg) {
		t.Fatal("ciphertext must differ from plaintext")
	}
	// KID=1 encodes as varint 0x01 — blob[0] is still 1
	if blob[0] != 1 {
		t.Fatalf("kid varint: got %d, want 1", blob[0])
	}

	data, err := box.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, msg) {
		t.Fatalf("decrypted mismatch: got %q, want %q", data, msg)
	}
}

func TestEncrypt_NonDeterministic(t *testing.T) {
	box := newBox(t, key1pass)
	msg := []byte("same input")
	b1, _ := box.Encrypt(ctx, msg)
	b2, _ := box.Encrypt(ctx, msg)
	if bytes.Equal(b1, b2) {
		t.Fatal("two Encrypt calls on the same input must produce different blobs (random nonce)")
	}
}

// TestDecrypt_WrongKeyMaterial: the same KID sealed with different material fails AEAD
// authentication. Box.Decrypt reports ErrDecrypt (naming the KID), with the algorithm's
// error kept in the chain for detail.
func TestDecrypt_WrongKeyMaterial(t *testing.T) {
	blob, err := newBox(t, key1pass).Encrypt(ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Same KID slot, different phrase → key resolves, but the tag will not verify.
	_, err = newBox(t, key2pass).Decrypt(ctx, blob)
	if !errors.Is(err, cryptobox.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("original algorithm error not preserved in chain: %v", err)
	}
}

// --- Key rotation ---

func TestRotation_OldBlobStillReadable(t *testing.T) {
	box1 := newBox(t, key1pass)
	msg := []byte("secret")
	blob, _ := box1.Encrypt(ctx, msg)

	box2 := newBox(t, key1pass, key2pass)
	data, err := box2.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal("old blob must be decryptable after rotation:", err)
	}
	if !bytes.Equal(data, msg) {
		t.Fatal("decrypted content mismatch after rotation")
	}
}

func TestRecrypt(t *testing.T) {
	box1 := newBox(t, key1pass)
	msg := []byte("secret")
	blob, _ := box1.Encrypt(ctx, msg)

	box2 := newBox(t, key1pass, key2pass)
	newBlob, err := cryptobox.Recrypt(ctx, blob, box1, box2)
	if err != nil {
		t.Fatal(err)
	}
	// KID=2 encodes as varint 0x02
	if newBlob[0] != 2 {
		t.Fatalf("re-encrypted blob kid: got %d, want 2", newBlob[0])
	}

	data, err := box2.Decrypt(ctx, newBlob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, msg) {
		t.Fatal("re-encrypted blob must decrypt to the original data")
	}
}

// --- Retired key ---

func TestRetiredKey(t *testing.T) {
	box1 := newBox(t, key1pass)
	blob, _ := box1.Encrypt(ctx, []byte("old data"))

	box2 := newBox(t, "-", key2pass)
	_, err := box2.Decrypt(ctx, blob)
	if !errors.Is(err, cryptobox.ErrKeyRetired) {
		t.Fatalf("expected ErrKeyRetired, got %v", err)
	}
	// Decrypt names the KID the blob asked for, alongside the matchable sentinel.
	if !strings.Contains(err.Error(), "key [1]") {
		t.Fatalf("error should name the blob's KID: %v", err)
	}
}

// --- Validation ---

func TestBlobTooShort(t *testing.T) {
	box := newBox(t, key1pass)
	_, err := box.Decrypt(ctx, []byte{0x01, 0x02})
	if !errors.Is(err, cryptobox.ErrBlobTooShort) {
		t.Fatalf("expected ErrBlobTooShort, got %v", err)
	}
}

func TestParse_LastTombstone_Rejected(t *testing.T) {
	_, err := cryptobox.ParseKeyring(key1pass + ",-")
	if err == nil {
		t.Fatal("expected error when last entry is tombstone")
	}
}

func TestStringMaterial_TooShort(t *testing.T) {
	_, err := cryptobox.NewTextKey(1, "short")
	if !errors.Is(err, cryptobox.ErrInvalidIKM) {
		t.Fatalf("expected ErrInvalidIKM, got %v", err)
	}
}

func TestStringMaterial_InvalidChar(t *testing.T) {
	_, err := cryptobox.NewTextKey(1, "valid-start-but space-inside-it!")
	if !errors.Is(err, cryptobox.ErrInvalidIKM) {
		t.Fatalf("expected ErrInvalidIKM, got %v", err)
	}
}

// --- Parse format ---

func TestParse_ExplicitKID(t *testing.T) {
	ring, err := cryptobox.ParseKeyring("[42]" + key1pass)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 42 {
		t.Fatalf("explicit KID: got %d, want 42", ring.Primary().Kid())
	}
}

func TestParse_HexKID(t *testing.T) {
	ring, err := cryptobox.ParseKeyring("[0x2a]" + key1pass) // 0x2a = 42
	if err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 42 {
		t.Fatalf("hex KID: got %d, want 42", ring.Primary().Kid())
	}
}

func TestParse_TombstoneWithExplicitKID(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass + ",[5]-," + key2pass)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ring.Find(5)
	if !errors.Is(err, cryptobox.ErrKeyRetired) {
		t.Fatalf("expected ErrKeyRetired for [5]-, got %v", err)
	}
}

func TestParse_EscapeCommaInPassphrase(t *testing.T) {
	pass := `correct-horse-battery\,staple-1!`
	ring, err := cryptobox.ParseKeyring(pass)
	if err != nil {
		t.Fatal(err)
	}
	box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)
	blob, err := box.Encrypt(ctx, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := box.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("hi")) {
		t.Fatal("round-trip failed with escaped-comma passphrase")
	}
}

func TestParse_DuplicateKID_Rejected(t *testing.T) {
	_, err := cryptobox.ParseKeyring("[1]" + key1pass + ",[1]" + key2pass)
	if err == nil {
		t.Fatal("expected error for duplicate KID")
	}
}

func TestParse_ZeroKID_Rejected(t *testing.T) {
	_, err := cryptobox.ParseKeyring("[0]" + key1pass)
	if err == nil {
		t.Fatal("expected error for KID=0")
	}
}

// --- FileMaterial viewport ---

func tempFile(t *testing.T, size int) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ikm-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	for i := range data {
		data[i] = byte('A' + i%26)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestFileMaterial_WholeFile(t *testing.T) {
	path := tempFile(t, 64)
	key, err := cryptobox.NewFileKey(1, path)
	if err != nil {
		t.Fatal(err)
	}
	ikm, err := key.KeyMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ikm) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(ikm))
	}
}

func TestFileMaterial_AutoCapsAt256(t *testing.T) {
	path := tempFile(t, 300)
	key, err := cryptobox.NewFileKey(1, path)
	if err != nil {
		t.Fatal(err)
	}
	ikm, _ := key.KeyMaterial(ctx)
	if len(ikm) != 256 {
		t.Fatalf("expected 256 bytes (auto cap), got %d", len(ikm))
	}
}

func TestFileMaterial_WithOffset(t *testing.T) {
	path := tempFile(t, 100)
	key, err := cryptobox.NewFileKey(1, path+":50")
	if err != nil {
		t.Fatal(err)
	}
	ikm, _ := key.KeyMaterial(ctx)
	if len(ikm) != 50 {
		t.Fatalf("expected 50 bytes, got %d", len(ikm))
	}
}

func TestFileMaterial_WithOffsetAndLength(t *testing.T) {
	path := tempFile(t, 100)
	key, err := cryptobox.NewFileKey(1, path+":10:30")
	if err != nil {
		t.Fatal(err)
	}
	ikm, _ := key.KeyMaterial(ctx)
	if len(ikm) != 30 {
		t.Fatalf("expected 30 bytes, got %d", len(ikm))
	}
	if ikm[0] != 'K' {
		t.Fatalf("expected first byte 'K' (offset 10), got %q", ikm[0])
	}
}

func TestFileMaterial_OffsetExceedsFile(t *testing.T) {
	path := tempFile(t, 50)
	_, err := cryptobox.NewFileKey(1, path+":60")
	if !errors.Is(err, cryptobox.ErrInvalidIKM) {
		t.Fatalf("expected ErrInvalidIKM for offset > file size, got %v", err)
	}
}

func TestFileMaterial_ViewportExceedsFile(t *testing.T) {
	path := tempFile(t, 50)
	_, err := cryptobox.NewFileKey(1, path+":10:50")
	if !errors.Is(err, cryptobox.ErrInvalidIKM) {
		t.Fatalf("expected ErrInvalidIKM for viewport beyond file, got %v", err)
	}
}

func TestFileMaterial_LengthExceedsMax(t *testing.T) {
	path := tempFile(t, 300)
	_, err := cryptobox.NewFileKey(1, path+":0:257")
	if !errors.Is(err, cryptobox.ErrInvalidIKM) {
		t.Fatalf("expected ErrInvalidIKM for length > 256, got %v", err)
	}
}

func TestFileMaterial_EffectiveLengthTooSmall(t *testing.T) {
	path := tempFile(t, 25)
	_, err := cryptobox.NewFileKey(1, path+":20")
	if !errors.Is(err, cryptobox.ErrInvalidIKM) {
		t.Fatalf("expected ErrInvalidIKM for effective length < min, got %v", err)
	}
}

func TestFileMaterial_UsableInBox(t *testing.T) {
	path := tempFile(t, 64)
	ring, err := cryptobox.ParseKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)
	blob, err := box.Encrypt(ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := box.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("secret")) {
		t.Fatal("round-trip failed with FileMaterial")
	}
}

// --- Keyring management ---

func TestKeyring_Add_SetPrimary(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := cryptobox.NewTextKey(2, key2pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Add(key2); err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary after Add: got %d, want 2", ring.Primary().Kid())
	}

	if err := ring.SetPrimary(1); err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 1 {
		t.Fatalf("primary after SetPrimary(1): got %d, want 1", ring.Primary().Kid())
	}
}

func TestKeyring_Rotate(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := cryptobox.NewTextKey(2, key2pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Rotate(key2); err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary after Rotate: got %d, want 2", ring.Primary().Kid())
	}

	// Now retire the old key — must succeed since it's no longer primary.
	if err := ring.Retire(1); err != nil {
		t.Fatal(err)
	}
	_, err = ring.Find(1)
	if !errors.Is(err, cryptobox.ErrKeyRetired) {
		t.Fatalf("expected ErrKeyRetired after Retire, got %v", err)
	}
}

func TestKeyring_Retire_NonPrimary(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass + "," + key2pass)
	if err != nil {
		t.Fatal(err)
	}
	// primary = kid 2

	if err := ring.Retire(1); err != nil {
		t.Fatal(err)
	}
	_, err = ring.Find(1)
	if !errors.Is(err, cryptobox.ErrKeyRetired) {
		t.Fatalf("expected ErrKeyRetired after Retire, got %v", err)
	}
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary must not change after retiring non-primary: got %d, want 2", ring.Primary().Kid())
	}
}

func TestKeyring_Retire_Primary_Rejected(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass + "," + key2pass)
	if err != nil {
		t.Fatal(err)
	}
	// primary = kid 2

	err = ring.Retire(2)
	if err == nil {
		t.Fatal("expected error when retiring the primary key")
	}
	// primary must remain unchanged
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary changed after rejected Retire: got %d, want 2", ring.Primary().Kid())
	}
}

func TestKeyring_List(t *testing.T) {
	ring, err := cryptobox.ParseKeyring(key1pass + ",-," + key3pass)
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		kid     uint16
		retired bool
	}
	var got []row
	for key, retired := range ring.List() {
		got = append(got, row{key.Kid(), retired})
	}

	want := []row{{1, false}, {2, true}, {3, false}}
	if len(got) != len(want) {
		t.Fatalf("List() count: got %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("List()[%d]: got %+v, want %+v", i, got[i], w)
		}
	}
}

// These exercise NewKeyring directly (hermetic — no environment). NewKeyring loads
// once and does not watch; hot-reload is opt-in via Keyring.WatchFile, scoped to a
// context cancelled at test cleanup.

func TestNewKeyring_Inline(t *testing.T) {
	ring, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{
		Keyring: strings.Join([]string{key1pass, key2pass, key3pass}, ","),
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ring.Primary().Kid() != 3 {
		t.Fatalf("primary: got %d, want 3", ring.Primary().Kid())
	}
}

// TestNewKeyring_Multiline: a file may list one key per line (blank lines and a
// trailing newline are ignored; implicit KIDs count only real entries).
func TestNewKeyring_Multiline(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, "\n"+key1pass+"\n\n"+key2pass+"\n")

	ring, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: path})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary: got %d, want 2", ring.Primary().Kid())
	}
}

func TestNewKeyring_File(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, key1pass+","+key2pass)

	ring, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: path})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary: got %d, want 2", ring.Primary().Kid())
	}
}

// TestNewKeyring_WatchFile: NewKeyring loads once; WatchFile hot-reloads the source.
func TestNewKeyring_WatchFile(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, key1pass) // kid 1

	ring, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: path})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ring.Primary().Kid() != 1 {
		t.Fatalf("initial primary: got %d, want 1", ring.Primary().Kid())
	}

	errc := ring.WatchFile(t.Context())
	go func() {
		for range errc {
		}
	}()

	// Overwrite — primary becomes kid 2.
	writeFile(t, path, key1pass+","+key2pass)

	if !waitPrimary(t, ring, 2) {
		t.Fatal("hot-reload did not update primary to 2")
	}
}

func TestNewKeyring_FilePrecedence(t *testing.T) {
	path := t.TempDir() + "/keyring.conf"
	writeFile(t, path, key1pass+","+key2pass)

	// File wins over inline Keyring when both are set.
	ring, err := cryptobox.NewKeyring(cryptobox.KeyringOptions{Filename: path, Keyring: key3pass})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// File has 2 keys → primary kid 2; inline has kid 3 → must not be used.
	if ring.Primary().Kid() != 2 {
		t.Fatalf("primary: got %d, want 2 (file must take precedence)", ring.Primary().Kid())
	}
}

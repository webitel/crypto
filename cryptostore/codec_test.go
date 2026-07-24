package cryptostore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

const indexRoot = "blind-index-root-key-0123456789"

func indexRing(t *testing.T) *cryptobox.Keyring {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(indexRoot)
	if err != nil {
		t.Fatalf("Parse index keyring: %v", err)
	}
	return ring
}

func newCodec(t *testing.T, keys string) *cryptostore.Codec {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(keys)
	if err != nil {
		t.Fatalf("Parse keyring: %v", err)
	}
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), indexRing(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")

	blob, err := c.Encrypt(ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(blob, []byte("secret")) {
		t.Fatal("not encrypted")
	}
	data, _, err := c.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret" {
		t.Fatalf("round-trip = %q", data)
	}
}

func TestSearchTokenDomain(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")

	a1, _ := c.SearchToken(ctx, "users.email", []byte("ann@x.io"))
	a2, _ := c.SearchToken(ctx, "users.email", []byte("ann@x.io"))
	if !bytes.Equal(a1, a2) {
		t.Fatal("same domain+value must yield same token")
	}
	if len(a1) != 32 {
		t.Fatalf("token len = %d, want 32", len(a1))
	}

	other, _ := c.SearchToken(ctx, "users.phone", []byte("ann@x.io"))
	if bytes.Equal(a1, other) {
		t.Fatal("different domains must not collide")
	}
}

func TestSearchTokenStableAcrossRotation(t *testing.T) {
	ctx := context.Background()
	// The blind index uses an independent keyring, so rotating the data keyring
	// must NOT change tokens.
	before, _ := newCodec(t, "correct-horse-battery-staple-001!").SearchToken(ctx, "users.email", []byte("ann@x.io"))
	after, _ := newCodec(t, "correct-horse-battery-staple-001!,fresh-rotated-phrase-2026-xyz!").
		SearchToken(ctx, "users.email", []byte("ann@x.io"))
	if !bytes.Equal(before, after) {
		t.Fatalf("token changed across data-key rotation: %x != %x", before, after)
	}
}

func TestSearchTokenNoIndexKey(t *testing.T) {
	ring, _ := cryptobox.ParseKeyring("correct-horse-battery-staple-001!")
	c, _ := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), nil)
	if _, err := c.SearchToken(context.Background(), "users.email", []byte("x")); !errors.Is(err, cryptostore.ErrIndexKey) {
		t.Fatalf("err = %v, want ErrIndexKey", err)
	}
}

func TestPrimaryKIDAndRecrypt(t *testing.T) {
	ctx := context.Background()
	c1 := newCodec(t, "correct-horse-battery-staple-001!")

	if kid, _ := c1.PrimaryKID(ctx); kid != 1 {
		t.Fatalf("primary kid = %d, want 1", kid)
	}

	c2 := newCodec(t, "correct-horse-battery-staple-001!,fresh-rotated-phrase-2026-xyz!")
	if kid, _ := c2.PrimaryKID(ctx); kid != 2 {
		t.Fatalf("primary kid after rotation = %d, want 2", kid)
	}

	// Raw cipher blobs (Cipher()) so KIDOf reads the cryptobox header directly;
	// migrate under c2's primary with cryptobox.Recrypt.
	blob, _ := c1.Cipher().Encrypt(ctx, []byte("secret"))
	if k, _, _ := cryptobox.KIDOf(blob); k != 1 {
		t.Fatalf("sealed kid = %d, want 1", k)
	}
	migrated, err := cryptobox.Recrypt(ctx, blob, c2.Cipher())
	if err != nil {
		t.Fatal(err)
	}
	if k, _, _ := cryptobox.KIDOf(migrated); k != 2 {
		t.Fatalf("recrypted kid = %d, want 2", k)
	}
	if data, _ := c2.Cipher().Decrypt(ctx, migrated); string(data) != "secret" {
		t.Fatalf("recrypt corrupted data: %q", data)
	}
}

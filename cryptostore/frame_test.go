package cryptostore_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

func TestInlineBinaryRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")

	framed, err := c.Encrypt(ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != 0x00 {
		t.Fatalf("binary frame must start with NUL marker, got %#x", framed[0])
	}
	// KID is still readable from the wrapped blob.
	blob, ok := cryptostore.UnframeBinary(framed)
	if !ok {
		t.Fatal("UnframeBinary failed on framed value")
	}
	if kid, _, _ := cryptobox.KIDOf(blob); kid != 1 {
		t.Fatalf("kid = %d, want 1", kid)
	}

	data, enc, err := c.Decrypt(ctx, framed)
	if err != nil || !enc || string(data) != "secret" {
		t.Fatalf("Decrypt = (%q,%v,%v), want (secret,true,nil)", data, enc, err)
	}
}

func TestInlineBinaryPlaintextPassthrough(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")

	// Legacy plaintext (former text → never starts with NUL) passes through.
	legacy := []byte("ann@example.com")
	data, enc, err := c.Decrypt(ctx, legacy)
	if err != nil || enc || !bytes.Equal(data, legacy) {
		t.Fatalf("passthrough = (%q,%v,%v), want (legacy,false,nil)", data, enc, err)
	}
}

func TestInlineBinaryCorruptionErrors(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")
	framed, _ := c.Encrypt(ctx, []byte("secret"))
	framed[len(framed)-1] ^= 0xff // corrupt the tag/ciphertext
	if _, _, err := c.Decrypt(ctx, framed); err == nil {
		t.Fatal("framed-but-corrupt must error, got nil")
	}
}

func TestInlineTextRoundTripAndCoincidence(t *testing.T) {
	ctx := context.Background()
	c := newCodec(t, "correct-horse-battery-staple-001!")

	s, err := c.EncryptText(ctx, []byte("123-45-6789"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := c.DecryptText(ctx, s); err != nil || string(got) != "123-45-6789" {
		t.Fatalf("DecryptText round-trip = (%q,%v)", got, err)
	}
	// Plain string without the tag → passthrough.
	if got, enc, _ := c.DecryptText(ctx, "just text"); enc || string(got) != "just text" {
		t.Fatalf("text passthrough failed: %q enc=%v", got, enc)
	}
	// Tag present but not real ciphertext → treated as plaintext (no error).
	if _, enc, err := c.DecryptText(ctx, "cbox:not-base64-$$"); err != nil || enc {
		t.Fatalf("bad-tag value = (enc=%v,%v), want (false,nil)", enc, err)
	}
}

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

func mustRing(t *testing.T, s string) *cryptobox.Keyring {
	t.Helper()
	r, err := cryptobox.ParseKeyring(s)
	if err != nil {
		t.Fatalf("Parse keyring %q: %v", s, err)
	}
	return r
}

func testCodec(t *testing.T) *cryptostore.Codec {
	t.Helper()
	cr, err := cryptostore.NewCodec(
		cryptobox.NewBox(cryptobox.ChaCha20Poly1305, mustRing(t, "correct-horse-battery-staple-001!")),
		mustRing(t, "blind-index-root-key-0123456789"),
	)
	if err != nil {
		t.Fatalf("New codec: %v", err)
	}
	return cr
}

func TestDecryptValue(t *testing.T) {
	ctx := context.Background()
	cr := testCodec(t)

	// bytea column form: \x-hex of a binary-framed value.
	framed, err := cr.Encrypt(ctx, []byte("ann@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	data, enc, err := decryptValue(ctx, cr, `\x`+hex.EncodeToString(framed))
	if err != nil || !enc || string(data) != "ann@example.com" {
		t.Fatalf("bytea decrypt: data=%q enc=%v err=%v", data, enc, err)
	}

	// same ciphertext, alternative encodings of the raw bytes.
	for _, in := range []string{
		"0x" + hex.EncodeToString(framed),
		"hex:" + hex.EncodeToString(framed),
		"base64:" + base64.StdEncoding.EncodeToString(framed),
		"base64:" + base64.RawURLEncoding.EncodeToString(framed),
	} {
		p, e, err := decryptValue(ctx, cr, in)
		if err != nil || !e || string(p) != "ann@example.com" {
			t.Fatalf("decrypt %q: data=%q enc=%v err=%v", in, p, e, err)
		}
	}

	// json/text attribute form: cbox:base64.
	txt, err := cr.EncryptText(ctx, []byte("123-45-6789"))
	if err != nil {
		t.Fatal(err)
	}
	data, enc, err = decryptValue(ctx, cr, txt)
	if err != nil || !enc || string(data) != "123-45-6789" {
		t.Fatalf("text decrypt: data=%q enc=%v err=%v", data, enc, err)
	}

	// legacy plaintext stored as bytea: not framed → passthrough, encrypted=false.
	data, enc, err = decryptValue(ctx, cr, `\x`+hex.EncodeToString([]byte("legacy")))
	if err != nil || enc || string(data) != "legacy" {
		t.Fatalf("legacy passthrough: data=%q enc=%v err=%v", data, enc, err)
	}

	// unrecognized form (neither \x/0x nor cbox:).
	if _, _, err := decryptValue(ctx, cr, "just-text"); err == nil {
		t.Fatal("expected error for unrecognized value")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	cr := testCodec(t)

	// binary framing: seal, then feed the sealed bytes back under every byte scheme.
	framed, err := cr.Encrypt(ctx, []byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		`\x` + hex.EncodeToString(framed),
		"hex:" + hex.EncodeToString(framed),
		"base64:" + base64.StdEncoding.EncodeToString(framed),
	} {
		p, enc, err := decryptValue(ctx, cr, in)
		if err != nil || !enc || string(p) != "top-secret" {
			t.Fatalf("binary round-trip %q: p=%q enc=%v err=%v", in, p, enc, err)
		}
	}

	// text framing: the cbox string decrypts back.
	txt, err := cr.EncryptText(ctx, []byte("json-secret"))
	if err != nil {
		t.Fatal(err)
	}
	p, enc, err := decryptValue(ctx, cr, txt)
	if err != nil || !enc || string(p) != "json-secret" {
		t.Fatalf("text round-trip: p=%q enc=%v err=%v", p, enc, err)
	}
}

func TestEncodeValue(t *testing.T) {
	b := []byte{0x00, 0x01, 0xff}
	cases := map[string]string{
		"pgbytea": `\x0001ff`,
		"hex":     "0001ff",
		"base64":  base64.StdEncoding.EncodeToString(b),
	}
	for out, want := range cases {
		got, err := encodeValue(b, out)
		if err != nil || got != want {
			t.Fatalf("encodeValue(%s) = %q, %v; want %q", out, got, err, want)
		}
	}
	if _, err := encodeValue(b, "bogus"); err == nil {
		t.Fatal("expected error for unknown --out")
	}
}

func TestFileScheme(t *testing.T) {
	ctx := context.Background()
	cr := testCodec(t)
	dir := t.TempDir()

	// encrypt a plaintext FILE to a ciphertext FILE, then decrypt the file back.
	ptFile := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(ptFile, []byte("file-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readPlaintext("file:" + ptFile)
	if err != nil || string(data) != "file-content" {
		t.Fatalf("readPlaintext(file:): %q %v", data, err)
	}
	framed, err := cr.Encrypt(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	ctFile := filepath.Join(dir, "cipher.bin")
	if err := emitValue(framed, "file:"+ctFile); err != nil {
		t.Fatal(err)
	}
	got, enc, err := decryptValue(ctx, cr, "file:"+ctFile)
	if err != nil || !enc || string(got) != "file-content" {
		t.Fatalf("decrypt file: got=%q enc=%v err=%v", got, enc, err)
	}
}

func TestStreamFileRoundTrip(t *testing.T) {
	ctx := context.Background()
	cr := testCodec(t)
	dir := t.TempDir()

	// > chunkSize (64 KiB) to exercise multiple chunks + the last-flag boundary.
	data := make([]byte, 150*1024)
	for i := range data {
		data[i] = byte(i * 7)
	}
	src := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "big.enc")
	if _, n, err := streamEncryptFile(ctx, cr, src, enc); err != nil || n != int64(len(data)) {
		t.Fatalf("encrypt-file: n=%d err=%v", n, err)
	}
	// The ciphertext must differ from the plaintext (and be a WBS stream: magic \x89WBS).
	ct, _ := os.ReadFile(enc)
	if string(ct[:4]) != "\x89WBS" {
		t.Fatalf("ciphertext is not a WBS stream: %x", ct[:4])
	}
	dec := filepath.Join(dir, "big.out")
	if n, err := streamDecryptFile(ctx, cr, enc, dec); err != nil || n != int64(len(data)) {
		t.Fatalf("decrypt-file: n=%d err=%v", n, err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != string(data) {
		t.Fatalf("round-trip mismatch: %d vs %d bytes", len(got), len(data))
	}
}

func TestInlineFileSizeCap(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(big, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	old := maxInlineFileBytes
	maxInlineFileBytes = 1024
	defer func() { maxInlineFileBytes = old }()

	if _, ok, err := resolveBytes("file:" + big); !ok || err == nil {
		t.Fatalf("oversize file: want (ok=true, err!=nil), got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(resolveErr(t, "file:"+big), "encrypt-file") {
		t.Fatal("error should point to encrypt-file")
	}
}

func resolveErr(t *testing.T, arg string) string {
	t.Helper()
	_, _, err := resolveBytes(arg)
	if err == nil {
		t.Fatal("expected error")
	}
	return err.Error()
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	cr := testCodec(t)

	// scalar field: key equals the field name, token matches the codec.
	sc, err := schema.ParseConfig([]byte(`{"version":1,"units":{"directory.users":{"fields":{
	  "email":   {"search": true},
	  "profile": {"nested": [{"path":["$.ssn"],"search":true}]}
	}}}}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	codec, err := schema.NewCodec(schema.WithBase(cr), schema.WithBaseline(sc))
	if err != nil {
		t.Fatal(err)
	}

	// scalar field token matches schema.SearchKey + codec.SearchToken.
	key := schema.SearchKey("email")
	tok, err := cr.SearchToken(ctx, "directory.users."+key, []byte("a@x.io"))
	if err != nil {
		t.Fatalf("SearchToken: %v", err)
	}
	_, codecToken, err := codec.SearchToken(ctx, "directory.users", "email", "a@x.io")
	if err != nil {
		t.Fatalf("codec.SearchToken: %v", err)
	}
	if base64.RawURLEncoding.EncodeToString(tok) != codecToken {
		t.Fatalf("scalar token mismatch: %s vs %s", base64.RawURLEncoding.EncodeToString(tok), codecToken)
	}

	// json attribute: key is "profile.ssn".
	if got := schema.SearchKey("profile", "ssn"); got != "profile.ssn" {
		t.Fatalf("json key = %q, want profile.ssn", got)
	}

	// two equal plaintexts in the same domain produce the same token.
	tok2, _ := cr.SearchToken(ctx, "directory.users.email", []byte("a@x.io"))
	if base64.RawURLEncoding.EncodeToString(tok) != base64.RawURLEncoding.EncodeToString(tok2) {
		t.Fatal("same plaintext/domain produced different tokens")
	}

	// different domain → different token.
	other, _ := cr.SearchToken(ctx, "directory.users.phone", []byte("a@x.io"))
	if base64.RawURLEncoding.EncodeToString(tok) == base64.RawURLEncoding.EncodeToString(other) {
		t.Fatal("different domains produced the same token")
	}
}

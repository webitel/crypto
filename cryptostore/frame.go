package cryptostore

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
)

// Inline framing makes a stored value self-identifying as ciphertext, so encrypted
// data can co-locate with legacy plaintext in the same column or json attribute
// (no separate ciphertext column, opportunistic migration). The marker is only a
// cheap filter; AEAD authentication is the real arbiter.
//
// Two transport encodings wrap the same cryptobox blob (which carries the KID):
//
//   - Binary (bytea column): binTag ‖ blob. The leading NUL byte cannot
//     appear in a value converted from a Postgres text column (text forbids NUL),
//     so it is unambiguous there. The second byte is the inline-envelope format
//     version (NOT the cipher algorithm — that stays implicit in the cryptobox
//     Box); bump it only on a layout change.
//   - Text (json attribute / text): textTag ‖ base64(blob), a JSON-safe string.
//     The tag is an opaque scheme marker with no in-band version field: a future
//     layout change registers a new tag rather than bumping a digit (the binary
//     frame keeps its version byte because NUL already discriminates there).
var binTag = []byte{0x00, 0x01} // NUL, format v1

const textTag = "cbox:" // cryptobox blob

// FrameBinary wraps blob for storage in a bytea column.
func FrameBinary(blob []byte) []byte {
	if len(blob) == 0 {
		return nil // NULL
	}
	out := make([]byte, len(binTag)+len(blob))
	copy(out, binTag)
	copy(out[len(binTag):], blob)
	return out
}

// UnframeBinary returns the wrapped blob and true if v carries the binary tag.
func UnframeBinary(v []byte) ([]byte, bool) {
	return bytes.CutPrefix(v, binTag)
}

// FrameText wraps blob as a JSON-safe string (tagged base64).
func FrameText(blob []byte) string {
	if len(blob) == 0 {
		return "" // NULL
	}
	return textTag + base64.StdEncoding.EncodeToString(blob)
}

// UnframeText returns the wrapped blob and true if s carries the text tag and
// decodes as base64.
func UnframeText(s string) ([]byte, bool) {
	if !strings.HasPrefix(s, textTag) {
		return nil, false
	}
	blob, err := base64.StdEncoding.DecodeString(s[len(textTag):])
	if err != nil {
		return nil, false
	}
	return blob, true
}

// Encrypt seals data and binary-frames it for a bytea column (self-marking
// ciphertext). For raw, unframed sealing use Cipher().Encrypt.
func (c *Codec) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	blob, err := c.cipher.Encrypt(ctx, data)
	if err != nil {
		return nil, err
	}
	return FrameBinary(blob), nil
}

// Decrypt decrypts a binary-framed value. If v is not framed it is treated as
// legacy plaintext and returned unchanged with encrypted=false. A framed value
// that fails authentication is an error: the binary tag (leading NUL) cannot
// occur in former text, so a failure means corruption, not a coincidence. For raw,
// unframed opening use Cipher().Decrypt.
func (c *Codec) Decrypt(ctx context.Context, v []byte) (data []byte, encrypted bool, err error) {
	blob, ok := UnframeBinary(v)
	if !ok {
		return v, false, nil
	}
	data, err = c.cipher.Decrypt(ctx, blob)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// EncryptText seals data and text-frames it for a json attribute.
func (c *Codec) EncryptText(ctx context.Context, data []byte) (string, error) {
	blob, err := c.cipher.Encrypt(ctx, data)
	if err != nil {
		return "", err
	}
	return FrameText(blob), nil
}

// RecryptText re-encrypts a text-framed value under the current primary key,
// returning the new framed string. A value that is not tagged (or fails to open)
// is returned unchanged with recrypted=false — used to migrate json attributes.
func (c *Codec) RecryptText(ctx context.Context, s string) (out string, recrypted bool, err error) {
	blob, ok := UnframeText(s)
	if !ok {
		return s, false, nil
	}
	data, err := c.cipher.Decrypt(ctx, blob)
	if err != nil {
		return s, false, nil
	}
	out, err = c.EncryptText(ctx, data)
	if err != nil {
		return s, false, err
	}
	return out, true, nil
}

// DecryptText decrypts a text-framed value. If s is not tagged it is returned as
// plaintext bytes with encrypted=false. A tagged value that fails authentication
// is also treated as plaintext (the text tag could, unlike the binary tag,
// coincide with a legitimate plaintext string).
func (c *Codec) DecryptText(ctx context.Context, s string) (data []byte, encrypted bool, err error) {
	blob, ok := UnframeText(s)
	if !ok {
		return []byte(s), false, nil
	}
	data, err = c.cipher.Decrypt(ctx, blob)
	if err != nil {
		return []byte(s), false, nil
	}
	return data, true, nil
}

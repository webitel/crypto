package cryptobox

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const hkdfInfoChaCha20 = "webitel.cryptobox.v1.chacha20poly1305"

// ChaCha20Poly1305 is a CipherFunc that derives a ChaCha20-Poly1305 AEAD
// from key.Material() using HKDF-SHA256.
//
// Usage:
//
//	box := cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring)
func ChaCha20Poly1305(ctx context.Context, key Key) (cipher.AEAD, error) {
	ikm, err := key.KeyMaterial(ctx)
	if err != nil {
		return nil, err
	}
	derived, err := deriveKey(ikm, hkdfInfoChaCha20, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(derived)
}

// deriveKey runs HKDF-SHA256(ikm, salt=nil, info) and returns size bytes.
// Changing info produces a completely different key from the same IKM —
// use distinct info strings per algorithm to ensure domain separation.
func deriveKey(ikm []byte, info string, size int) ([]byte, error) {
	h := hkdf.New(sha256.New, ikm, nil, []byte(info))
	key := make([]byte, size)
	_, err := io.ReadFull(h, key)
	return key, err
}

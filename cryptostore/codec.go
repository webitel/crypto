package cryptostore

import (
	"context"
	"fmt"

	"github.com/webitel/crypto/cryptobox"
)

// Codec is the storage-agnostic, value-oriented cryptographic core: it encrypts and
// decrypts individual values — with self-marking inline framing (see frame.go) —
// and derives blind-index search tokens. It knows nothing about tables, columns,
// objects or any storage shape; higher layers build on it (cryptostore/schema is
// the record-oriented codec for row stores, blob stores wrap objects, …).
//
// Codec.Encrypt/Decrypt add the inline frame; for raw, unframed cryptobox
// operations (e.g. wrapping a DEK) use Cipher() directly. A Codec is safe for
// concurrent use.
//
// As in cryptobox, data denotes open, unencrypted bytes (the cleartext in/out of
// the codec) — not necessarily human-readable text; blob/value denote ciphertext.
type Codec struct {
	cipher cryptobox.Cipher
	bindex *blindIndex
}

// NewCodec builds the value codec from a cryptobox cipher (value encryption; the
// key version is carried in the blob header) and an optional blind-index keyring.
// Pass a nil index when no searchable data is used; SearchToken then returns
// ErrIndexKey. Keep the index keyring independent of the cipher keyring so
// data-key rotation does not invalidate search tokens.
func NewCodec(cipher cryptobox.Cipher, index *cryptobox.Keyring) (*Codec, error) {
	if cipher == nil {
		return nil, fmt.Errorf("cryptostore: <nil> cipher")
	}
	c := &Codec{cipher: cipher}
	if index != nil {
		bi, err := newBlindIndex(index)
		if err != nil {
			return nil, err
		}
		c.bindex = bi
	}
	return c, nil
}

// Cipher returns the underlying cryptobox cipher for raw, unframed encryption —
// e.g. wrapping a per-object DEK, or a value that carries its own envelope.
// Codec.Encrypt/Decrypt add the inline self-marking frame; Cipher().Encrypt/Decrypt
// do not (and never migrate legacy data).
func (c *Codec) Cipher() cryptobox.Cipher { return c.cipher }

// CanIndex reports whether a blind-index keyring was configured, i.e. whether
// SearchToken works. Stores use it to fail fast when a schema declares searchable
// fields but no search keyring is available.
func (c *Codec) CanIndex() bool { return c.bindex != nil }

// SearchToken returns the deterministic blind-index token for data, scoped
// to domain (e.g. "schema.table.column"). Equal data under the same domain
// yields an equal token, enabling exact-match lookups without revealing the key;
// different domains never collide. Returns ErrIndexKey if no index keyring was
// configured. ctx is threaded to the keyring's KeyMaterial source (file, KMS, …).
func (c *Codec) SearchToken(ctx context.Context, domain string, data []byte) ([]byte, error) {
	if c.bindex == nil {
		return nil, fmt.Errorf("%w: no index keyring configured", ErrIndexKey)
	}
	return c.bindex.token(ctx, domain, data)
}

// PrimaryKID reports the key version Encrypt currently uses, by sealing an empty
// probe and reading its header. It needs no access to the keyring, so key material
// stays inside cryptobox.
func (c *Codec) PrimaryKID(ctx context.Context) (cryptobox.KID, error) {
	probe, err := c.cipher.Encrypt(ctx, nil)
	if err != nil {
		return 0, err
	}
	kid, _, err := cryptobox.KIDOf(probe)
	return kid, err
}

package cryptostore

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync"

	"github.com/webitel/crypto/cryptobox"
)

// bindexInfo is the HKDF domain separator for blind-index subkeys. Bump the
// version suffix only for a deliberate, breaking change to token derivation —
// it invalidates every stored token and forces a full reindex.
const bindexInfo = "webitel.cryptostore.bindex.v1"

// blindIndex derives deterministic, keyed search tokens for exact-match lookups
// over encrypted values.
//
// The token for a value is HMAC-SHA256(subkey, data), where subkey is
// HKDF-SHA256 of a single root key bound to a caller-supplied domain string.
// Callers scope the domain to a logical location (e.g. "schema.table.column"),
// so the same data under two domains yields two different tokens and cannot
// be correlated across them. The domain is opaque to the blind index — it stays
// storage-agnostic, while the field layer derives domains from "unit.field".
//
// The index keyring is intentionally SEPARATE from the data-encryption keyring:
// rotating the data keys must not invalidate search tokens (which would force a
// full reindex). Today only the index keyring's PRIMARY key derives tokens, and
// rotating it is a full reindex (tokens carry no key version) — so in practice it
// holds a single, stable key. Holding the keyring (not raw bytes) is deliberate
// groundwork for a future versioned-token rotation; see the design backlog.
//
// Tokens are the full 32-byte HMAC — no truncation — so exact-match queries
// never collide. (Truncating to a Bloom filter would trade precision for fuzzy
// matching; that is out of scope for equality search.)
type blindIndex struct {
	ring *cryptobox.Keyring

	mu   sync.Mutex
	keys map[string][]byte // "<primaryKID>\x00<domain>" -> derived subkey
}

// newBlindIndex builds a blind index over an index keyring. Token derivation uses
// the keyring's primary key material as the HKDF root.
func newBlindIndex(ring *cryptobox.Keyring) (*blindIndex, error) {
	if ring == nil {
		return nil, fmt.Errorf("%w: nil index keyring", ErrIndexKey)
	}
	return &blindIndex{ring: ring, keys: map[string][]byte{}}, nil
}

// subkey derives (and caches) the HKDF subkey for domain under the primary key.
// The cache is keyed by primary KID too, so a keyring reload that changes the
// primary never serves a stale subkey.
func (x *blindIndex) subkey(ctx context.Context, domain string) ([]byte, error) {
	primary := x.ring.Primary()
	cacheKey := strconv.FormatUint(uint64(primary.Kid()), 10) + "\x00" + domain

	x.mu.Lock()
	defer x.mu.Unlock()
	if k, ok := x.keys[cacheKey]; ok {
		return k, nil
	}
	root, err := primary.KeyMaterial(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIndexKey, err)
	}
	if len(root) < 16 {
		return nil, fmt.Errorf("%w: index key material must be at least 16 bytes, got %d", ErrIndexKey, len(root))
	}
	k, err := hkdf.Key(sha256.New, root, nil, bindexInfo+":"+domain, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("cryptostore: derive blind-index key: %w", err)
	}
	x.keys[cacheKey] = k
	return k, nil
}

// token computes the search token for data under the domain's subkey.
func (x *blindIndex) token(ctx context.Context, domain string, data []byte) ([]byte, error) {
	key, err := x.subkey(ctx, domain)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

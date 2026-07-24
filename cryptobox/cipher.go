package cryptobox

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// Cipher encrypts and decrypts versioned blobs.
// Blob format: [kid: varint 1–3B][nonce: N bytes][ciphertext + tag].
//
// Naming convention (throughout cryptobox and cryptostore): data is open,
// unencrypted bytes — the cleartext passed to Encrypt and returned by Decrypt.
// It is deliberately not called "plaintext": what matters is only that it is
// unencrypted, not that it is human-readable text. blob is the sealed ciphertext.
type Cipher interface {
	Encrypt(ctx context.Context, data []byte) (blob []byte, err error)
	Decrypt(ctx context.Context, blob []byte) (data []byte, err error)
}

// CipherFunc derives a cipher.AEAD from a Key's material.
// Implement this to add new encryption algorithms.
type CipherFunc func(ctx context.Context, of Key) (cipher.AEAD, error)

// Box combines a Keyring with a CipherFunc to implement Cipher.
// Encrypt uses the primary key; Decrypt routes by the kid varint in the blob header.
//
// Derived cipher.AEADs are cached by kid after the first use.
// The cache is safe for concurrent use.
type Box struct {
	ring        *Keyring
	algo        CipherFunc
	mu          sync.RWMutex
	cache       map[KID]cipher.AEAD
	ringVersion uint64
}

// *Box implements Cipher interface
var _ Cipher = (*Box)(nil)

// NewBox creates a Box that routes keys by kid and derives AEADs via algo.
func NewBox(algo CipherFunc, keys *Keyring) *Box {
	if algo == nil {
		algo = DefaultAlgo
	}
	return &Box{
		algo:        algo,
		ring:        keys,
		cache:       make(map[KID]cipher.AEAD),
		ringVersion: keys.version.Load(),
	}
}

func (c *Box) aead(ctx context.Context, key Key) (cipher.AEAD, error) {
	kid := key.Kid()
	rv := c.ring.version.Load()

	c.mu.RLock()
	if a, ok := c.cache[kid]; ok && c.ringVersion == rv {
		c.mu.RUnlock()
		return a, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-read version after acquiring the write lock — another goroutine may have
	// already rebuilt the cache between our RUnlock and Lock.
	rv = c.ring.version.Load()
	if a, ok := c.cache[kid]; ok && c.ringVersion == rv {
		return a, nil
	}
	if c.ringVersion != rv {
		c.cache = make(map[KID]cipher.AEAD)
		c.ringVersion = rv
	}
	a, err := c.algo(ctx, key)
	if err != nil {
		return nil, err
	}
	c.cache[kid] = a
	return a, nil
}

// Box implements Cipher interface
var _ Cipher = (*Box)(nil)

func (c *Box) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	key := c.ring.Primary()

	aead, err := c.aead(ctx, key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	var kidBuf [maxKIDBytes]byte
	kidLen := encodeKID(kidBuf[:], key.Kid())

	out := make([]byte, 0, kidLen+len(nonce)+len(data)+aead.Overhead())
	out = append(out, kidBuf[:kidLen]...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, data, nil), nil
}

func (c *Box) Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		// no data
		return nil, nil
	}

	kid, kidLen, err := decodeKID(blob)
	if err != nil {
		return nil, err
	}

	key, err := c.ring.Find(kid)
	if err != nil {
		// Name the KID the blob asked for; the sentinel (ErrKeyNotFound / ErrKeyRetired)
		// stays matchable via errors.Is.
		return nil, fmt.Errorf("%w (key [%d])", err, kid)
	}

	aead, err := c.aead(ctx, key)
	if err != nil {
		return nil, err
	}

	start := kidLen
	if len(blob) < start+aead.NonceSize()+aead.Overhead() {
		return nil, ErrBlobTooShort
	}

	nonce := blob[start : start+aead.NonceSize()]
	data, err := aead.Open(nil, nonce, blob[start+aead.NonceSize():], nil)
	if err != nil {
		// The key was resolved (kid is in the ring) but AEAD authentication failed.
		// This is indistinguishable between a changed/wrong key for this kid and a
		// corrupt/foreign blob — so name the kid and keep the algorithm's error.
		return nil, fmt.Errorf("%w: key [%d] does not authenticate this data — its key material changed, or the data is corrupt: %w", ErrDecrypt, kid, err)
	}
	return data, nil
}

// KIDOf reports which key a blob was sealed with by decoding the kid varint
// in the blob header, without decrypting. It returns the kid and the number of
// header bytes the varint occupied. Use it to route a blob to the right key, to
// group stored blobs by key version (usage metrics), or to detect blobs still
// sealed under a non-primary key during migration.
//
// It does not authenticate the blob: a corrupt header may decode to an arbitrary
// kid. The kid is only trustworthy once Open succeeds.
func KIDOf(blob []byte) (kid KID, headerLen int, err error) {
	return decodeKID(blob)
}

// maxKIDBytes is the maximum number of bytes a varint-encoded uint16 can occupy.
const maxKIDBytes = 3

// encodeKID encodes kid into dst as a protobuf varint and returns the number of bytes written.
func encodeKID(dst []byte, kid KID) int {
	v := uint32(kid)
	n := 0
	for v >= 0x80 {
		dst[n] = byte(v&0x7f) | 0x80
		v >>= 7
		n++
	}
	dst[n] = byte(v)
	return n + 1
}

// decodeKID decodes a protobuf varint KID from the start of blob.
// Returns the decoded KID, the number of bytes consumed, and any error.
func decodeKID(blob []byte) (kid KID, n int, err error) {
	var v uint32
	for i := 0; i < maxKIDBytes && i < len(blob); i++ {
		b := blob[i]
		v |= uint32(b&0x7f) << (7 * uint(i))
		if b < 0x80 {
			return KID(v), i + 1, nil
		}
	}
	return 0, 0, ErrBlobTooShort
}

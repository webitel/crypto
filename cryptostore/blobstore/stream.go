package blobstore

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

// Object encryption uses envelope encryption with a streaming body:
//
//   - A fresh 32-byte data key (DEK) is generated per object and wrapped with the
//     cryptostore codec (cryptobox Encrypt). The wrapped DEK carries the key
//     version (KID) in its header, so an object's key version is readable without
//     touching the body — and key migration only re-wraps this small header.
//   - The body is encrypted with ChaCha20-Poly1305 in fixed-size chunks. Each
//     chunk's nonce is prefix(7) ‖ counter(uint32) ‖ last-flag(1); the counter
//     orders chunks and the last-flag marks the final one, so truncation or
//     reordering fails authentication.
//
// File layout:
//
//	[0:4]    magic \x89 'W' 'B' 'S'  (leading \x89 marks the stream binary, so a tool
//	         or transport can't mistake it for text and silently mangle it)
//	[4:5]    format version (formatVer)
//	[5:7]    wrapped-DEK length (uint16, big-endian)
//	[7:71]   wrapped DEK, zero-padded to hdrAreaLen
//	[71:78]  stream nonce prefix (7 bytes)
//	[78:]    ciphertext chunks
//
// The magic is a format tag, not a security check: the wrapped DEK and every body
// chunk are AEAD-authenticated, so a forged or hand-edited header fails to open. The
// header area is fixed-size so a migration can overwrite the wrapped DEK in place
// (the version, prefix, and body never move).
const (
	magic      = "\x89WBS" // 4-byte signature; leading \x89 marks the stream binary
	formatVer  = 1         // WBS format version, stored in the byte right after magic
	hdrAreaLen = 64        // a cryptobox-wrapped 32B DEK is <= 63 bytes
	prefixLen  = 7
	verOff     = 4                     // format-version byte
	lenOff     = 5                     // wrapped-DEK length (uint16, big-endian)
	wrapOff    = 7                     // wrapped DEK
	prefixOff  = wrapOff + hdrAreaLen  // 71
	bodyOff    = prefixOff + prefixLen // 78
	dekLen     = chacha20poly1305.KeySize
	chunkSize  = 64 * 1024
)

// Seal stream-encrypts r into w under codec (envelope DEK + chunked STREAM body)
// and returns the object's key version and the number of plaintext bytes consumed.
// Memory use is bounded to a few fixed-size chunks regardless of input size, so it
// suits large inputs. The output is the WBS object format documented above; read
// it back with OpenReader.
func Seal(ctx context.Context, codec *cryptostore.Codec, w io.Writer, r io.Reader) (cryptobox.KID, int64, error) {
	return seal(ctx, codec, w, r)
}

// OpenReader returns a streaming reader that decrypts a WBS object read from src
// (as written by Seal). Decryption is chunked, so memory stays bounded.
func OpenReader(ctx context.Context, codec *cryptostore.Codec, src io.Reader) (io.Reader, error) {
	return openReader(ctx, codec, src)
}

// seal encrypts r into w and returns the object's key version and the number of
// plaintext bytes consumed.
func seal(ctx context.Context, codec *cryptostore.Codec, w io.Writer, r io.Reader) (cryptobox.KID, int64, error) {
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return 0, 0, err
	}
	wrapped, err := codec.Cipher().Encrypt(ctx, dek)
	if err != nil {
		return 0, 0, err
	}
	if len(wrapped) > hdrAreaLen {
		return 0, 0, fmt.Errorf("blobstore: wrapped DEK %d bytes exceeds header area %d", len(wrapped), hdrAreaLen)
	}
	kid, _, err := cryptobox.KIDOf(wrapped)
	if err != nil {
		return 0, 0, err
	}

	hdr := make([]byte, bodyOff)
	copy(hdr, magic)        // [0:4]
	hdr[verOff] = formatVer // [4]
	binary.BigEndian.PutUint16(hdr[lenOff:wrapOff], uint16(len(wrapped)))
	copy(hdr[wrapOff:prefixOff], wrapped)
	prefix := hdr[prefixOff:bodyOff]
	if _, err := rand.Read(prefix); err != nil {
		return 0, 0, err
	}
	if _, err := w.Write(hdr); err != nil {
		return 0, 0, err
	}

	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		return 0, 0, err
	}

	var total int64
	var counter uint32
	cur := make([]byte, chunkSize)
	next := make([]byte, chunkSize)

	cn, cerr := readChunk(r, cur)
	if cerr != nil {
		return 0, 0, cerr
	}
	for {
		nn, nerr := readChunk(r, next)
		if nerr != nil {
			return 0, 0, nerr
		}
		last := nn == 0
		ct := aead.Seal(nil, makeNonce(prefix, counter, last), cur[:cn], nil)
		if _, err := w.Write(ct); err != nil {
			return 0, 0, err
		}
		total += int64(cn)
		if last {
			break
		}
		if counter == ^uint32(0) {
			return 0, 0, fmt.Errorf("blobstore: object too large")
		}
		counter++
		cur, next = next, cur
		cn = nn
	}
	return kid, total, nil
}

// openReader returns a streaming reader that decrypts the object in src.
func openReader(ctx context.Context, codec *cryptostore.Codec, src io.Reader) (io.Reader, error) {
	hdr := make([]byte, bodyOff)
	if _, err := io.ReadFull(src, hdr); err != nil {
		return nil, fmt.Errorf("blobstore: read header: %w", err)
	}
	wl, err := parseHeader(hdr)
	if err != nil {
		return nil, err
	}
	dek, err := codec.Cipher().Decrypt(ctx, hdr[wrapOff:wrapOff+wl])
	if err != nil {
		return nil, fmt.Errorf("blobstore: unwrap DEK: %w", err)
	}
	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, prefixLen)
	copy(prefix, hdr[prefixOff:bodyOff])

	return &decryptReader{
		src:    src,
		aead:   aead,
		prefix: prefix,
		curCT:  make([]byte, chunkSize+aead.Overhead()),
		nextCT: make([]byte, chunkSize+aead.Overhead()),
	}, nil
}

type decryptReader struct {
	src    io.Reader
	aead   cipher.AEAD
	prefix []byte

	counter uint32
	curCT   []byte
	nextCT  []byte
	primed  bool

	data []byte // decrypted, not yet returned
	off  int
	eof  bool
	err  error
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for d.off >= len(d.data) {
		if d.err != nil {
			return 0, d.err
		}
		if d.eof {
			return 0, io.EOF
		}
		if err := d.fill(); err != nil {
			d.err = err
			if len(d.data) == 0 {
				return 0, err
			}
			break
		}
	}
	n := copy(p, d.data[d.off:])
	d.off += n
	return n, nil
}

func (d *decryptReader) fill() error {
	if !d.primed {
		n, err := readChunk(d.src, d.curCT)
		if err != nil {
			return err
		}
		d.curCT = d.curCT[:n]
		d.primed = true
	}
	nn, err := readChunk(d.src, d.nextCT)
	if err != nil {
		return err
	}
	last := nn == 0
	data, err := d.aead.Open(d.data[:0], makeNonce(d.prefix, d.counter, last), d.curCT, nil)
	if err != nil {
		return fmt.Errorf("blobstore: decrypt chunk %d: %w", d.counter, err)
	}
	d.data = data
	d.off = 0
	d.counter++
	if last {
		d.eof = true
		return nil
	}
	d.curCT, d.nextCT = d.nextCT[:nn], d.curCT[:cap(d.curCT)]
	return nil
}

// rekey re-wraps the object's DEK header under the current primary key, in place,
// without touching the body. It returns the new key version and whether the
// header was rewritten (false if already under the primary key). hdr is the
// object's fixed header region [0:prefixOff); rewritten is the bytes to write back
// at offset lenOff (the wrapped-DEK length and area, prefix untouched).
func rekey(ctx context.Context, codec *cryptostore.Codec, hdr []byte, primary cryptobox.KID) (newKID cryptobox.KID, rewritten []byte, changed bool, err error) {
	wl, err := parseHeader(hdr)
	if err != nil {
		return 0, nil, false, err
	}
	cur, _, err := cryptobox.KIDOf(hdr[wrapOff : wrapOff+wl])
	if err != nil {
		return 0, nil, false, err
	}
	if cur == primary {
		return cur, nil, false, nil
	}
	dek, err := codec.Cipher().Decrypt(ctx, hdr[wrapOff:wrapOff+wl])
	if err != nil {
		return 0, nil, false, err
	}
	wrapped, err := codec.Cipher().Encrypt(ctx, dek)
	if err != nil {
		return 0, nil, false, err
	}
	if len(wrapped) > hdrAreaLen {
		return 0, nil, false, fmt.Errorf("blobstore: rewrapped DEK too large")
	}
	kid, _, err := cryptobox.KIDOf(wrapped)
	if err != nil {
		return 0, nil, false, err
	}
	// [lenOff:prefixOff): 2-byte length + padded wrapped area. Prefix stays put.
	out := make([]byte, prefixOff-lenOff)
	binary.BigEndian.PutUint16(out[0:2], uint16(len(wrapped)))
	copy(out[2:], wrapped)
	return kid, out, true, nil
}

// headerKID parses an object header and returns its key version, without
// decrypting anything.
func headerKID(hdr []byte) (cryptobox.KID, error) {
	wl, err := parseHeader(hdr)
	if err != nil {
		return 0, err
	}
	kid, _, err := cryptobox.KIDOf(hdr[wrapOff : wrapOff+wl])
	return kid, err
}

// parseHeader validates the fixed header — magic, format version, and wrapped-DEK
// length — and returns the wrapped-DEK length. hdr must hold at least wrapOff bytes.
func parseHeader(hdr []byte) (wrapLen int, err error) {
	if string(hdr[0:verOff]) != magic {
		return 0, fmt.Errorf("blobstore: bad magic")
	}
	if hdr[verOff] != formatVer {
		return 0, fmt.Errorf("blobstore: unsupported format version %d (want %d)", hdr[verOff], formatVer)
	}
	wl := int(binary.BigEndian.Uint16(hdr[lenOff:wrapOff]))
	if wl == 0 || wl > hdrAreaLen {
		return 0, fmt.Errorf("blobstore: bad header length %d", wl)
	}
	return wl, nil
}

func makeNonce(prefix []byte, counter uint32, last bool) []byte {
	n := make([]byte, chacha20poly1305.NonceSize) // 12
	copy(n[0:prefixLen], prefix)
	binary.BigEndian.PutUint32(n[prefixLen:prefixLen+4], counter)
	if last {
		n[prefixLen+4] = 1
	}
	return n
}

// readChunk fills buf as far as possible. It reports (n, nil) and treats a short
// or empty tail read as a normal stop (n may be < len(buf), including 0).
func readChunk(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	switch err {
	case nil, io.EOF, io.ErrUnexpectedEOF:
		return n, nil
	default:
		return n, err
	}
}

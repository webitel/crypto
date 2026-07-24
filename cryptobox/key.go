package cryptobox

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// KID is a key identifier — uint16 encoded as a protobuf varint in blob headers.
type KID = uint16

const (
	minIKMLen   = 20  // minimum passphrase length (StringMaterial) and file bytes (FileMaterial)
	maxIKMBytes = 256 // maximum effective bytes read from a file
)

// KeyMaterial is the source of raw input key material bytes.
// Implementations may read from memory (StringMaterial), files (FileMaterial),
// or external systems (Vault, KMS, …).
type KeyMaterial interface {
	KeyMaterial(ctx context.Context) ([]byte, error)
}

// Key pairs a KID with a KeyMaterial source.
type Key struct {
	kid KID
	src KeyMaterial
}

// NewKey creates a Key with the given identifier and material source.
func NewKey(kid KID, src KeyMaterial) Key {
	return Key{kid: kid, src: src}
}

// Kid returns the key identifier.
func (x Key) Kid() KID { return x.kid }

// KeyMaterial delegates to the underlying KeyMaterial source.
func (x Key) KeyMaterial(ctx context.Context) ([]byte, error) {
	if x.src == nil {
		return nil, ErrKeyNotFound
	}
	return x.src.KeyMaterial(ctx)
}

// TextMaterial holds a phrase as key material.
type TextMaterial struct {
	phrase string
}

// NewTextMaterial validates and wraps a phrase.
// Phrase must be printable ASCII (0x21–0x7E), minimum 20 characters.
func NewTextMaterial(phrase string) (*TextMaterial, error) {
	if err := validatePassphrase(phrase); err != nil {
		return nil, err
	}
	return &TextMaterial{phrase: phrase}, nil
}

func (m *TextMaterial) KeyMaterial(_ context.Context) ([]byte, error) {
	return []byte(m.phrase), nil
}

// NewTextKey is a convenience constructor: TextMaterial + KID → Key.
func NewTextKey(kid KID, phrase string) (Key, error) {
	m, err := NewTextMaterial(phrase)
	if err != nil {
		return Key{}, err
	}
	return NewKey(kid, m), nil
}

// FileMaterial reads key material from a portion of a file.
// The viewport (offset + length) is resolved at construction time; the file is opened lazily on each Material() call.
//
// Address format: "path[:offset[:length]]"
//
//	/run/secrets/key.pem          — whole file, up to 256 bytes from byte 0
//	/run/secrets/key.pem:64       — up to 256 bytes starting at byte 64
//	/run/secrets/key.pem:64:32    — exactly 32 bytes starting at byte 64
type FileMaterial struct {
	path   string
	offset int64
	length int64 // always resolved; never 0 after construction
}

// NewFileMaterial parses "path[:offset[:length]]" and validates the viewport against the file on disk.
// File content is read lazily on Material().
func NewFileMaterial(path string) (*FileMaterial, error) {
	name, offset, specLen := parseFileAddr(path)

	if name == "" {
		return nil, fmt.Errorf("%w: file path is empty", ErrInvalidIKM)
	}
	if offset < 0 {
		return nil, fmt.Errorf("%w: offset must be non-negative", ErrInvalidIKM)
	}
	if specLen > maxIKMBytes {
		return nil, fmt.Errorf("%w: length %d exceeds max %d bytes", ErrInvalidIKM, specLen, maxIKMBytes)
	}

	info, err := os.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIKM, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w: path is a directory", ErrInvalidIKM)
	}
	if err := canTrustKeyFile(name, info); err != nil {
		return nil, err
	}

	fileSize := info.Size()
	if offset >= fileSize {
		return nil, fmt.Errorf("%w: offset %d exceeds file size %d", ErrInvalidIKM, offset, fileSize)
	}

	available := fileSize - offset
	var length int64
	if specLen < 0 {
		length = min(available, int64(maxIKMBytes))
	} else {
		if (offset + specLen) > fileSize {
			return nil, fmt.Errorf("%w: viewport [%d:%d] exceeds file size %d",
				ErrInvalidIKM, offset, offset+specLen, fileSize)
		}
		length = specLen
	}

	if length < minIKMLen {
		return nil, fmt.Errorf("%w: effective length %d bytes is below minimum %d",
			ErrInvalidIKM, length, minIKMLen)
	}

	return &FileMaterial{path: name, offset: offset, length: length}, nil
}

func (m *FileMaterial) KeyMaterial(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	file, err := os.Open(m.path)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: FileMaterial open: %w", err)
	}
	defer file.Close()

	if m.offset > 0 {
		if _, err := file.Seek(m.offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("cryptobox: FileMaterial seek: %w", err)
		}
	}

	buf := make([]byte, m.length)
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, fmt.Errorf("cryptobox: FileMaterial read: %w", err)
	}
	return buf, nil
}

// NewFileKey is a convenience constructor: FileMaterial + KID → Key.
func NewFileKey(kid KID, path string) (Key, error) {
	m, err := NewFileMaterial(path)
	if err != nil {
		return Key{}, err
	}
	return NewKey(kid, m), nil
}

// parseFileAddr parses "path[:offset[:length]]".
// specLen == -1 means length was not specified (auto).
func parseFileAddr(addr string) (path string, offset, specLen int64) {
	specLen = -1

	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, 0, -1
	}

	tail := addr[i+1:]
	num, err := strconv.ParseInt(tail, 10, 64)
	if err != nil {
		// Last segment is not a number → plain path with colon (unusual, but handle it).
		return addr, 0, -1
	}

	// Last segment is a number. Check if the segment before it is also a number.
	rest := addr[:i]
	j := strings.LastIndex(rest, ":")
	if j >= 0 {
		if o, err2 := strconv.ParseInt(rest[j+1:], 10, 64); err2 == nil {
			// "path:offset:length"
			return rest[:j], o, num
		}
	}

	// "path:offset" — num is the offset, length is auto.
	return rest, num, -1
}

func validatePassphrase(s string) error {
	if len(s) < minIKMLen {
		return fmt.Errorf("%w: too short (min %d chars, got %d)", ErrInvalidIKM, minIKMLen, len(s))
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x21 || b > 0x7E {
			return fmt.Errorf("%w: invalid byte 0x%02X at position %d (printable ASCII 0x21–0x7E required)",
				ErrInvalidIKM, b, i)
		}
	}
	return nil
}

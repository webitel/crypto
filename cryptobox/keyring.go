package cryptobox

import (
	"context"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Keyring holds a set of keyed materials identified by KID.
// The last non-retired key is the primary (used for Encrypt).
// All methods are safe for concurrent use.
type Keyring struct {
	mu      sync.RWMutex
	entries []entry
	primary KID
	version atomic.Uint64
	src     *KeyFile // source file when built from one (NewKeyring); enables WatchFile
}

type entry struct {
	kid     KID
	key     Key
	retired bool
}

const tombstone = "-"

// ParseKeyring builds a Keyring from a comma-separated key string.
//
// Entry format: ["[" KID "]"] material
//
//   - KID is decimal (42) or hex (0x2f); when omitted the 1-based position is used.
//   - material starting with "/" is a file path (auto-detected); supports viewport: /path[:offset[:length]].
//   - material "-" marks a retired slot (tombstone).
//   - Escape sequences in material: \\ \, \[ \/ \-
//
// Examples:
//
//	"correct-horse-battery-staple!"              — string key, implicit KID=1
//	"[42]correct-horse-battery-staple!,-"        — explicit KID=42, then tombstone KID=2
//	"/run/secrets/key.pem:64:32"                 — file key, implicit KID=1
//	"[0x1f]/run/secrets/key.pem"                 — file key, explicit KID=31
func ParseKeyring(raw string) (*Keyring, error) {

	parts := splitEntries(raw)
	if len(parts) > 65535 {
		return nil, fmt.Errorf("cryptobox: too many entries (max 65535, got %d)", len(parts))
	}

	k := &Keyring{}

	for i, part := range parts {
		implicitKID := KID(i + 1)

		kid, material, isFile, isTomb, err := parseEntry(part, implicitKID)
		if err != nil {
			return nil, fmt.Errorf("cryptobox: entry %d: %w", i+1, err)
		}

		for _, e := range k.entries {
			if e.kid == kid {
				return nil, fmt.Errorf("cryptobox: duplicate kid %d at entry %d", kid, i+1)
			}
		}

		if isTomb {
			k.entries = append(k.entries, entry{kid: kid, retired: true})
			continue
		}

		var key Key
		if isFile {
			key, err = NewFileKey(kid, material)
		} else {
			key, err = NewTextKey(kid, material)
		}
		if err != nil {
			return nil, fmt.Errorf("cryptobox: entry %d: %w", i+1, err)
		}

		k.entries = append(k.entries, entry{kid: kid, key: key})
		k.primary = kid
	}

	if len(k.entries) == 0 {
		return nil, fmt.Errorf("cryptobox: empty keyring")
	}
	if k.primary == 0 || k.entries[len(k.entries)-1].retired {
		return nil, fmt.Errorf("cryptobox: last entry must not be a tombstone")
	}

	return k, nil
}

// Load atomically replaces the keyring state parsed from raw.
// If parsing fails, the existing state is unchanged and the error is returned.
func (kr *Keyring) Load(raw string) error {
	fresh, err := ParseKeyring(raw)
	if err != nil {
		return err
	}
	kr.mu.Lock()
	kr.entries = fresh.entries
	kr.primary = fresh.primary
	kr.version.Add(1)
	kr.mu.Unlock()
	return nil
}

// KeyringOptions describes how to build a Keyring — from an inline spec or a file.
// It carries no cipher/Box concern (the algorithm is a Box property, not a keyring
// one) and no watch state: NewKeyring loads once and returns a plain *Keyring. For
// hot-reload call Keyring.WatchFile(ctx) on the result (see the package docs).
type KeyringOptions struct {
	// Keyring is inline key material (see ParseKeyring for the format).
	Keyring string `json:"keyring,omitempty"`
	// Filename loads the material from a file (same format, one key per line and/or
	// comma-separated). It takes precedence over Keyring when both are set.
	Filename string `json:"filename,omitempty"`
	// FilePoll is the minimum interval between reload attempts for a WatchFile on the
	// returned ring; 0 uses the default. Ignored for an inline keyring.
	FilePoll time.Duration `json:"file_poll,omitempty"`
}

// NewKeyring builds a Keyring from opts, loading once. When Filename is set the ring
// remembers its source so Keyring.WatchFile can hot-reload it later; otherwise the
// inline Keyring spec is parsed. It does not start any goroutine.
func NewKeyring(opts KeyringOptions) (*Keyring, error) {
	kr := &Keyring{}
	if opts.Filename != "" {
		fd := &KeyFile{Name: opts.Filename, Poll: opts.FilePoll}
		if _, err := fd.Load(kr); err != nil {
			return nil, err
		}
		kr.src = fd
		return kr, nil
	}
	if err := kr.Load(opts.Keyring); err != nil {
		return nil, err
	}
	return kr, nil
}

// Primary returns the current primary key (used for Encrypt).
func (kr *Keyring) Primary() Key {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	key, _ := kr.find(kr.primary)
	return key
}

// SetPrimary overrides which key is used for Encrypt.
func (kr *Keyring) SetPrimary(kid KID) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	for _, e := range kr.entries {
		if e.kid == kid {
			if e.retired {
				return ErrKeyRetired
			}
			kr.primary = kid
			return nil
		}
	}
	return ErrKeyNotFound
}

// Find returns the key with the given kid.
// Returns ErrKeyRetired for tombstoned slots, ErrKeyNotFound for absent kids.
func (kr *Keyring) Find(kid KID) (Key, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.find(kid)
}

// List returns an iterator over all entries in insertion order.
// The bool value is true when the entry is a retired tombstone.
// A snapshot of the entries is taken at the moment List is called.
func (kr *Keyring) List() iter.Seq2[Key, bool] {
	kr.mu.RLock()
	snapshot := make([]entry, len(kr.entries))
	copy(snapshot, kr.entries)
	kr.mu.RUnlock()

	return func(yield func(Key, bool) bool) {
		for _, e := range snapshot {
			key := e.key
			if e.retired {
				key = Key{kid: e.kid}
			}
			if !yield(key, e.retired) {
				return
			}
		}
	}
}

// Add inserts a key into the keyring. The key's kid must be unique.
// If the new key's kid is greater than the current primary, it becomes the new primary.
func (kr *Keyring) Add(new Key) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	return kr.add(new)
}

// Rotate adds next as a new key and immediately promotes it to primary.
// It is an atomic shorthand for Add + SetPrimary.
func (kr *Keyring) Rotate(next Key) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if err := kr.add(next); err != nil {
		return err
	}
	kr.primary = next.Kid()
	return nil
}

// Retire marks a key slot as a tombstone. Returns an error if kid is the current primary —
// rotate to a new key first. Blobs encrypted with a retired key will return ErrKeyRetired
// on Decrypt, signalling that re-encryption is needed before the tombstone can be dropped.
func (kr *Keyring) Retire(kid KID) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if kr.primary == kid {
		return fmt.Errorf("cryptobox: cannot retire the primary key (kid %d); rotate to a new key first", kid)
	}
	for i, e := range kr.entries {
		if e.kid == kid {
			if e.retired {
				return nil
			}
			kr.entries[i].key = Key{}
			kr.entries[i].retired = true
			return nil
		}
	}
	return ErrKeyNotFound
}

// find is the internal unlocked lookup — callers must hold mu.RLock or mu.Lock.
func (kr *Keyring) find(kid KID) (Key, error) {
	for _, e := range kr.entries {
		if e.kid == kid {
			if e.retired {
				return Key{}, ErrKeyRetired
			}
			return e.key, nil
		}
	}
	return Key{}, ErrKeyNotFound
}

// add is the internal unlocked insert — callers must hold mu.Lock.
func (kr *Keyring) add(new Key) error {
	for _, has := range kr.entries {
		if has.kid == new.Kid() {
			return fmt.Errorf("cryptobox: kid %d already exists in keyring", new.Kid())
		}
	}
	kr.entries = append(kr.entries, entry{kid: new.Kid(), key: new})
	if new.Kid() > kr.primary {
		kr.primary = new.Kid()
	}
	return nil
}

// splitEntries splits a keyring spec into entries. Both "," and newline separate
// entries, so a file may list one key per line (or comma-separated, or a mix); the
// inline env form stays single-line comma-separated. Outer whitespace is trimmed
// (a phrase never contains spaces) and empty entries are dropped — so blank lines
// and a trailing newline are harmless, and implicit KIDs count only real entries.
// Backslash escapes (\\ \, \[ \/ \-) are preserved for parseEntry.
func splitEntries(raw string) []string {
	var entries []string
	var cur strings.Builder
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			entries = append(entries, s)
		}
		cur.Reset()
	}
	i := 0
	for i < len(raw) {
		b := raw[i]
		if b == '\\' && i+1 < len(raw) {
			cur.WriteByte(b)
			cur.WriteByte(raw[i+1])
			i += 2
		} else if b == ',' || b == '\n' {
			flush()
			i++
		} else {
			cur.WriteByte(b)
			i++
		}
	}
	flush()
	return entries
}

// parseEntry extracts (kid, material, isFile, isTombstone) from a single raw entry string.
// Backslash sequences are still present in raw; they are resolved after type detection.
func parseEntry(raw string, implicitKID KID) (kid KID, material string, isFile, isTomb bool, err error) {
	rawMat := raw

	if len(raw) > 0 && raw[0] == '[' {
		j := strings.IndexByte(raw, ']')
		if j < 0 {
			return 0, "", false, false, fmt.Errorf("unclosed '[' in %q", raw)
		}
		kid, err = parseKIDStr(raw[1:j])
		if err != nil {
			return 0, "", false, false, err
		}
		rawMat = raw[j+1:]
	} else {
		kid = implicitKID
	}

	switch {
	case rawMat == tombstone:
		return kid, "", false, true, nil
	case len(rawMat) > 0 && rawMat[0] == '/':
		return kid, unescape(rawMat), true, false, nil
	default:
		return kid, unescape(rawMat), false, false, nil
	}
}

func parseKIDStr(s string) (KID, error) {
	var v uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = strconv.ParseUint(s[2:], 16, 16)
	} else {
		v, err = strconv.ParseUint(s, 10, 16)
	}
	if err != nil {
		return 0, fmt.Errorf("invalid KID %q: %w", s, err)
	}
	if v == 0 {
		return 0, fmt.Errorf("KID must be non-zero")
	}
	return KID(v), nil
}

// unescape resolves backslash sequences: \\ → \, \X → X for any X.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// Watch polls filename for changes and reloads the keyring whenever the file is modified.
// It is a thin wrapper around KeyFile.Watch with a fresh KeyFile (default poll interval).
// Errors are forwarded on the returned buffered channel; the channel is closed when ctx is done.
func (kr *Keyring) Watch(ctx context.Context, filename string) <-chan error {
	return (&KeyFile{Name: filename}).Watch(ctx, kr)
}

// WatchFile hot-reloads the keyring from the file it was built from (NewKeyring with
// a Filename), honoring the KeyringOptions.FilePoll interval. For an inline keyring
// (no source file) it is a no-op: the returned channel is closed immediately.
// Errors are forwarded on the returned buffered channel; it is closed when ctx is done.
func (kr *Keyring) WatchFile(ctx context.Context) <-chan error {
	if kr.src == nil {
		ch := make(chan error)
		close(ch)
		return ch
	}
	return kr.src.Watch(ctx, kr)
}

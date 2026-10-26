package env

import (
	"fmt"
	"strings"
)

// Name is an environment-variable name or namespace: segments joined by underscores,
// such as "CRYPTO_CIPHER_KEYS". It builds namespaced keys ([Name.Name], [Name.With])
// and validates them ([Name.IsValid], [Name.Err], [Name.Must]). The empty Name is invalid.
type Name string

// Name joins the given parts onto the space s and returns the full key. Parts are
// separated by a single "_" (a separator already present on either side is not
// doubled), and a part equal to the trailing segment is dropped — so a bare key and an
// already-namespaced one resolve to the same result.
//
// A part that begins with the whole current name is taken as already fully qualified
// and replaces it, WITHOUT segment separation: Name("A").Name("ABC") == "ABC" (not
// "A_ABC"). Pass the complete namespace explicitly to use this escape hatch.
func (s Name) Name(name ...string) string {
	return joinName(string(s), name)
}

// With is like [Name.Name] but returns the joined result as a Name, for building a deeper
// namespace step by step: Name("CRYPTO").With("SEARCH").With("KEYRING") == "CRYPTO_SEARCH_KEYRING".
func (s Name) With(name ...string) Name {
	return Name(joinName(string(s), name))
}

// joinName appends each part to name, inserting a single separator between segments,
// dropping a part that already is the trailing segment, and adopting a part that already
// is fully qualified (begins with name). See [Name.Name] for the exposed contract.
func joinName(name string, with []string) string {
	var sp string
	for _, part := range with {
		if sp = ""; strings.HasSuffix(name, sep) {
			part, _ = strings.CutPrefix(part, sep) // ONE
		} else if !strings.HasPrefix(part, sep) {
			sp = sep
		}
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, name) {
			name = part // fully qualified name ; advance
			continue
		}
		if ns, in := strings.CutSuffix(name, part); in {
			// ensure: segment !
			if ns == "" || strings.HasSuffix(ns, sep) {
				continue // OK ; match: segment !
			}
		}
		name += sp + part // [_]part
	}
	return name
}

// IsValid reports whether s is a syntactically valid environment-variable name: a letter
// or underscore, followed by any number of letters, digits, or underscores. The empty
// name is invalid.
func (s Name) IsValid() bool {
	n := consumeName(string(s))
	return len(s) == n
	// if not valid [n] - position of wrong char !
}

// Err returns nil when s is valid, otherwise an error wrapping [InvalidName] that reports the
// name as missing (when empty) or names the 1-based position of the first invalid byte.
func (s Name) Err() error {
	if len(s) == 0 {
		return fmt.Errorf("%w; missing", InvalidName)
	}
	if n := consumeName(string(s)); n < len(s) {
		// [s] not empty ; -1 = first character
		return fmt.Errorf("%w; character at position %d", InvalidName, (max(n, 0) + 1))
	}
	// OK
	return nil
}

// consumeName returns the length of the valid-name prefix of s, or -1 when the first
// byte is not a valid starter (letter or underscore).
func consumeName(s string) (i int) {
	if len(s) == 0 || !isLetter(s[i]) {
		return -1
	}
	i++
	for len(s) > i && isLetterDigit(s[i]) {
		i++
	}
	return i
}

func isLetter(c byte) bool {
	return c == '_' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func isLetterDigit(c byte) bool {
	return isLetter(c) || ('0' <= c && c <= '9')
}

// Must panics when s is not a valid name. Use it for names fixed in code (e.g. a
// package-level namespace) where an invalid value is a programming error, not input.
func (s Name) Must() {
	err := s.Err()
	if err != nil {
		panic(err)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webitel/crypto/cryptobox"
)

func TestKeygenEntry(t *testing.T) {
	// keyring control chars that keygenAlpha must never emit.
	const controls = ",[]/-\\\"'" + "`"

	e1, err := keygenEntry(0)
	if err != nil {
		t.Fatal(err)
	}
	// random-length phrase within [minPhraseLen, maxPhraseLen].
	if len(e1) < minPhraseLen || len(e1) > maxPhraseLen {
		t.Fatalf("phrase len = %d, want [%d,%d]", len(e1), minPhraseLen, maxPhraseLen)
	}
	if _, err := cryptobox.ParseKeyring(e1); err != nil {
		t.Fatalf("entry does not parse: %v", err)
	}
	if strings.ContainsAny(e1, controls) {
		t.Fatalf("entry has keyring control chars: %q", e1)
	}
	// two generations differ (randomness).
	if e2, _ := keygenEntry(0); e2 == e1 {
		t.Fatal("two keygens produced the same phrase")
	}
	// explicit KID prefix, and it becomes the primary.
	ek, err := keygenEntry(42)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ek, "[42]") {
		t.Fatalf("kid entry = %q, want [42] prefix", ek)
	}
	ring, err := cryptobox.ParseKeyring(ek)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Primary().Kid() != 42 {
		t.Fatalf("primary kid = %d, want 42", ring.Primary().Kid())
	}
	// out-of-range kid is rejected.
	if _, err := keygenEntry(70000); err == nil {
		t.Fatal("expected error for out-of-range --kid")
	}
}

// TestKeygenAlphabet checks that generated characters stay within keygenAlpha and
// cover it: over a large sample every alphabet char appears and none outside it
// does. (It does not assert uniformity — a small modulo bias is accepted by design.)
func TestKeygenAlphabet(t *testing.T) {
	s, err := randomString(20000, keygenAlpha)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[rune]int{}
	for _, r := range s {
		seen[r]++
	}
	for _, r := range keygenAlpha {
		if seen[r] == 0 {
			t.Fatalf("alphabet char %q never selected", r)
		}
	}
	if len(seen) != len(keygenAlpha) {
		t.Fatalf("selected %d distinct chars, alphabet has %d (out-of-alphabet output)", len(seen), len(keygenAlpha))
	}
}

func TestKeygenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cipher.key")
	if err := cmdKeygen([]string{"--file", path, "--bytes", "24"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) != 24 {
		t.Fatalf("key file: %d bytes, err=%v", len(b), err)
	}
}

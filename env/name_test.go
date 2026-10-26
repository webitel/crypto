package env_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/webitel/crypto/env"
)

// TestNameValidity: a name must start with a letter or underscore and continue with
// letters, digits, or underscores; empty and anything else is invalid.
func TestNameValidity(t *testing.T) {
	valid := []string{"APP", "_x", "A1_B2", "__TEST__", "a", "CRYPTO_CIPHER_KEYS"}
	for _, s := range valid {
		n := env.Name(s)
		if !n.IsValid() {
			t.Errorf("Name(%q).IsValid() = false, want true", s)
		}
		if err := n.Err(); err != nil {
			t.Errorf("Name(%q).Err() = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "1VAR", "A-B", "A B", "VAR!", "фыва"}
	for _, s := range invalid {
		n := env.Name(s)
		if n.IsValid() {
			t.Errorf("Name(%q).IsValid() = true, want false", s)
		}
		if err := n.Err(); err == nil || !errors.Is(err, env.InvalidName) {
			t.Errorf("Name(%q).Err() = %v, want ErrName", s, err)
		}
	}
}

// TestNameErrPosition: the empty name reports "missing"; a bad character reports its
// position.
func TestNameErrPosition(t *testing.T) {
	if err := env.Name("").Err(); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf(`Name("").Err() = %v, want "...missing"`, err)
	}
	if err := env.Name("AB-C").Err(); err == nil || !strings.Contains(err.Error(), "position") {
		t.Errorf(`Name("AB-C").Err() = %v, want "...position..."`, err)
	}
}

// TestNameMust: Must panics on an invalid name and is a no-op on a valid one.
func TestNameMust(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Must() on invalid name did not panic")
			}
		}()
		env.Name("1bad").Must()
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Must() on valid name panicked: %v", r)
			}
		}()
		env.Name("APP_OK").Must()
	}()
}

// TestNameJoin: Name and With build the same key; With returns a Name, Name a string.
func TestNameJoin(t *testing.T) {
	cases := []struct {
		space string
		parts []string
		want  string
	}{
		{"APP", []string{"CRYPTO"}, "APP_CRYPTO"},
		{"APP", []string{"CRYPTO", "CIPHER", "KEYS"}, "APP_CRYPTO_CIPHER_KEYS"},
		{"APP", nil, "APP"},
		{"APP", []string{""}, "APP"},                  // empty part skipped
		{"APP", []string{"", "CRYPTO"}, "APP_CRYPTO"}, // empty part skipped, then joined
	}
	for _, c := range cases {
		if got := env.Name(c.space).Name(c.parts...); got != c.want {
			t.Errorf("Name(%q).Name(%q) = %q, want %q", c.space, c.parts, got, c.want)
		}
		if got := env.Name(c.space).With(c.parts...); string(got) != c.want {
			t.Errorf("Name(%q).With(%q) = %q, want %q", c.space, c.parts, got, c.want)
		}
	}
}

// TestNameJoinSeparators: exactly one underscore joins segments, whether the separator
// is contributed by a trailing space, a leading part, both, or neither.
func TestNameJoinSeparators(t *testing.T) {
	cases := []struct {
		space, part, want string
	}{
		{"APP", "CRYPTO", "APP_CRYPTO"},   // neither → inserted
		{"APP_", "CRYPTO", "APP_CRYPTO"},  // trailing sep on space → not doubled
		{"APP", "_CRYPTO", "APP_CRYPTO"},  // leading sep on part → reused
		{"APP_", "_CRYPTO", "APP_CRYPTO"}, // both → collapsed to one
	}
	for _, c := range cases {
		if got := env.Name(c.space).Name(c.part); got != c.want {
			t.Errorf("Name(%q).Name(%q) = %q, want %q", c.space, c.part, got, c.want)
		}
	}
}

// TestNameJoinIdempotent: re-appending a segment that is already the trailing segment is
// a no-op (used so Options.Getnenv can accept either a bare or a namespaced key).
func TestNameJoinIdempotent(t *testing.T) {
	if got := env.Name("mod_var").Name("var"); got != "mod_var" {
		t.Errorf(`Name("mod_var").Name("var") = %q, want "mod_var"`, got)
	}
	if got := env.Name("APP_CRYPTO_SEARCH").Name("SEARCH"); got != "APP_CRYPTO_SEARCH" {
		t.Errorf(`re-append SEARCH = %q, want "APP_CRYPTO_SEARCH"`, got)
	}
}

// TestNameJoinSegmentAware locks the two dedup fixes: a fully-qualified part (one that
// starts with the whole namespace) is adopted rather than truncated, and suffix dedup
// matches whole segments, not raw substrings.
func TestNameJoinSegmentAware(t *testing.T) {
	// fully-qualified part → adopted (not dropped down to the namespace)
	if got := env.Name("CRYPTO").Name("CRYPTO_KEYS"); got != "CRYPTO_KEYS" {
		t.Errorf(`Name("CRYPTO").Name("CRYPTO_KEYS") = %q, want "CRYPTO_KEYS"`, got)
	}
	if got := env.Name("APP_CRYPTO").Name("APP_CRYPTO_CIPHER"); got != "APP_CRYPTO_CIPHER" {
		t.Errorf(`fully-qualified nest = %q, want "APP_CRYPTO_CIPHER"`, got)
	}
	// suffix substring that is NOT a whole segment → appended, not deduped away
	if got := env.Name("mod_var").Name("ar"); got != "mod_var_ar" {
		t.Errorf(`Name("mod_var").Name("ar") = %q, want "mod_var_ar"`, got)
	}
}

// TestNameJoinUnderscores: leading/trailing underscores are preserved and deduped by
// whole segment (ported from the old ns_test.go).
func TestNameJoinUnderscores(t *testing.T) {
	// "_mod" is the whole trailing segment of "__mod" → deduped away.
	if got := env.Name("__mod").With("_mod"); string(got) != "__mod" {
		t.Errorf(`Name("__mod").With("_mod") = %q, want "__mod"`, got)
	}
	// trailing "__" is kept; re-appending SEARCH is idempotent.
	name := env.Name("__CRYPTO__").With("SEARCH")
	if string(name) != "__CRYPTO__SEARCH" {
		t.Errorf(`With("SEARCH") = %q, want "__CRYPTO__SEARCH"`, name)
	}
	if got := name.Name("SEARCH"); got != "__CRYPTO__SEARCH" {
		t.Errorf(`re-append SEARCH = %q, want "__CRYPTO__SEARCH"`, got)
	}
}

// TestNameEmptyKeyLookup: an empty key resolves to the bare namespace, so an Options
// whose namespace names a full variable reads it via Getenv("") (ported from ns_test.go).
func TestNameEmptyKeyLookup(t *testing.T) {
	testenv := env.Options{Namespace: env.Name("__TEST__")}
	t.Setenv("__TEST__", "ok")
	if got := testenv.Getenv(""); got != "ok" {
		t.Fatalf(`Getenv("") with namespace __TEST__ = %q, want "ok"`, got)
	}
	// The same name through the package root (empty namespace) reads the bare variable.
	testenv = env.Environment(testenv.Namespace.Name())
	if got := testenv.Getenv(""); got != "ok" {
		t.Fatalf(`Getenv("") under the root namespace = %q, want "ok"`, got)
	}
}

// TestEnvironmentNamespace: env.Environment nests under the empty root namespace and,
// with no explicit LookupEnv, falls back to the real process environment.
func TestEnvironmentNamespace(t *testing.T) {
	t.Setenv("CRYPTO_CIPHER_KEYS", "value")
	if got := env.Environment("CRYPTO").Getenv("CIPHER_KEYS"); got != "value" {
		t.Errorf(`Environment("CRYPTO").Getenv("CIPHER_KEYS") = %q, want "value"`, got)
	}
	// A deeper namespace composes the same way.
	if got := env.Environment("CRYPTO", "CIPHER").Getenv("KEYS"); got != "value" {
		t.Errorf(`Environment("CRYPTO","CIPHER").Getenv("KEYS") = %q, want "value"`, got)
	}
}

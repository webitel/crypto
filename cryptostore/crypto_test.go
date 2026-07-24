package cryptostore_test

import (
	"testing"

	"github.com/webitel/crypto/cryptostore"
)

// TestDefaultMemoized checks that Default builds the core once and returns the same
// result thereafter, independent of the ambient environment (with cipher keys set
// both calls yield the same *Codec; without, both yield the same error).
func TestDefaultMemoized(t *testing.T) {
	c1, err1 := cryptostore.Default()
	c2, err2 := cryptostore.Default()

	if c1 != c2 {
		t.Fatalf("Default not memoized: %p != %p", c1, c2)
	}
	if (err1 == nil) != (err2 == nil) {
		t.Fatalf("Default error not stable: %v vs %v", err1, err2)
	}
	if err1 != nil && err1.Error() != err2.Error() {
		t.Fatalf("Default error changed between calls: %v vs %v", err1, err2)
	}
	if err1 == nil && c1 == nil {
		t.Fatal("Default returned nil codec with nil error")
	}
}

func TestSystemDir(t *testing.T) {
	t.Setenv("WBTL_CRYPTO_DIR", "") // force default
	if got := cryptostore.SystemDir(); got != "/var/lib/webitel/crypto" {
		t.Fatalf("default SystemDir = %q", got)
	}
	t.Setenv("WBTL_CRYPTO_DIR", "/etc/webitel/crypto")
	if got := cryptostore.SystemDir(); got != "/etc/webitel/crypto" {
		t.Fatalf("override SystemDir = %q", got)
	}
}

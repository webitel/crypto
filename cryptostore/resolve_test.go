package cryptostore_test

import (
	"testing"

	"github.com/webitel/crypto/cryptostore"
)

// TestStoreOptionsResolve: a relative driver path is anchored to BaseDir; absolute
// and empty paths, and a relative path with no BaseDir, are returned unchanged.
func TestStoreOptionsResolve(t *testing.T) {
	cases := []struct {
		baseDir, path, want string
	}{
		{"/etc/webitel/crypto", "rec", "/etc/webitel/crypto/rec"},
		{"/etc/webitel/crypto", "../shared/rec", "/etc/webitel/shared/rec"},
		{"/etc/webitel/crypto", "/abs/rec", "/abs/rec"}, // absolute: unchanged
		{"/etc/webitel/crypto", "", ""},                 // empty: unchanged
		{"", "rec", "rec"},                              // no base: resolve against CWD (unchanged)
	}
	for _, c := range cases {
		o := cryptostore.StoreOptions{BaseDir: c.baseDir}
		if got := o.Resolve(c.path); got != c.want {
			t.Errorf("Resolve(baseDir=%q, %q) = %q, want %q", c.baseDir, c.path, got, c.want)
		}
	}
}

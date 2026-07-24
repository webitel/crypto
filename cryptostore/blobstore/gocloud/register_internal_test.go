package gocloud

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptostore"
)

// TestResolveBucketURL: a relative file:// path is anchored to BaseDir; absolute
// paths, other schemes, an empty BaseDir, and query params are handled as expected.
func TestResolveBucketURL(t *testing.T) {
	const base = "/etc/webitel/crypto"
	cases := []struct {
		name, dsn, baseDir, want string
	}{
		{"relative", "file://rec", base, "file:///etc/webitel/crypto/rec"},
		{"dot-relative", "file://./rec", base, "file:///etc/webitel/crypto/rec"},
		{"parent-relative", "file://../shared", base, "file:///etc/webitel/shared"},
		{"absolute", "file:///srv/rec", base, "file:///srv/rec"},
		{"query-preserved", "file://rec?create_dir=true", base, "file:///etc/webitel/crypto/rec?create_dir=true"},
		{"no-base", "file://rec", "", "file://rec"},          // no config dir → unchanged (CWD fallback)
		{"other-scheme", "s3://bucket", base, "s3://bucket"}, // not a file URL → unchanged
		{"mem", "mem://", base, "mem://"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := cryptostore.StoreOptions{DSN: c.dsn, BaseDir: c.baseDir}
			if got := resolveBucketURL(opts); got != c.want {
				t.Errorf("resolveBucketURL(%q, base=%q) = %q, want %q", c.dsn, c.baseDir, got, c.want)
			}
		})
	}
}

// TestResolveBucketURLOpens verifies the resolved URL actually opens the bucket
// rooted at the config-relative directory, not the process CWD.
func TestResolveBucketURLOpens(t *testing.T) {
	dir := t.TempDir() // stands in for the config file's directory
	opts := cryptostore.StoreOptions{DSN: "file://data", BaseDir: dir}

	url := resolveBucketURL(opts)
	if want := "file://" + filepath.Join(dir, "data"); url != want {
		t.Fatalf("resolved URL = %q, want %q", url, want)
	}
	// The target dir must exist for fileblob to open it.
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := OpenBucket(context.Background(), url)
	if err != nil {
		t.Fatalf("OpenBucket(%q): %v", url, err)
	}
	b.Close()
}

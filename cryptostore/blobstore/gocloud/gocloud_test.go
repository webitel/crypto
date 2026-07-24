package gocloud_test

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/blobstore"
	"github.com/webitel/crypto/cryptostore/blobstore/gocloud"
)

func newCodec(t *testing.T, keys string) *cryptostore.Codec {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestMemBucket exercises the gocloud adapter over an in-memory bucket: streaming
// round-trips, usage from the catalog, and a catalog rebuild via Reindex.
func TestMemBucket(t *testing.T) {
	ctx := context.Background()
	b, err := gocloud.OpenBucket(ctx, "mem://")
	if err != nil {
		t.Fatal(err)
	}
	c := newCodec(t, "correct-horse-battery-staple-001!")
	st, err := blobstore.NewStore("blob:mem", b, filepath.Join(t.TempDir(), "catalog.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	objs := map[string][]byte{
		"a.txt":         []byte("hello"),
		"big.bin":       bytes.Repeat([]byte("B"), 64*1024*2+13), // multi-chunk
		"nested/c.json": []byte(`{"x":1}`),
	}
	for k, v := range objs {
		if err := st.Put(ctx, k, bytes.NewReader(v)); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	for k, v := range objs {
		rc, err := st.Get(ctx, k)
		if err != nil {
			t.Fatalf("Get %s: %v", k, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, v) {
			t.Fatalf("%s round-trip mismatch", k)
		}
	}

	usage, err := st.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].KID != 1 || usage[0].Count != int64(len(objs)) {
		t.Fatalf("usage = %+v, want kid=1 count=%d", usage, len(objs))
	}

	// Reindex must reproduce the same catalog from the bucket alone.
	if err := st.Reindex(ctx); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	usage, err = st.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].Count != int64(len(objs)) {
		t.Fatalf("usage after reindex = %+v", usage)
	}

	if err := st.Delete(ctx, "a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "a.txt"); err == nil {
		t.Fatal("expected error reading deleted object")
	}
}

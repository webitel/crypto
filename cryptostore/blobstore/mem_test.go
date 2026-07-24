package blobstore_test

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/blobstore"
)

// memBucket is a minimal in-memory Bucket that does NOT implement patcher, so it
// drives the store's generic full-rewrite migration path (as cloud backends do).
// Its Close is a no-op, so data survives a store Close — letting a test reopen a
// rotated store over the same data.
type memBucket struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemBucket() *memBucket { return &memBucket{m: map[string][]byte{}} }

func (b *memBucket) NewReader(_ context.Context, key string) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.m[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), d...))), nil
}

func (b *memBucket) NewWriter(_ context.Context, key string) (io.WriteCloser, error) {
	return &memWriter{b: b, key: key}, nil
}

func (b *memBucket) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, key)
	return nil
}

func (b *memBucket) List(_ context.Context, fn func(blobstore.ObjectInfo) error) error {
	b.mu.Lock()
	keys := make([]string, 0, len(b.m))
	sizes := map[string]int64{}
	for k, v := range b.m {
		keys = append(keys, k)
		sizes[k] = int64(len(v))
	}
	b.mu.Unlock()
	for _, k := range keys {
		if err := fn(blobstore.ObjectInfo{Key: k, Size: sizes[k]}); err != nil {
			return err
		}
	}
	return nil
}

func (b *memBucket) Close() error { return nil }

type memWriter struct {
	b   *memBucket
	key string
	buf bytes.Buffer
}

func (w *memWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func (w *memWriter) Close() error {
	w.b.mu.Lock()
	defer w.b.mu.Unlock()
	w.b.m[w.key] = append([]byte(nil), w.buf.Bytes()...)
	return nil
}

func TestGenericMigrate(t *testing.T) {
	ctx := context.Background()
	bucket := newMemBucket()
	want := payloads()

	c1 := newCodec(t, "correct-horse-battery-staple-001!")
	st1, err := blobstore.NewStore("blob:mem", bucket, filepath.Join(t.TempDir(), "c1.db"), c1)
	if err != nil {
		t.Fatal(err)
	}
	for k, data := range want {
		if err := st1.Put(ctx, k, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	if u, _ := st1.Usage(ctx); len(u) != 1 || u[0].KID != 1 {
		t.Fatalf("usage before = %+v, want kid=1", u)
	}
	st1.Close() // memBucket.Close is a no-op; data persists

	// Rotate; reopen over the SAME bucket with a fresh catalog rebuilt by Reindex.
	c2 := newCodec(t, "correct-horse-battery-staple-001!,fresh-rotated-phrase-2026-xyz!")
	st2, err := blobstore.NewStore("blob:mem", bucket, filepath.Join(t.TempDir(), "c2.db"), c2)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.Reindex(ctx); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	res, err := st2.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if res.Recrypted != int64(len(want)) {
		t.Fatalf("recrypted = %d, want %d", res.Recrypted, len(want))
	}
	if u, _ := st2.Usage(ctx); len(u) != 1 || u[0].KID != 2 {
		t.Fatalf("usage after = %+v, want kid=2", u)
	}
	// Bodies still decrypt under the new key (full rewrite preserved the stream).
	for k, data := range want {
		rc, err := st2.Get(ctx, k)
		if err != nil {
			t.Fatalf("Get %s: %v", k, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, data) {
			t.Fatalf("%s mismatch after generic migrate", k)
		}
	}
}

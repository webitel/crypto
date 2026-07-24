package blobstore

import (
	"context"
	"io"
)

// ObjectInfo is a stored object's key and ciphertext size, as listed by a Bucket.
type ObjectInfo struct {
	Key  string
	Size int64
}

// Bucket is the physical object backend behind the encrypted store's controller:
// a local directory, an S3/GCS bucket, an in-memory bucket, etc. The store deals
// only in keys and streams; all path/credential handling lives in the Bucket.
type Bucket interface {
	// NewReader streams the stored object at key.
	NewReader(ctx context.Context, key string) (io.ReadCloser, error)
	// NewWriter streams a new object at key, committing on Close (overwriting any
	// existing object). If the returned writer implements canceler, Cancel aborts
	// without committing.
	NewWriter(ctx context.Context, key string) (io.WriteCloser, error)
	// Delete removes the object at key (absent key is not an error).
	Delete(ctx context.Context, key string) error
	// List calls fn for every object; returning an error stops iteration.
	List(ctx context.Context, fn func(ObjectInfo) error) error
	// Close releases backend resources.
	Close() error
}

// patcher is an optional Bucket capability: in-place byte patching. Backends with
// mutable storage (a local file) implement it so migration can rewrite the small
// DEK header in place (O(1)). Immutable backends (cloud object stores) omit it,
// and the store falls back to rewriting the whole object.
type patcher interface {
	PatchAt(ctx context.Context, key string, off int64, b []byte) error
}

// canceler is an optional WriteCloser capability: abort a write without
// committing the object (e.g. on a mid-stream encryption error).
type canceler interface {
	Cancel() error
}

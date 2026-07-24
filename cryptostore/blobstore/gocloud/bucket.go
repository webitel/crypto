// Package gocloud provides cloud-backed buckets for cryptostore/blobstore via the
// Go CDK (gocloud.dev/blob): Amazon S3, Google Cloud Storage, the local
// filesystem, and in-memory — selected by URL. It is a separate module so the
// heavy cloud SDK dependencies stay opt-in.
//
// Supported URL schemes (driver registered by blank import):
//
//	s3://bucket?region=us-east-1      Amazon S3 (and S3-compatible via ?endpoint=)
//	gs://bucket                       Google Cloud Storage
//	file:///var/data                  local filesystem
//	mem://                            in-memory (tests)
//
// Object migration on a cloud bucket rewrites the whole object (cloud objects are
// immutable); the per-object DEK header is re-keyed during that rewrite.
package gocloud

import (
	"context"
	"io"

	"gocloud.dev/blob"

	// Register URL openers for the supported schemes.
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"

	"github.com/webitel/crypto/cryptostore/blobstore"
)

// Bucket adapts a gocloud.dev *blob.Bucket to blobstore.Bucket. It is immutable
// (no patcher), so the store migrates objects by full rewrite.
type Bucket struct {
	b *blob.Bucket
}

// OpenBucket opens a bucket from a Go CDK URL (see package docs for schemes).
func OpenBucket(ctx context.Context, url string) (*Bucket, error) {
	b, err := blob.OpenBucket(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Bucket{b: b}, nil
}

func (g *Bucket) NewReader(ctx context.Context, key string) (io.ReadCloser, error) {
	return g.b.NewReader(ctx, key, nil)
}

func (g *Bucket) NewWriter(ctx context.Context, key string) (io.WriteCloser, error) {
	return g.b.NewWriter(ctx, key, nil)
}

func (g *Bucket) Delete(ctx context.Context, key string) error {
	return g.b.Delete(ctx, key)
}

func (g *Bucket) List(ctx context.Context, fn func(blobstore.ObjectInfo) error) error {
	it := g.b.List(nil)
	for {
		o, err := it.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if o.IsDir {
			continue
		}
		if err := fn(blobstore.ObjectInfo{Key: o.Key, Size: o.Size}); err != nil {
			return err
		}
	}
}

func (g *Bucket) Close() error { return g.b.Close() }

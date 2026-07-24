// Package blobstore implements a cryptostore.Store for opaque objects (files),
// with streaming envelope encryption — one realization of an object-oriented
// store. A controller keeps a sqlite catalog of (key, key version) so
// per-key usage and key migration need no full backend scan.
//
// The physical backend is abstracted as a Bucket: a local directory ships in
// this module; cloud backends (S3, GCS) live in cryptostore/blobstore/gocloud so
// their heavy dependencies stay optional.
package blobstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

// Store is the encrypted object store controller: a Bucket backend plus a catalog
// index. It implements cryptostore.Store.
type Store struct {
	name   string
	bucket Bucket
	codec  *cryptostore.Codec
	cat    *catalog
}

// NewStore builds a controller over an arbitrary Bucket, with its catalog kept at
// catalogPath (a local sqlite file — operational state on the agent host, which
// Reindex can rebuild from the backend). Cloud backends use this directly.
func NewStore(name string, bucket Bucket, catalogPath string, codec *cryptostore.Codec) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o755); err != nil {
		return nil, fmt.Errorf("blobstore: catalog dir: %w", err)
	}
	cat, err := openCatalog(catalogPath)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "blob"
	}
	return &Store{name: name, bucket: bucket, codec: codec, cat: cat}, nil
}

// Open opens (creating if needed) a local-directory store rooted at dir, with the
// catalog under dir/.blobfs/.catalog.
func Open(name, dir string, codec *cryptostore.Codec) (*Store, error) {
	fs, err := newLocalFS(dir)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "blobfs:" + filepath.Base(fs.root)
	}
	return NewStore(name, fs, filepath.Join(fs.root, metaDir, catalogName), codec)
}

// Name implements cryptostore.Store.
func (c *Store) Name() string { return c.name }

// Close releases the catalog and the backend.
func (c *Store) Close() error {
	err := c.cat.close()
	if berr := c.bucket.Close(); err == nil {
		err = berr
	}
	return err
}

// Put streams r into the object at key, encrypting it, and records it in the
// catalog.
func (c *Store) Put(ctx context.Context, key string, r io.Reader) error {
	w, err := c.bucket.NewWriter(ctx, key)
	if err != nil {
		return err
	}
	kid, _, err := seal(ctx, c.codec, w, r)
	if err != nil {
		abortWrite(ctx, c.bucket, w, key)
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.cat.upsert(ctx, key, kid)
}

// Get returns a streaming reader that decrypts the object at key. Close it.
func (c *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	f, err := c.bucket.NewReader(ctx, key)
	if err != nil {
		return nil, err
	}
	rd, err := openReader(ctx, c.codec, f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &readCloser{r: rd, c: f}, nil
}

// Delete removes the object and its catalog entry.
func (c *Store) Delete(ctx context.Context, key string) error {
	if err := c.bucket.Delete(ctx, key); err != nil {
		return err
	}
	return c.cat.remove(ctx, key)
}

// Usage implements cryptostore.Store from the catalog.
func (c *Store) Usage(ctx context.Context) ([]cryptostore.KeyUsage, error) {
	return c.cat.usage(ctx)
}

// Migrate implements cryptostore.Store. For each object not under the primary key
// it re-keys the DEK header and updates the catalog. On a patcher backend (local
// file) the header is rewritten in place (O(1)); otherwise the whole object is
// rewritten (cloud objects are immutable). DryRun only counts.
func (c *Store) Migrate(ctx context.Context, req cryptostore.MigrateOptions) (cryptostore.MigrateResult, error) {
	res := cryptostore.MigrateResult{Store: c.name}
	primary, err := c.codec.PrimaryKID(ctx)
	if err != nil {
		return res, err
	}
	keys, err := c.cat.keysNotUnder(ctx, primary)
	if err != nil {
		return res, err
	}
	res.Scanned = int64(len(keys))
	if req.DryRun {
		res.Remaining = int64(len(keys))
		return res, nil
	}
	total := int64(len(keys))
	if req.OnProgress != nil {
		req.OnProgress(cryptostore.Progress{Store: c.name, Done: 0, Total: total})
	}
	for i, key := range keys {
		changed, newKID, err := c.rekeyObject(ctx, key, primary)
		if err != nil {
			return res, err
		}
		if changed {
			if err := c.cat.setKID(ctx, key, newKID); err != nil {
				return res, err
			}
			res.Recrypted++
		}
		if req.OnProgress != nil {
			req.OnProgress(cryptostore.Progress{Store: c.name, Done: int64(i + 1), Total: total})
		}
		if err := throttle(ctx, req.RatePerSec); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (c *Store) rekeyObject(ctx context.Context, key string, primary cryptobox.KID) (bool, cryptobox.KID, error) {
	// Fast path: a mutable backend patches the fixed header region in place.
	if p, ok := c.bucket.(patcher); ok {
		hdr, err := c.readHeader(ctx, key, prefixOff)
		if err != nil {
			return false, 0, err
		}
		newKID, rewritten, changed, err := rekey(ctx, c.codec, hdr, primary)
		if err != nil || !changed {
			return false, newKID, err
		}
		return true, newKID, p.PatchAt(ctx, key, lenOff, rewritten)
	}

	// Generic path: rewrite the whole object with a re-keyed header (immutable
	// backends such as cloud object stores).
	r, err := c.bucket.NewReader(ctx, key)
	if err != nil {
		return false, 0, err
	}
	full := make([]byte, bodyOff)
	if _, err := io.ReadFull(r, full); err != nil {
		r.Close()
		return false, 0, fmt.Errorf("blobstore: read header %q: %w", key, err)
	}
	newKID, rewritten, changed, err := rekey(ctx, c.codec, full[:prefixOff], primary)
	if err != nil || !changed {
		r.Close()
		return false, newKID, err
	}
	copy(full[lenOff:prefixOff], rewritten)

	w, err := c.bucket.NewWriter(ctx, key)
	if err != nil {
		r.Close()
		return false, 0, err
	}
	if _, err := w.Write(full); err != nil {
		abortWrite(ctx, c.bucket, w, key)
		r.Close()
		return false, 0, err
	}
	if _, err := io.Copy(w, r); err != nil {
		abortWrite(ctx, c.bucket, w, key)
		r.Close()
		return false, 0, err
	}
	r.Close()
	if err := w.Close(); err != nil {
		return false, 0, err
	}
	return true, newKID, nil
}

func (c *Store) readHeader(ctx context.Context, key string, n int) ([]byte, error) {
	r, err := c.bucket.NewReader(ctx, key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	hdr := make([]byte, n)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("blobstore: read header %q: %w", key, err)
	}
	return hdr, nil
}

// Reindex rebuilds the catalog by scanning every object's header. Use it after
// the backend was modified out-of-band, or to populate a fresh catalog for an
// existing cloud bucket.
func (c *Store) Reindex(ctx context.Context) error {
	var entries []catalogEntry
	err := c.bucket.List(ctx, func(o ObjectInfo) error {
		hdr, err := c.readHeader(ctx, o.Key, prefixOff)
		if err != nil {
			return fmt.Errorf("blobstore: reindex %q: %w", o.Key, err)
		}
		kid, err := headerKID(hdr)
		if err != nil {
			return fmt.Errorf("blobstore: reindex %q: %w", o.Key, err)
		}
		entries = append(entries, catalogEntry{key: o.Key, kid: kid})
		return nil
	})
	if err != nil {
		return err
	}
	return c.cat.replaceAll(ctx, entries)
}

// abortWrite cancels a write if the backend supports it, else commits and deletes.
func abortWrite(ctx context.Context, b Bucket, w io.WriteCloser, key string) {
	if c, ok := w.(canceler); ok {
		_ = c.Cancel()
		return
	}
	_ = w.Close()
	_ = b.Delete(ctx, key)
}

func throttle(ctx context.Context, ratePerSec int) error {
	if ratePerSec <= 0 {
		return nil
	}
	t := time.NewTimer(time.Second / time.Duration(ratePerSec))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type readCloser struct {
	r io.Reader
	c io.Closer
}

func (rc *readCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }
func (rc *readCloser) Close() error               { return rc.c.Close() }

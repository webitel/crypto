package blobstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// metaDir holds the local store's bookkeeping, named after the driver scheme
// ("blobfs") so a data directory shows plainly which store owns it. It is kept out
// of the object listing and rejected as a key prefix. catalogName is the sqlite
// catalog inside it (key → key-version, size).
const (
	metaDir     = ".blobfs"
	catalogName = ".catalog"
)

// localFS is a Bucket over a local directory. It implements patcher, so the
// store rewrites the DEK header in place during migration.
type localFS struct {
	root string
}

func newLocalFS(dir string) (*localFS, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, metaDir), 0o755); err != nil {
		return nil, fmt.Errorf("blobstore: create root: %w", err)
	}
	return &localFS{root: root}, nil
}

// path maps a key to an absolute path inside root, rejecting escapes and the
// reserved meta directory.
func (l *localFS) path(key string) (string, error) {
	clean := filepath.Clean("/" + filepath.FromSlash(key))
	p := filepath.Join(l.root, clean)
	if p != l.root && !strings.HasPrefix(p, l.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("blobstore: invalid key %q", key)
	}
	if rel, _ := filepath.Rel(l.root, p); rel == metaDir || strings.HasPrefix(rel, metaDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("blobstore: key %q is reserved", key)
	}
	return p, nil
}

func (l *localFS) NewReader(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (l *localFS) NewWriter(_ context.Context, key string) (io.WriteCloser, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return nil, err
	}
	return &fileWriter{f: tmp, tmp: tmp.Name(), final: p}, nil
}

func (l *localFS) Delete(_ context.Context, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (l *localFS) List(_ context.Context, fn func(ObjectInfo) error) error {
	return filepath.WalkDir(l.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == metaDir {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(l.root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return fn(ObjectInfo{Key: filepath.ToSlash(rel), Size: info.Size()})
	})
}

func (l *localFS) PatchAt(_ context.Context, key string, off int64, b []byte) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(b, off); err != nil {
		return err
	}
	return f.Sync()
}

func (l *localFS) Close() error { return nil }

// fileWriter writes to a temp file and atomically renames it into place on Close.
type fileWriter struct {
	f     *os.File
	tmp   string
	final string
}

func (w *fileWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

func (w *fileWriter) Close() error {
	if err := w.f.Close(); err != nil {
		os.Remove(w.tmp)
		return err
	}
	return os.Rename(w.tmp, w.final)
}

// Cancel discards the partial write without publishing the object.
func (w *fileWriter) Cancel() error {
	w.f.Close()
	return os.Remove(w.tmp)
}

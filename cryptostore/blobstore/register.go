package blobstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/webitel/crypto/cryptostore"
)

// init registers the "blobfs" DSN scheme. Import this package for its side effect
// (e.g. _ "github.com/webitel/crypto/cryptostore/blobstore") to let cryptostore.OpenStore
// build local-directory blob stores from configuration. The DSN is blobfs:<dir>,
// e.g. blobfs:/var/lib/webitel/crypto — the opaque part is the directory.
//
// Schemaless: a blob store encrypts whole objects and ignores the field schema.
func init() {
	cryptostore.RegisterSchemaless("blobfs", open)
}

func open(_ context.Context, opts cryptostore.StoreOptions) (cryptostore.Store, error) {
	_, dir, _ := strings.Cut(opts.DSN, ":")
	if dir == "" {
		return nil, fmt.Errorf("blobstore: DSN %q has no directory (want blobfs:<dir>)", opts.DSN)
	}
	// A relative dir is anchored to the config file's directory, not the CWD.
	dir = opts.Resolve(dir)
	name := opts.Name
	return Open(name, dir, opts.Codec)
}

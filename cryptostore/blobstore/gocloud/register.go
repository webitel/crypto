package gocloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/blobstore"
)

// schemes are the Go CDK bucket URL schemes this driver serves (one DriverFunc,
// several DSN schemes). They match the blob drivers imported by bucket.go.
var schemes = []string{"s3", "gs", "file", "mem"}

// init registers the cloud (Go CDK) bucket schemes. Import this package for its
// side effect (e.g. _ "github.com/webitel/crypto/cryptostore/blobstore/gocloud") to
// let cryptostore.OpenStore build cloud blob stores from configuration. The DSN is the
// Go CDK bucket URL (s3://…, gs://…, file://…, mem://…); the sqlite catalog path
// lives in the config block.
func init() {
	for _, scheme := range schemes {
		cryptostore.Register(scheme, open)
	}
}

// Config carries the cloud store's extras that are not part of the bucket URL.
type Config struct {
	// Catalog is the local sqlite path for the controller index. It is operational
	// state on the agent host (not the data) and can be rebuilt with Reindex.
	Catalog string `json:"catalog"`
}

func open(ctx context.Context, opts cryptostore.StoreOptions) (cryptostore.Store, error) {
	var cfg Config
	if len(opts.ConfigRaw) > 0 {
		if err := json.Unmarshal(opts.ConfigRaw, &cfg); err != nil {
			return nil, fmt.Errorf("blobcloud: config: %w", err)
		}
	}
	if cfg.Catalog == "" {
		return nil, fmt.Errorf("blobcloud: empty catalog path")
	}
	b, err := OpenBucket(ctx, resolveBucketURL(opts)) // the DSN is the Go CDK bucket URL
	if err != nil {
		return nil, fmt.Errorf("blobcloud: open bucket: %w", err)
	}
	// The catalog is local agent-host state; a relative path is anchored to the
	// config file's directory, not the CWD.
	st, err := blobstore.NewStore(opts.Name, b, opts.Resolve(cfg.Catalog), opts.Codec)
	if err != nil {
		b.Close()
		return nil, err
	}
	return st, nil
}

// resolveBucketURL anchors a relative file:// bucket path to the config file's
// directory, the same way blobfs anchors its directory (and the catalog above).
// Only the local-filesystem "file" scheme carries a path to resolve — s3/gs/mem
// URLs are returned unchanged. Everything after file:// (up to a "?query") is taken
// as the filesystem path and run through opts.Resolve, then re-prefixed; an absolute
// path (file:///abs) or an empty BaseDir passes through. This sidesteps gocloud's
// own file:// handling, which otherwise resolves a relative path against the CWD
// (file://./x) or misreads the first segment as a URL host (file://x → /x).
func resolveBucketURL(opts cryptostore.StoreOptions) string {
	const prefix = "file://"
	if !strings.HasPrefix(opts.DSN, prefix) {
		return opts.DSN
	}
	path, query, hasQuery := strings.Cut(strings.TrimPrefix(opts.DSN, prefix), "?")
	url := prefix + opts.Resolve(path)
	if hasQuery {
		url += "?" + query
	}
	return url
}

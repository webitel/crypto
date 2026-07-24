package cryptostore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
)

// StoreOptions carries everything a store DriverFunc needs to build a Store from
// configuration: the shared codec core, the store's data source name, and its
// raw config and schema blocks. Core does not parse the DSN opaque part or the
// config/schema blocks — the driver does — so core stays agnostic of impl
// specifics.
type StoreOptions struct {
	DSN       string          // [D]ata [S]ource [N]ame ; scheme selects the driver, opaque is the driver's connection options
	Name      string          // store friendly / display name
	Codec     *Codec          // value-oriented encryption codec
	ConfigRaw json.RawMessage // store impl-specific extras not expressible in the DSN
	SchemaRaw json.RawMessage // field schema for record-oriented stores (may be empty)
	Verbose   bool            // enable store-level debug logging (e.g. SQL query tracing)
	// BaseDir is the directory of the config source that declared the store (empty
	// when the config did not come from a file). Drivers anchor relative filesystem
	// paths — a blobfs directory, a sqlite catalog — to it via Resolve, so those
	// paths are relative to the config file, not the process working directory.
	BaseDir string
}

// Resolve interprets a driver's filesystem path relative to the config source that
// declared the store: an absolute path (or empty) is returned unchanged; a relative
// one is joined with BaseDir. When BaseDir is empty (config not from a file), the
// path is returned as-is, i.e. left to resolve against the process working directory
// — the historical behavior. Drivers whose DSN opaque or config block names a local
// path should route it through Resolve.
func (x *StoreOptions) Resolve(path string) string {
	if path == "" {
		return ""
	}
	if x.BaseDir == "" || filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(x.BaseDir, path)
}

// DriverFunc builds a Store for a registered DSN scheme — the factory a driver
// package registers for its scheme(s). A Store that owns resources (e.g. a
// connection pool) may also implement io.Closer; Open's caller is responsible for
// closing such stores on shutdown.
type DriverFunc func(ctx context.Context, opts StoreOptions) (Store, error)

var (
	regMu    sync.RWMutex
	registry = map[string]DriverFunc{}
)

// Register makes a DriverFunc available under a DSN scheme (the part before the
// first ":", e.g. "postgres", "blobfs", "s3"). Implementations call it from an
// init(), so importing the impl package (e.g. _ "github.com/webitel/crypto/cryptostore/postgres")
// enables that scheme; a driver may register several schemes. It panics on empty
// or duplicate registration.
func Register(scheme string, driver DriverFunc) {
	if scheme == "" || driver == nil {
		panic("cryptostore: Register requires a non-empty scheme and driver")
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[scheme]; dup {
		panic("cryptostore: duplicate store scheme " + scheme)
	}
	registry[scheme] = driver
}

// Schemes returns the registered DSN schemes, sorted — useful for diagnostics.
func Schemes() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	return schemesLocked()
}

// Scheme returns the DSN scheme: everything before the first ":", or the whole
// string when there is no ":". The opaque remainder (if any) is the driver's to
// interpret — core only uses the scheme to pick the opener.
func Scheme(dsn string) string {
	scheme, _, _ := getScheme(dsn)
	return scheme
}

// Maybe rawDSN is of the form scheme:opaque.
// (Scheme must be [a-zA-Z][a-zA-Z0-9+.-]*)
// If so, return scheme, opaque; else return "", rawDSN.
func getScheme(rawDSN string) (scheme, opaque string, err error) {
	for i := 0; i < len(rawDSN); i++ {
		c := rawDSN[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		// do nothing
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return "", rawDSN, nil
			}
		case c == ':':
			if i == 0 {
				return "", "", errors.New("dsn: missing protocol scheme")
			}
			return rawDSN[:i], rawDSN[i+1:], nil
		default:
			// we have encountered an invalid character,
			// so there is no valid scheme
			return "", rawDSN, nil
		}
	}
	// it is implied that this is a stand-alone scheme without options
	return rawDSN, "", nil
}

// OpenStore opens a single store via the driver registered for opts.DSN's scheme.
// It is the core per-store primitive; assembling many stores from a config file
// (with a shared Codec and a Migration over them) is the agent's job — see cryptoctl.
func OpenStore(ctx context.Context, opts StoreOptions) (Store, error) {
	driver, err := lookupDriver(Scheme(opts.DSN))
	if err != nil {
		return nil, err
	}
	return driver(ctx, opts)
}

func lookupDriver(scheme string) (DriverFunc, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	o, ok := registry[scheme]
	if !ok {
		return nil, fmt.Errorf("cryptostore: unknown store protocol scheme %q (.well-known: %v)", scheme, schemesLocked())
	}
	return o, nil
}

func schemesLocked() []string {
	out := make([]string, 0, len(registry))
	for s := range registry {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

// init registers the "postgres" DSN scheme. Import this package for its side
// effect (e.g. _ "github.com/webitel/crypto/cryptostore/postgres") to let
// cryptostore.OpenStore build Postgres stores from configuration. The connection
// string is the whole DSN (postgres://…); the schema holding the SQL helper
// functions comes from the config block (Config.Schema).
func init() {
	cryptostore.Register("postgres", open)
}

func open(ctx context.Context, opts cryptostore.StoreOptions) (cryptostore.Store, error) {
	var cfg Config
	if len(opts.ConfigRaw) > 0 {
		if err := json.Unmarshal(opts.ConfigRaw, &cfg); err != nil {
			return nil, fmt.Errorf("postgres: config: %w", err)
		}
	}
	var sch *schema.Config
	if len(opts.SchemaRaw) > 0 {
		s, err := schema.ParseConfig(opts.SchemaRaw)
		if err != nil {
			return nil, err
		}
		sch = s
	}
	name := cfg.Name
	if name == "" {
		name = opts.Name
	}
	codec, err := schema.NewCodec(schema.WithBase(opts.Codec), schema.WithBaseline(sch))
	if err != nil {
		return nil, err
	}
	// Fail fast (before acquiring a pool): this record store fills the search-index
	// column, so a schema with searchable fields needs a blind-index keyring.
	if err := codec.RequireIndex(); err != nil {
		return nil, fmt.Errorf("postgres: %s: %w", name, err)
	}
	// Stores with the same DSN share one pool (see pool.go); InstallFunctions runs
	// per store since the function schema (Config.Schema) may differ, and it is idempotent.
	pool, err := acquirePool(ctx, opts.DSN, pgxConnString(opts.DSN), opts.Verbose)
	if err != nil {
		return nil, err
	}
	if err := InstallFunctions(ctx, pool, cfg.Schema); err != nil {
		releasePool(opts.DSN)
		return nil, err
	}
	return &sharedStore{
		Store: New(name, pool, codec, cfg.Schema),
		dsn:   opts.DSN,
	}, nil
}

// sharedStore is a registry-opened Store backed by a reference-counted shared pool.
// Close drops the store's reference exactly once; the pool closes with the last one.
type sharedStore struct {
	*Store
	dsn  string
	once sync.Once
}

func (c *sharedStore) Close() error {
	c.once.Do(func() { releasePool(c.dsn) })
	return nil
}

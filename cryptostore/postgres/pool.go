package postgres

import (
	"context"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Stores opened through the cryptostore registry (cryptostore.OpenStore) share one pgx
// pool per identical DSN: a deployment (e.g. the cryptoctl agent) that gathers many
// per-service store configs — each with its own schema but the same "postgres" DSN —
// then talks to one database over a single pool instead of N. The pool is reference
// counted by DSN and closed when the last store using it is closed. The standalone
// Open constructor is unaffected — it always owns a dedicated pool.
var (
	poolMu    sync.Mutex
	poolCache = map[string]*sharedPool{} // key: the store DSN, verbatim
)

type sharedPool struct {
	pool *pgxpool.Pool
	refs int
}

// acquirePool returns the pool for dsn, creating it (from connString) on first use
// and reusing it — with an incremented reference count — on later calls with the
// same dsn. Balance every successful call with releasePool.
func acquirePool(ctx context.Context, dsn, connString string, verbose bool) (*pgxpool.Pool, error) {
	poolMu.Lock()
	defer poolMu.Unlock()
	if sp := poolCache[dsn]; sp != nil {
		sp.refs++
		return sp.pool, nil
	}
	pool, err := newPool(ctx, connString, verbose)
	if err != nil {
		return nil, err
	}
	poolCache[dsn] = &sharedPool{pool: pool, refs: 1}
	return pool, nil
}

// releasePool drops one reference to dsn's pool, closing it once the last reference
// is gone. It is a no-op for an unknown dsn.
func releasePool(dsn string) {
	poolMu.Lock()
	defer poolMu.Unlock()
	sp := poolCache[dsn]
	if sp == nil {
		return
	}
	sp.refs--
	if sp.refs <= 0 {
		sp.pool.Close()
		delete(poolCache, dsn)
	}
}

// pgxConnString derives the pgx connection string from a store DSN of the form
// <scheme>[:opaque]. A URL-form opaque ("//host/db") keeps its scheme so pgx parses
// it as a URL; anything else (a keyword string, or the empty opaque of a bare
// "postgres" / "postgres:") is passed through — empty means "resolve from the libpq
// environment (PGHOST, PGPORT, PGSERVICE, …)".
func pgxConnString(dsn string) string {
	_, opaque, _ := strings.Cut(dsn, ":")
	if strings.HasPrefix(opaque, "//") {
		return dsn
	}
	return opaque
}

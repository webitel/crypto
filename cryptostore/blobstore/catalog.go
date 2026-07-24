package blobstore

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go sqlite driver, registers "sqlite"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

// catalog is the store's controller index: a small sqlite database recording one
// row per object (key, key version). Every Put/Delete/Migrate goes through it, so
// per-key usage is an O(1) GROUP BY and migration enumerates only the affected
// keys — no full directory scan or per-object header read. It can be rebuilt from
// the objects themselves (Reindex) if it drifts.
type catalog struct {
	db *sql.DB
}

func openCatalog(path string) (*catalog, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("blobstore: open catalog: %w", err)
	}
	// sqlite is a single-writer; one connection avoids "database is locked".
	db.SetMaxOpenConns(1)
	const ddl = `
		PRAGMA journal_mode=WAL;
		PRAGMA busy_timeout=5000;
		CREATE TABLE IF NOT EXISTS objects (
			key        TEXT PRIMARY KEY,
			kid        INTEGER NOT NULL,
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		);
		CREATE INDEX IF NOT EXISTS objects_kid ON objects(kid);`
	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("blobstore: init catalog: %w", err)
	}
	return &catalog{db: db}, nil
}

func (c *catalog) close() error { return c.db.Close() }

func (c *catalog) upsert(ctx context.Context, key string, kid cryptobox.KID) error {
	_, err := c.db.ExecContext(ctx,
		`INSERT INTO objects (key, kid, updated_at) VALUES (?,?, strftime('%s','now'))
		 ON CONFLICT(key) DO UPDATE SET kid=excluded.kid, updated_at=excluded.updated_at`,
		key, int64(kid))
	return err
}

func (c *catalog) setKID(ctx context.Context, key string, kid cryptobox.KID) error {
	_, err := c.db.ExecContext(ctx,
		`UPDATE objects SET kid=?, updated_at=strftime('%s','now') WHERE key=?`, int64(kid), key)
	return err
}

func (c *catalog) remove(ctx context.Context, key string) error {
	_, err := c.db.ExecContext(ctx, `DELETE FROM objects WHERE key=?`, key)
	return err
}

func (c *catalog) usage(ctx context.Context) ([]cryptostore.KeyUsage, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT kid, count(*) FROM objects GROUP BY kid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cryptostore.KeyUsage
	for rows.Next() {
		var kid int64
		var u cryptostore.KeyUsage
		if err := rows.Scan(&kid, &u.Count); err != nil {
			return nil, err
		}
		u.KID = cryptobox.KID(kid)
		out = append(out, u)
	}
	return out, rows.Err()
}

// keysNotUnder returns object keys whose key version is not primary — the work
// list for migration.
func (c *catalog) keysNotUnder(ctx context.Context, primary cryptobox.KID) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT key FROM objects WHERE kid <> ? ORDER BY key`, int64(primary))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// catalogEntry is one object as discovered during a rebuild.
type catalogEntry struct {
	key string
	kid cryptobox.KID
}

// replaceAll atomically swaps the catalog contents for entries (used by Reindex).
func (c *catalog) replaceAll(ctx context.Context, entries []catalogEntry) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM objects`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO objects (key, kid, updated_at) VALUES (?,?, strftime('%s','now'))`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.key, int64(e.kid)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Package postgres implements a cryptostore.Store backed by PostgreSQL.
//
// Ciphertext is stored inline in each field (self-marking — see cryptostore
// framing); key versions are read straight from the ciphertext with the
// cryptostore_kid / cryptostore_kids SQL functions (InstallFunctions), so Usage
// and Migrate need no companion key-version column. Searchable fields keep their
// blind-index tokens in the schema.Codec's single __cs_idx column. Migration is in
// place and opportunistic — a natural write re-encrypts under the primary key —
// with Migrate sweeping any stragglers.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/tracelog"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

// Store is a Postgres-backed cryptostore.Store. Create one with New (reusing a
// service pool) in-service, or let cryptostore.OpenStore build one from configuration
// (the registry driver — scheme "postgres" — over a shared pool; see driver.go).
type Store struct {
	db     DB
	name   string
	codec  *schema.Codec
	schema string // schema holding cryptostore_kid / cryptostore_kids
}

// New builds a store over an existing db connection — the right choice in-service,
// reusing the service's own pool. dbSchema (empty → "public") is where the
// cryptostore_* functions were installed.
func New(name string, db DB, codec *schema.Codec, dbSchema string) *Store {
	if dbSchema == "" {
		dbSchema = defaultSchema
	}
	return &Store{db: db, name: name, codec: codec, schema: dbSchema}
}

// Name implements cryptostore.Store.
func (c *Store) Name() string { return c.name }

// SearchToken returns the __cs_idx slot key and the base64url blind-index token for
// an exact-match lookup on a searchable field. It delegates to the field codec, so
// the domain and dotted-key escaping match what was written at encode time. value
// is the plaintext; path is the json attribute's object-key segments (empty for a
// scalar field). Used by the agent's `search` command to build a containment query.
func (c *Store) SearchToken(ctx context.Context, unit, field string, value any, path ...string) (key, token string, err error) {
	return c.codec.SearchToken(ctx, unit, field, value, path...)
}

func (c *Store) kidFn() string     { return ident(c.schema, true) + ".cryptostore_kid" }
func (c *Store) kidsFn() string    { return ident(c.schema, true) + ".cryptostore_kids" }
func (c *Store) pendingFn() string { return ident(c.schema, true) + ".cryptostore_pending" }

type encField struct {
	unit  string
	field string
	json  bool
	paths [][]string // for json fields: parsed object-key paths of the encrypted attributes
}

func (c *Store) fields() []encField {
	sc := c.codec.Schema()
	var out []encField
	for unit, u := range sc.Units {
		for f, p := range u.Fields {
			ef := encField{unit: unit, field: f, json: p.HasNested()}
			for _, a := range p.Nested {
				if keys, err := a.Segments(); err == nil {
					ef.paths = append(ef.paths, keys)
				}
			}
			out = append(out, ef)
		}
	}
	return out
}

// Usage implements cryptostore.Store. Like Migrate, it works PER TABLE — one scan
// per unit, not one per column: a LATERAL subquery unfolds every managed column of
// each row into a set of kids (scalar → cryptostore_kid, 0 or 1 kid, NULL legacy
// plaintext excluded; json → cryptostore_kids, one per encrypted attribute), which
// the outer query groups and counts. Counts only (ciphertext volume is not
// reported). A managed column not yet deployed skips the whole table, as in Migrate.
func (c *Store) Usage(ctx context.Context) ([]cryptostore.KeyUsage, error) {
	agg := map[cryptobox.KID]int64{}
	units := c.units()
	names := make([]string, 0, len(units))
	for u := range units {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, unit := range names {
		if err := c.usageUnit(ctx, unit, units[unit], agg); err != nil {
			return nil, err
		}
	}
	out := make([]cryptostore.KeyUsage, 0, len(agg))
	for kid, n := range agg {
		out = append(out, cryptostore.KeyUsage{KID: kid, Count: n})
	}
	return out, nil
}

// usageUnit tallies key usage for one table in a single scan, folding every managed
// column into a per-row set of kids via one LATERAL subquery (see Usage). Results
// are accumulated into agg.
func (c *Store) usageUnit(ctx context.Context, unit string, fields []encField, agg map[cryptobox.KID]int64) error {
	branches := make([]string, 0, len(fields))
	for _, f := range fields {
		col := "r." + ident(f.field, true)
		if f.json {
			branches = append(branches, fmt.Sprintf(`SELECT ks.kid FROM %s(%s) AS ks(kid)`, c.kidsFn(), col))
		} else {
			branches = append(branches, fmt.Sprintf(`SELECT %s(%s)::int AS kid WHERE %[1]s(%[2]s) NOTNULL`, c.kidFn(), col))
		}
	}
	if len(branches) == 0 {
		return nil
	}
	q := fmt.Sprintf(
		`SELECT k.kid, count(*)::bigint FROM %s r
		 CROSS JOIN LATERAL (%s) AS k(kid) GROUP BY k.kid`,
		tableName(unit), strings.Join(branches, " UNION ALL "),
	)
	rows, err := c.db.Query(ctx, q)
	if err != nil {
		if isColumnUndefined(err) {
			return nil // a managed column isn't deployed yet — skip the table
		}
		return fmt.Errorf("postgres: usage %s: %w", unit, err)
	}
	defer rows.Close()
	for rows.Next() {
		var kid int32
		var n int64
		if err := rows.Scan(&kid, &n); err != nil {
			return err
		}
		agg[cryptobox.KID(kid)] += n
	}
	return rows.Err()
}

// Migrate implements cryptostore.Store. It (re-)encrypts every managed value to
// the primary key, working PER TABLE and in batches: each batch selects the rows
// needing work, runs them through the field codec (DecodeRecords → EncodeRecords,
// which also rebuilds the __cs_idx search tokens), and writes the whole batch back
// in a single set-based UPDATE. The UPDATE carries an optimistic CAS on the old
// values (IS NOT DISTINCT FROM), so a concurrent natural write is skipped, not
// clobbered. A row qualifies when any scalar column holds non-empty, non-primary
// data (plaintext counts → first-time encryption) or any json attribute is under a
// non-primary key. Empty/NULL values are left untouched. DryRun only counts.
func (c *Store) Migrate(ctx context.Context, req cryptostore.MigrateOptions) (cryptostore.MigrateResult, error) {
	res := cryptostore.MigrateResult{Store: c.name}
	primary, err := c.codec.Base().PrimaryKID(ctx)
	if err != nil {
		return res, err
	}
	batch := req.BatchSize
	if batch <= 0 {
		batch = defaultBatchSize
	}

	units := c.units()
	names := make([]string, 0, len(units))
	for u := range units {
		names = append(names, u)
	}
	sort.Strings(names)

	if req.DryRun {
		for _, unit := range names {
			n, err := c.countUnit(ctx, unit, units[unit], int32(primary))
			if err != nil {
				return res, err
			}
			res.Scanned += n
			res.Remaining += n
		}
		return res, nil
	}

	var done, total int64
	if req.OnProgress != nil {
		for _, unit := range names {
			if n, err := c.countUnit(ctx, unit, units[unit], int32(primary)); err == nil {
				total += n
			}
		}
		req.OnProgress(cryptostore.Progress{Store: c.name, Total: total})
	}
	report := func(d int64) {
		if req.OnProgress == nil {
			return
		}
		done += d
		req.OnProgress(cryptostore.Progress{Store: c.name, Done: done, Total: total})
	}

	for _, unit := range names {
		ur, err := c.migrateUnit(ctx, unit, units[unit], int32(primary), batch, req, report)
		if err != nil {
			return res, err
		}
		res.Scanned += ur.Scanned
		res.Recrypted += ur.Recrypted
	}
	return res, nil
}

// units groups the managed fields by their table.
func (c *Store) units() map[string][]encField {
	out := map[string][]encField{}
	for _, f := range c.fields() {
		out[f.unit] = append(out[f.unit], f)
	}
	return out
}

// predicate is the WHERE selecting rows that still need (re-)encryption. Scalar:
// a non-empty value not under the primary key (length>0 already excludes NULL and
// empty). JSON: any configured attribute path is "pending" per cryptostore_pending
// — which catches plaintext attributes (first-time encryption), not just
// non-primary ciphertext.
func (c *Store) predicate(rel string, fields []encField) string {
	parts := make([]string, len(fields))
	for i, f := range fields {
		col := (rel + ".") + ident(f.field, true)
		if f.json {
			if len(f.paths) == 0 {
				parts[i] = "false" // json field with no configured paths: nothing to do
				continue
			}
			terms := make([]string, len(f.paths))
			for j, keys := range f.paths {
				terms[j] = fmt.Sprintf("%s(%s, $1)", c.pendingFn(), jsonbPathExpr(col, keys))
			}
			parts[i] = "(" + strings.Join(terms, " OR ") + ")"
		} else {
			parts[i] = fmt.Sprintf("(length(%s) > 0 AND %s(%[1]s) IS DISTINCT FROM $1)", col, c.kidFn())
		}
	}
	return strings.Join(parts, " OR ")
}

// jsonbPathExpr builds a jsonb navigation expression for an object-key path, e.g.
// col=profile, keys=["passport","number"] → `"profile" -> 'passport' -> 'number'`.
func jsonbPathExpr(col string, keys []string) string {
	var b strings.Builder
	b.WriteString(col)
	for _, k := range keys {
		b.WriteString("->'")
		b.WriteString(strings.ReplaceAll(k, "'", "''"))
		b.WriteString("'")
	}
	return b.String()
}

// unitHasSearch reports whether any field of the unit is searchable, i.e. whether
// the __cs_idx column is in play.
func (c *Store) unitHasSearch(unit string) bool {
	return c.codec.Schema().Unit(unit).HasSearchable()
}

func (c *Store) countUnit(ctx context.Context, unit string, fields []encField, primary int32) (int64, error) {
	q := fmt.Sprintf(`SELECT count(*)::bigint FROM %s r WHERE %s`, tableName(unit), c.predicate("r", fields))
	rows, err := c.db.Query(ctx, q, primary)
	if err != nil {
		if isColumnUndefined(err) {
			return 0, nil
		}
		return 0, err
	}
	defer rows.Close()
	var n int64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
	}
	return n, rows.Err()
}

func (c *Store) migrateUnit(ctx context.Context, unit string, fields []encField, primary int32, batch int, req cryptostore.MigrateOptions, report func(int64)) (cryptostore.MigrateResult, error) {
	var res cryptostore.MigrateResult
	tbl := tableName(unit)
	selCols := make([]string, len(fields))
	for i, f := range fields {
		selCols[i] = "r." + ident(f.field, true)
	}
	sel := fmt.Sprintf(`SELECT ctid::text, %s FROM %s r WHERE %s LIMIT %d`,
		strings.Join(selCols, ", "), tbl, c.predicate("r", fields), batch)
	hasSearch := c.unitHasSearch(unit)

	for {
		rows, err := c.db.Query(ctx, sel, primary)
		if err != nil {
			if isColumnUndefined(err) {
				return res, nil // column not deployed yet — nothing to do
			}
			return res, fmt.Errorf("postgres: scan %s: %w", unit, err)
		}
		var ctids []string
		var recs []schema.Record
		olds := make([][][]byte, len(fields))
		for rows.Next() {
			ctid := ""
			vals := make([][]byte, len(fields))
			dst := make([]any, 0, len(fields)+1)
			dst = append(dst, &ctid)
			for i := range fields {
				dst = append(dst, &vals[i])
			}
			if err := rows.Scan(dst...); err != nil {
				rows.Close()
				return res, err
			}
			ctids = append(ctids, ctid)
			rec := schema.Record{}
			for i, f := range fields {
				rec[f.field] = vals[i]
				olds[i] = append(olds[i], vals[i])
			}
			recs = append(recs, rec)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return res, err
		}
		if len(recs) == 0 {
			break
		}
		res.Scanned += int64(len(recs))

		// Normalize the whole row to the primary key and rebuild search tokens:
		// decode any ciphertext (and leave legacy plaintext) → encrypt every managed
		// field + fill __cs_idx. Idempotent for values already under the primary key.
		if err := c.codec.DecodeRecords(ctx, unit, recs); err != nil {
			return res, fmt.Errorf("postgres: decode %s: %w", unit, err)
		}
		if err := c.codec.EncodeRecords(ctx, unit, recs); err != nil {
			return res, fmt.Errorf("postgres: encode %s: %w", unit, err)
		}

		news := make([][][]byte, len(fields))
		for i, f := range fields {
			news[i] = make([][]byte, len(recs))
			for j, rec := range recs {
				news[i][j] = toColBytes(rec[f.field])
			}
		}
		var idxNew [][]byte
		if hasSearch {
			idxNew = make([][]byte, len(recs))
			for j, rec := range recs {
				idxNew[j] = toColBytes(rec[c.codec.IndexField()])
			}
		}

		upd, args := c.buildUpdate(tbl, fields, hasSearch, ctids, news, olds, idxNew)
		tag, err := c.db.Exec(ctx, upd, args...)
		if err != nil {
			return res, fmt.Errorf("postgres: update %s: %w", unit, err)
		}
		res.Recrypted += tag.RowsAffected()
		report(int64(len(recs)))
		if tag.RowsAffected() == 0 {
			break // whole batch lost the CAS race; stop to avoid re-scanning forever
		}
		if err := throttle(ctx, req.RatePerSec, len(recs)); err != nil {
			return res, err
		}
	}
	return res, nil
}

// buildUpdate renders the single set-based UPDATE for a batch: every column's new
// value (and the search index) arrives as a parallel array via unnest, keyed by
// ctid, with an optimistic CAS (IS NOT DISTINCT FROM) on each column's old value.
// All arrays are bytea[]; json columns and __cs_idx are cast back with convert_from.
func (c *Store) buildUpdate(tbl string, fields []encField, hasSearch bool, ctids []string, news, olds [][][]byte, idxNew [][]byte) (string, []any) {
	var args []any
	arg := func(v any) int { args = append(args, v); return len(args) }

	unnest := []string{fmt.Sprintf("$%d::text[]", arg(ctids))}
	names := []string{"ctid"}
	var sets, cas []string
	for i, f := range fields {
		np, op := arg(news[i]), arg(olds[i])
		nn, on := fmt.Sprintf("n%d", i), fmt.Sprintf("o%d", i)
		unnest = append(unnest, fmt.Sprintf("$%d::bytea[]", np), fmt.Sprintf("$%d::bytea[]", op))
		names = append(names, nn, on)
		col := ident(f.field, false)
		if f.json {
			sets = append(sets, fmt.Sprintf("%s = convert_from(u.%s, 'UTF8')::jsonb", col, nn))
			cas = append(cas, fmt.Sprintf("t.%s IS NOT DISTINCT FROM convert_from(u.%s, 'UTF8')::jsonb", col, on))
		} else {
			sets = append(sets, fmt.Sprintf("%s = u.%s", col, nn))
			cas = append(cas, fmt.Sprintf("t.%s IS NOT DISTINCT FROM u.%s", col, on))
		}
	}
	if hasSearch {
		ip := arg(idxNew)
		unnest = append(unnest, fmt.Sprintf("$%d::bytea[]", ip))
		names = append(names, "idx")
		sets = append(sets, fmt.Sprintf("%s = convert_from(u.idx, 'UTF8')::jsonb", ident(c.codec.IndexField(), false)))
	}

	q := fmt.Sprintf(
		`UPDATE %s AS t SET %s FROM unnest(%s) AS u(%s) WHERE t.ctid = u.ctid::tid AND %s`,
		tbl, strings.Join(sets, ", "), strings.Join(unnest, ", "), strings.Join(names, ", "), strings.Join(cas, " AND "))
	return q, args
}

// toColBytes coerces a codec output value to the bytes bound into the UPDATE array
// (nil → SQL NULL).
func toColBytes(v any) []byte {
	switch t := v.(type) {
	case nil:
		return nil
	case []byte:
		return t
	case json.RawMessage:
		return []byte(t)
	case string:
		return []byte(t)
	default:
		return nil
	}
}

// newPool builds a pgx pool from a raw pgx connection string (URL or keyword form;
// empty resolves entirely from the libpq environment). verbose attaches a query
// tracer.
func newPool(ctx context.Context, connString string, verbose bool) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("postgres: invalid dsn ; %w", err)
	}
	if verbose {
		cfg.ConnConfig.Tracer = &tracelog.TraceLog{
			LogLevel: tracelog.LogLevelTrace,
			Logger:   tracelog.LoggerFunc(TraceLog),
			Config:   tracelog.DefaultTraceLogConfig(),
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	return pool, nil
}

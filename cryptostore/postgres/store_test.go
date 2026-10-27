package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/postgres" // import triggers init() → registers "postgres" kind
	"github.com/webitel/crypto/cryptostore/schema"
)

// TestOpenSearchableRequiresIndex is the fail-fast check: a schema with searchable
// fields but no search keyring must error at Open (before any DB connection), not
// silently disable search and blow up later on a write. No database needed — the
// opener rejects the config before postgres.Open connects.
func TestOpenSearchableRequiresIndex(t *testing.T) {
	ring, err := cryptobox.ParseKeyring("correct-horse-battery-staple-001!")
	if err != nil {
		t.Fatal(err)
	}
	// codec with NO blind index (nil) → a searchable schema must be rejected at open
	codec, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cryptostore.OpenStore(context.Background(), cryptostore.StoreOptions{
		DSN:       "postgres://localhost/unused",
		Name:      "t",
		Codec:     codec,
		SchemaRaw: json.RawMessage(`{"version":1,"units":{"u.t":{"fields":{"email":{"search":true}}}}}`),
	})
	if err == nil {
		t.Fatal("expected error: searchable schema without a search keyring")
	}
	if !strings.Contains(err.Error(), "searchable fields require a keyring") {
		t.Fatalf("error = %v, want mention of the missing search keyring", err)
	}
}

// TestStoreJSONFirstEncryption covers first-time encryption of a json attribute
// that has never been encrypted (the path-aware predicate, not just re-key), and
// the codec's skip rules: absent path, json null, and empty string are left alone.
func TestStoreJSONFirstEncryption(t *testing.T) {
	dsn := os.Getenv("CRYPTOSTORE_PG_DSN")
	if dsn == "" {
		t.Skip("set CRYPTOSTORE_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := postgres.InstallFunctions(ctx, pool, "public"); err != nil {
		t.Fatalf("install: %v", err)
	}

	const ddl = `
		CREATE SCHEMA IF NOT EXISTS cryptostore_test;
		DROP TABLE IF EXISTS cryptostore_test.jsonenc;
		CREATE TABLE cryptostore_test.jsonenc (
			id      bigint PRIMARY KEY,
			profile jsonb
		);`
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS cryptostore_test.jsonenc`) })

	// Seed raw PLAINTEXT documents (never encrypted), exercising the skip cases.
	seed := map[int]string{
		1: `{"name":"x","ssn":"111"}`, // plaintext ssn → encrypt
		2: `{"name":"y"}`,             // ssn absent → skip
		3: `{"name":"z","ssn":""}`,    // empty ssn → skip
		4: `{"ssn":null}`,             // json null → skip
	}
	for id, doc := range seed {
		if _, err := pool.Exec(ctx,
			`INSERT INTO cryptostore_test.jsonenc (id, profile) VALUES ($1, $2::jsonb)`, id, doc); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	sch, err := schema.ParseConfig([]byte(`{
		"version": 1,
		"units": {"cryptostore_test.jsonenc": {"fields": {"profile": {"nested": ["$.ssn"]}}}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cd := schemaCodec(t, inlineCodec(t, "correct-horse-battery-staple-001!"), sch)
	store := postgres.New("pg:jsonenc", pool, cd, "public")

	res, err := store.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if res.Recrypted != 1 {
		t.Fatalf("recrypted = %d, want 1 (only the plaintext-ssn row)", res.Recrypted)
	}

	// Exactly one row now has an encrypted ssn (cbox: tag).
	var enc int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM cryptostore_test.jsonenc WHERE left(profile->>'ssn', 5) = 'cbox:'`).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if enc != 1 {
		t.Fatalf("rows with encrypted ssn = %d, want 1", enc)
	}

	// Row 1 decrypts back to the original ssn.
	var prof []byte
	if err := pool.QueryRow(ctx, `SELECT profile FROM cryptostore_test.jsonenc WHERE id=1`).Scan(&prof); err != nil {
		t.Fatal(err)
	}
	rec := schema.Record{"profile": json.RawMessage(prof)}
	if err := cd.DecodeRecords(ctx, "cryptostore_test.jsonenc", []schema.Record{rec}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.Unmarshal(rec["profile"].([]byte), &doc)
	if doc["ssn"] != "111" {
		t.Fatalf("ssn after first-encrypt = %#v", doc["ssn"])
	}

	// Second run is a no-op (skip cases stay plaintext, row 1 already at primary).
	res2, err := store.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Recrypted != 0 {
		t.Fatalf("second migrate recrypted = %d, want 0 (idempotent)", res2.Recrypted)
	}
}

// inlineCodec builds a codec with a blind-index root key (searchable fields
// need one).
func inlineCodec(t *testing.T, keys string) *cryptostore.Codec {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	index, err := cryptobox.ParseKeyring("blind-index-root-key-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), index)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// schemaCodec wraps a base core with a fixed schema (as WithBaseline), the common
// test shape for the store-level codec.
func schemaCodec(t *testing.T, base *cryptostore.Codec, cfg *schema.Config) *schema.Codec {
	t.Helper()
	cd, err := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(cfg))
	if err != nil {
		t.Fatalf("schema.NewCodec: %v", err)
	}
	return cd
}

// TestInlineStore exercises inline-v2 Usage + Migrate (scalar bytea + json
// attributes) against a real Postgres, using the cryptostore_* SQL functions.
// Gated on CRYPTOSTORE_PG_DSN.
func TestStore(t *testing.T) {
	dsn := os.Getenv("CRYPTOSTORE_PG_DSN")
	if dsn == "" {
		t.Skip("set CRYPTOSTORE_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := postgres.InstallFunctions(ctx, pool, "public"); err != nil {
		t.Fatalf("install: %v", err)
	}

	const ddl = `
		CREATE SCHEMA IF NOT EXISTS cryptostore_test;
		DROP TABLE IF EXISTS cryptostore_test.users;
		CREATE TABLE cryptostore_test.users (
			id       bigint PRIMARY KEY,
			email    bytea,
			profile  jsonb,
			__cs_idx jsonb
		);`
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS cryptostore_test.users`) })

	sch, err := schema.ParseConfig([]byte(`{
		"version": 1,
		"units": {"cryptostore_test.users": {"fields": {
			"email":   {"search": true},
			"profile": {"nested": ["$.ssn"]}
		}}}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	seed := []struct {
		id    int
		email string
		ssn   string
	}{{1, "a@x.io", "111"}, {2, "b@x.io", "222"}, {3, "c@x.io", "333"}}

	// Seed under key version 1.
	cd1 := schemaCodec(t, inlineCodec(t, "correct-horse-battery-staple-001!"), sch)
	for _, r := range seed {
		rec := schema.Record{
			"email":   r.email,
			"profile": json.RawMessage(`{"name":"x","ssn":"` + r.ssn + `"}`),
		}
		if err := cd1.EncodeRecords(ctx, "cryptostore_test.users", []schema.Record{rec}); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(ctx,
			`INSERT INTO cryptostore_test.users (id, email, profile) VALUES ($1,$2,$3::jsonb)`,
			r.id, rec["email"], string(rec["profile"].([]byte)))
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	store1 := postgres.New("pg:inline", pool, cd1, "public")
	// 3 emails + 3 ssn attributes, all under kid 1.
	if u, err := store1.Usage(ctx); err != nil {
		t.Fatal(err)
	} else if len(u) != 1 || u[0].KID != 1 || u[0].Count != 6 {
		t.Fatalf("usage before = %+v, want kid=1 count=6", u)
	}

	// Rotate and migrate to key version 2.
	cd2 := schemaCodec(t, inlineCodec(t, "correct-horse-battery-staple-001!,fresh-rotated-phrase-2026-xyz!"), sch)
	store2 := postgres.New("pg:inline", pool, cd2, "public")

	res, err := store2.Migrate(ctx, cryptostore.MigrateOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Recrypted counts ROWS rewritten (per-table batch UPDATE), not values: 3 rows.
	if res.Recrypted != 3 {
		t.Fatalf("migrate recrypted = %d, want 3 rows", res.Recrypted)
	}
	if u, err := store2.Usage(ctx); err != nil {
		t.Fatal(err)
	} else if len(u) != 1 || u[0].KID != 2 || u[0].Count != 6 {
		t.Fatalf("usage after = %+v, want kid=2 count=6", u)
	}

	mig := cryptostore.NewMigration(store2)
	if ok, _ := mig.CanRetire(ctx, 1); !ok {
		t.Fatal("CanRetire(1) = false after full migration")
	}

	// Data still decrypts under the new key.
	var email []byte
	var profile []byte
	if err := pool.QueryRow(ctx, `SELECT email, profile FROM cryptostore_test.users WHERE id=1`).Scan(&email, &profile); err != nil {
		t.Fatal(err)
	}
	rec := schema.Record{"email": email, "profile": json.RawMessage(profile)}
	if err := cd2.DecodeRecords(ctx, "cryptostore_test.users", []schema.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if string(rec["email"].([]byte)) != "a@x.io" {
		t.Fatalf("email after migrate = %q", rec["email"])
	}
	var doc map[string]any
	json.Unmarshal(rec["profile"].([]byte), &doc)
	if doc["ssn"] != "111" {
		t.Fatalf("ssn after migrate = %#v", doc["ssn"])
	}

	// Migrate also (re)built the search index: __cs_idx now holds the email token,
	// matching what the codec computes for a query — even though the seed left it NULL.
	key, tok, err := cd2.SearchToken(ctx, "cryptostore_test.users", "email", "a@x.io")
	if err != nil {
		t.Fatal(err)
	}
	var hit int
	if err := pool.QueryRow(ctx,
		`SELECT id FROM cryptostore_test.users WHERE __cs_idx @> jsonb_build_object($1::text, $2::text)`,
		key, tok).Scan(&hit); err != nil {
		t.Fatalf("search by __cs_idx token: %v", err)
	}
	if hit != 1 {
		t.Fatalf("search hit id = %d, want 1", hit)
	}
}

// TestStoreFirstEncryption is the client-rollout path: a table already migrated to
// bytea + __cs_idx but still holding PLAINTEXT. Migrate must encrypt the plaintext,
// fill __cs_idx, skip NULL/empty values, and be idempotent on a second run.
func TestStoreFirstEncryption(t *testing.T) {
	dsn := os.Getenv("CRYPTOSTORE_PG_DSN")
	if dsn == "" {
		t.Skip("set CRYPTOSTORE_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := postgres.InstallFunctions(ctx, pool, "public"); err != nil {
		t.Fatalf("install: %v", err)
	}

	const ddl = `
		CREATE SCHEMA IF NOT EXISTS cryptostore_test;
		DROP TABLE IF EXISTS cryptostore_test.firstenc;
		CREATE TABLE cryptostore_test.firstenc (
			id       bigint PRIMARY KEY,
			email    bytea,
			__cs_idx jsonb
		);`
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS cryptostore_test.firstenc`) })

	// Seed raw plaintext (as if a text→bytea migration just ran), plus NULL and empty.
	rows := []struct {
		id    int
		email []byte
	}{{1, []byte("a@x.io")}, {2, []byte("b@x.io")}, {3, nil}, {4, []byte{}}}
	for _, r := range rows {
		if _, err := pool.Exec(ctx,
			`INSERT INTO cryptostore_test.firstenc (id, email) VALUES ($1, $2)`, r.id, r.email); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	sch, err := schema.ParseConfig([]byte(`{
		"version": 1,
		"units": {"cryptostore_test.firstenc": {"fields": {"email": {"search": true}}}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cd := schemaCodec(t, inlineCodec(t, "correct-horse-battery-staple-001!"), sch)
	store := postgres.New("pg:firstenc", pool, cd, "public")

	res, err := store.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Only the two non-empty plaintext rows are encrypted; NULL and '' are skipped.
	if res.Recrypted != 2 {
		t.Fatalf("recrypted = %d, want 2 (NULL/empty skipped)", res.Recrypted)
	}

	// Row 1 now decrypts and is indexed.
	var email []byte
	if err := pool.QueryRow(ctx, `SELECT email FROM cryptostore_test.firstenc WHERE id=1`).Scan(&email); err != nil {
		t.Fatal(err)
	}
	rec := schema.Record{"email": email}
	if err := cd.DecodeRecords(ctx, "cryptostore_test.firstenc", []schema.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if string(rec["email"].([]byte)) != "a@x.io" {
		t.Fatalf("email after first-encrypt = %q", rec["email"])
	}

	// NULL and empty rows are untouched: still NULL email and NULL __cs_idx.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM cryptostore_test.firstenc
		 WHERE id IN (3,4) AND __cs_idx IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("NULL/empty rows: %d have NULL __cs_idx, want 2", n)
	}

	// Second run is a no-op (everything already at the primary key).
	res2, err := store.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Recrypted != 0 {
		t.Fatalf("second migrate recrypted = %d, want 0 (idempotent)", res2.Recrypted)
	}
}

// TestStoreSkipsMissingTable: a schema unit whose table does not exist in this database
// (the service owning it is not installed) is skipped, not an error: there is no data
// under any key there.
func TestStoreSkipsMissingTable(t *testing.T) {
	dsn := os.Getenv("CRYPTOSTORE_PG_DSN")
	if dsn == "" {
		t.Skip("set CRYPTOSTORE_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := postgres.InstallFunctions(ctx, pool, "public"); err != nil {
		t.Fatalf("install: %v", err)
	}

	const ddl = `
		CREATE SCHEMA IF NOT EXISTS cryptostore_test;
		DROP TABLE IF EXISTS cryptostore_test.present;
		DROP TABLE IF EXISTS cryptostore_test.absent;
		CREATE TABLE cryptostore_test.present (id bigint PRIMARY KEY, secret bytea);
		INSERT INTO cryptostore_test.present (id, secret) VALUES (1, 'plain');`
	if _, err := pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS cryptostore_test.present`) })

	sch, err := schema.ParseConfig([]byte(`{
		"version": 1,
		"units": {
			"cryptostore_test.absent":  {"fields": {"secret": {}}},
			"cryptostore_test.present": {"fields": {"secret": {}}}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cd := schemaCodec(t, inlineCodec(t, "correct-horse-battery-staple-001!"), sch)
	store := postgres.New("pg:missing", pool, cd, "public")

	if _, err := store.Usage(ctx); err != nil {
		t.Fatalf("usage with a missing table: %v", err)
	}
	res, err := store.Migrate(ctx, cryptostore.MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate with a missing table: %v", err)
	}
	if res.Recrypted != 1 {
		t.Fatalf("recrypted = %d, want 1 (the present table)", res.Recrypted)
	}
	usage, err := store.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].Count != 1 {
		t.Fatalf("usage = %+v, want one key with 1 value", usage)
	}
}

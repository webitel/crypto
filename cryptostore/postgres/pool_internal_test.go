package postgres

import (
	"context"
	"testing"
)

func TestPgxConnString(t *testing.T) {
	cases := map[string]string{
		"postgres":                 "",                         // bare scheme → env
		"postgres:":                "",                         // empty opaque → env
		"postgres://u:p@h:5432/db": "postgres://u:p@h:5432/db", // URL form kept whole
		"postgres:host=h user=me":  "host=h user=me",           // keyword form → opaque
	}
	for dsn, want := range cases {
		if got := pgxConnString(dsn); got != want {
			t.Errorf("pgxConnString(%q) = %q, want %q", dsn, got, want)
		}
	}
}

func TestPoolSharedByDSN(t *testing.T) {
	// pgxpool.NewWithConfig does not dial until first use, so this needs no DB.
	const dsn = "postgres://localhost:5432/acquire_test"
	ctx := context.Background()

	p1, err := acquirePool(ctx, dsn, pgxConnString(dsn), false)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	p2, err := acquirePool(ctx, dsn, pgxConnString(dsn), false)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if p1 != p2 {
		t.Fatal("same DSN did not share one pool")
	}

	poolMu.Lock()
	sp, ok := poolCache[dsn]
	refs := 0
	if ok {
		refs = sp.refs
	}
	poolMu.Unlock()
	if !ok || refs != 2 {
		t.Fatalf("cache entry: ok=%v refs=%d, want ok=true refs=2", ok, refs)
	}

	releasePool(dsn) // one store closed: pool stays (refs 1)
	poolMu.Lock()
	_, still := poolCache[dsn]
	poolMu.Unlock()
	if !still {
		t.Fatal("pool closed while a reference remained")
	}

	releasePool(dsn) // last store closed: pool gone
	poolMu.Lock()
	_, gone := poolCache[dsn]
	poolMu.Unlock()
	if gone {
		t.Fatal("pool not released after last reference")
	}
}

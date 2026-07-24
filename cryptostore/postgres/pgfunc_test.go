package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/postgres"
)

// TestSQLFunctions verifies cryptostore_kid / cryptostore_kids against ciphertext
// produced by the Go framing, cross-checked with cryptobox.KIDOf. Gated on
// CRYPTOSTORE_PG_DSN.
func TestSQLFunctions(t *testing.T) {
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

	codec1 := rawCodec(t, "only-phrase-key-aaaaaaaaaa!")                                   // kid 1
	codec200 := rawCodec(t, "first-phrase-key-aaaaaaaa!,[200]second-phrase-key-bbbbbbbb!") // kid 200

	// --- scalar bytea: cryptostore_kid matches KIDOf, NULL for plaintext --------
	for _, tc := range []struct {
		name string
		c    *cryptostore.Codec
	}{{"kid1", codec1}, {"kid200", codec200}} {
		framed, err := tc.c.Encrypt(ctx, []byte("hello "+tc.name))
		if err != nil {
			t.Fatal(err)
		}
		blob, _ := cryptostore.UnframeBinary(framed)
		want, _, _ := cryptobox.KIDOf(blob)

		var got *int
		if err := pool.QueryRow(ctx, `SELECT cryptostore_kid($1)`, framed).Scan(&got); err != nil {
			t.Fatalf("kid query: %v", err)
		}
		if got == nil || *got != int(want) {
			t.Fatalf("%s: cryptostore_kid=%v, want %d", tc.name, got, want)
		}
	}
	// Legacy plaintext bytea (former text) → NULL.
	var nilkid *int
	if err := pool.QueryRow(ctx, `SELECT cryptostore_kid(convert_to('ann@example.com','UTF8'))`).Scan(&nilkid); err != nil {
		t.Fatal(err)
	}
	if nilkid != nil {
		t.Fatalf("cryptostore_kid(plaintext) = %v, want NULL", *nilkid)
	}

	// --- jsonb: cryptostore_kids extracts every encrypted attribute's kid -------
	ssn, _ := codec1.EncryptText(ctx, []byte("123-45-6789"))  // kid 1
	pass, _ := codec200.EncryptText(ctx, []byte("AB1234567")) // kid 200
	doc, _ := json.Marshal(map[string]any{
		"name":     "Ann", // plaintext, ignored
		"ssn":      ssn,
		"passport": map[string]any{"number": pass}, // nested
	})
	rows, err := pool.Query(ctx, `SELECT k FROM cryptostore_kids($1::jsonb) k ORDER BY k`, string(doc))
	if err != nil {
		t.Fatal(err)
	}
	var kids []int
	for rows.Next() {
		var k int
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		kids = append(kids, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(kids) != 2 || kids[0] != 1 || kids[1] != 200 {
		t.Fatalf("cryptostore_kids = %v, want [1 200]", kids)
	}
}

func rawCodec(t *testing.T, keys string) *cryptostore.Codec {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

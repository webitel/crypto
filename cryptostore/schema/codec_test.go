package schema_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

const indexRoot = "blind-index-root-key-0123456789"

func mustParseRing(t *testing.T, s string) *cryptobox.Keyring {
	t.Helper()
	r, err := cryptobox.ParseKeyring(s)
	if err != nil {
		t.Fatalf("Parse keyring: %v", err)
	}
	return r
}

func testConfig(t *testing.T) *schema.Config {
	t.Helper()
	s, err := schema.ParseConfig([]byte(`{
	  "version": 1,
	  "units": {
	    "directory.users": {
	      "fields": {
	        "email":   {"search": true},
	        "phone":   {},
	        "profile": {"nested": [{"path": ["ssn"], "search": true}, "$.passport.number"]}
	      }
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return s
}

func newCodec(t *testing.T, keys string) *schema.Codec {
	t.Helper()
	ring, err := cryptobox.ParseKeyring(keys)
	if err != nil {
		t.Fatalf("Parse keyring: %v", err)
	}
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), mustParseRing(t, indexRoot))
	if err != nil {
		t.Fatalf("New codec: %v", err)
	}
	cd, err := schema.NewCodec(schema.WithBase(c), schema.WithBaseline(testConfig(t)))
	if err != nil {
		t.Fatalf("New schema codec: %v", err)
	}
	return cd
}

func TestEncodeDecode(t *testing.T) {
	ctx := context.Background()
	cd := newCodec(t, "correct-horse-battery-staple-001!")

	rec := schema.Record{
		"id":      7,
		"email":   "ann@example.com",
		"phone":   "+15551234567",
		"profile": json.RawMessage(`{"name":"Ann","ssn":"123-45-6789","passport":{"number":"AB1234567"}}`),
	}
	if err := cd.EncodeRecords(ctx, "directory.users", []schema.Record{rec}); err != nil {
		t.Fatalf("EncodeRecords: %v", err)
	}

	// Scalar ciphertext is self-marking (leading NUL) and not the plaintext.
	em := rec["email"].([]byte)
	if em[0] != 0x00 || string(em) == "ann@example.com" {
		t.Fatalf("email not inline-framed: %#v", em)
	}
	// One search-index column holds the email token; phone (not searchable) has none.
	var idx map[string]string
	if err := json.Unmarshal(rec["__cs_idx"].(json.RawMessage), &idx); err != nil {
		t.Fatalf("__cs_idx: %v", err)
	}
	if idx["email"] == "" {
		t.Fatal("__cs_idx missing email token")
	}
	if _, ok := idx["phone"]; ok {
		t.Fatal("phone must not be in __cs_idx")
	}
	_, tok, err := cd.SearchToken(ctx, "directory.users", "email", "ann@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if tok != idx["email"] {
		t.Fatalf("search token mismatch: query %s stored %s", tok, idx["email"])
	}
	// JSON attribute encrypted in place, document shape preserved.
	var doc map[string]any
	json.Unmarshal(rec["profile"].([]byte), &doc)
	if doc["name"] != "Ann" || doc["ssn"] == "123-45-6789" {
		t.Fatalf("json attr not encrypted as expected: %#v", doc)
	}
	// Searchable json attribute is indexed under "<field>.<dot-path>"; the
	// non-searchable passport attribute is not.
	if idx["profile.ssn"] == "" {
		t.Fatal("__cs_idx missing profile.ssn token")
	}
	if _, ok := idx["profile.passport.number"]; ok {
		t.Fatal("non-searchable json attr must not be in __cs_idx")
	}
	jkey, jtok, err := cd.SearchToken(ctx, "directory.users", "profile", "123-45-6789", "ssn")
	if err != nil {
		t.Fatal(err)
	}
	if jkey != "profile.ssn" {
		t.Fatalf("json search key = %q, want profile.ssn", jkey)
	}
	if jtok != idx["profile.ssn"] {
		t.Fatalf("json search token mismatch: query %s stored %s", jtok, idx["profile.ssn"])
	}

	if err := cd.DecodeRecords(ctx, "directory.users", []schema.Record{rec}); err != nil {
		t.Fatalf("DecodeRecords: %v", err)
	}
	if string(rec["email"].([]byte)) != "ann@example.com" {
		t.Fatalf("email round-trip: %q", rec["email"])
	}
	if string(rec["phone"].([]byte)) != "+15551234567" {
		t.Fatalf("phone round-trip: %q", rec["phone"])
	}
	json.Unmarshal(rec["profile"].([]byte), &doc)
	if doc["ssn"] != "123-45-6789" || doc["passport"].(map[string]any)["number"] != "AB1234567" {
		t.Fatalf("json round-trip: %#v", doc)
	}
}

func TestLegacyPlaintextPassthrough(t *testing.T) {
	ctx := context.Background()
	cd := newCodec(t, "correct-horse-battery-staple-001!")
	rec := schema.Record{"email": []byte("legacy@old.example")}
	if err := cd.DecodeRecords(ctx, "directory.users", []schema.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec["email"].([]byte), []byte("legacy@old.example")) {
		t.Fatalf("legacy plaintext not passed through: %q", rec["email"])
	}
}

func TestIdempotentEncode(t *testing.T) {
	ctx := context.Background()
	cd := newCodec(t, "correct-horse-battery-staple-001!")
	rec := schema.Record{"email": "ann@example.com"}
	_ = cd.EncodeRecords(ctx, "directory.users", []schema.Record{rec})
	first := append([]byte(nil), rec["email"].([]byte)...)
	_ = cd.EncodeRecords(ctx, "directory.users", []schema.Record{rec})
	if !bytes.Equal(rec["email"].([]byte), first) {
		t.Fatal("second EncodeRecords re-framed an already-encrypted value")
	}
	if err := cd.DecodeRecords(ctx, "directory.users", []schema.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if string(rec["email"].([]byte)) != "ann@example.com" {
		t.Fatalf("idempotent round-trip: %q", rec["email"])
	}
}

func TestUnmanagedUnitNoop(t *testing.T) {
	ctx := context.Background()
	cd := newCodec(t, "correct-horse-battery-staple-001!")
	rec := schema.Record{"x": "plain"}
	if err := cd.EncodeRecords(ctx, "other.unit", []schema.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if rec["x"] != "plain" {
		t.Fatalf("unmanaged unit mutated: %#v", rec["x"])
	}
}

// TestUnitCodecFlow exercises the dynamic per-flow path: the engine builds a Unit
// for a single process-state column, where the variables to encrypt live under the
// nested "$.variables.<name>" attribute, and creates a UnitCodec on the fly.
func TestUnitCodecFlow(t *testing.T) {
	ctx := context.Background()
	ring, _ := cryptobox.ParseKeyring("correct-horse-battery-staple-001!")
	cr, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), mustParseRing(t, indexRoot))
	if err != nil {
		t.Fatal(err)
	}

	// A flow's encryption config: encrypt the "phone" variable (searchable) and the
	// "my_var" variable (no search), inside the state column's "variables" object.
	unit := &schema.Unit{Fields: map[string]*schema.FieldPolicy{
		"state": {Nested: []schema.FieldNested{
			{Path: []string{"$.variables.phone"}, Search: true},
			{Path: []string{"$.variables.my_var"}},
		}},
	}}
	uc, err := schema.NewUnitCodec(cr, "flow.process_state", unit)
	if err != nil {
		t.Fatalf("NewUnitCodec: %v", err)
	}

	rec := schema.Record{
		"id":    42,
		"state": json.RawMessage(`{"step":3,"variables":{"phone":"123456","my_var":"secret","keep":"plain"}}`),
	}
	if err := uc.EncodeRecords(ctx, []schema.Record{rec}); err != nil {
		t.Fatalf("EncodeRecords: %v", err)
	}

	var doc map[string]any
	json.Unmarshal(rec["state"].([]byte), &doc)
	vars := doc["variables"].(map[string]any)
	if vars["phone"] == "123456" || vars["my_var"] == "secret" {
		t.Fatalf("flow variables not encrypted: %#v", vars)
	}
	if vars["keep"] != "plain" || doc["step"].(float64) != 3 {
		t.Fatalf("non-configured state mutated: %#v", doc)
	}
	// Searchable variable token lands in __cs_idx under "state.variables.phone".
	var idx map[string]string
	json.Unmarshal(rec[schema.IndexField].(json.RawMessage), &idx)
	if idx["state.variables.phone"] == "" {
		t.Fatal("__cs_idx missing state.variables.phone token")
	}
	if _, ok := idx["state.variables.my_var"]; ok {
		t.Fatal("non-searchable flow var must not be indexed")
	}
	_, tok, err := uc.SearchToken(ctx, "state", "123456", "variables", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if tok != idx["state.variables.phone"] {
		t.Fatalf("flow search token mismatch: %s vs %s", tok, idx["state.variables.phone"])
	}

	if err := uc.DecodeRecords(ctx, []schema.Record{rec}); err != nil {
		t.Fatalf("DecodeRecords: %v", err)
	}
	json.Unmarshal(rec["state"].([]byte), &doc)
	vars = doc["variables"].(map[string]any)
	if vars["phone"] != "123456" || vars["my_var"] != "secret" || vars["keep"] != "plain" {
		t.Fatalf("flow round-trip: %#v", vars)
	}
}

// TestUnitCodecValidates rejects an invalid dynamically-built unit.
func TestUnitCodecValidates(t *testing.T) {
	ring, _ := cryptobox.ParseKeyring("correct-horse-battery-staple-001!")
	cr, _ := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), mustParseRing(t, indexRoot))
	bad := &schema.Unit{Fields: map[string]*schema.FieldPolicy{
		"state": {Search: true, Nested: []schema.FieldNested{{Path: []string{"$.x"}}}},
	}}
	if _, err := schema.NewUnitCodec(cr, "u", bad); err == nil {
		t.Fatal("expected error: scalar search on a json field")
	}
}

// TestFieldNestedForms checks the polymorphic FieldNested unmarshaler and the
// "$"-prefix rule: a bare string, an object with a "$"-prefixed shorthand path, and
// an object with a literal dotted-key segment.
func TestFieldNestedForms(t *testing.T) {
	s, err := schema.ParseConfig([]byte(`{"version":1,"units":{"u":{"fields":{
	  "doc": {"nested": ["$.a", {"path":["$.b"],"search":true}, {"path":["oauth2.refresh_token"],"search":true}]}
	}}}}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	attrs := s.Unit("u").Field("doc").Nested
	if len(attrs) != 3 {
		t.Fatalf("want 3 attrs, got %d", len(attrs))
	}
	// bare string → single "$"-prefixed element, split on read
	if segs, _ := attrs[0].Segments(); len(segs) != 1 || segs[0] != "a" || attrs[0].Search {
		t.Fatalf("string form: %#v", attrs[0])
	}
	// object with a "$"-prefixed shorthand path
	if segs, _ := attrs[1].Segments(); len(segs) != 1 || segs[0] != "b" || !attrs[1].Search {
		t.Fatalf("dot-path object form: %#v", attrs[1])
	}
	// literal-segment form: a single key that itself contains a dot (no "$" → verbatim)
	segs, err := attrs[2].Segments()
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	if len(segs) != 1 || segs[0] != "oauth2.refresh_token" || !attrs[2].Search {
		t.Fatalf("literal form: %#v segs=%v", attrs[2], segs)
	}
}

// TestJSONDottedKey covers a JSON object whose key name literally contains a dot
// ({"oauth2.refresh_token": ...}). A literal-segment Path (no "$" prefix) must target
// that literal key — not descend into a nested oauth2 → refresh_token path — and its
// index slot must not collide with the nested path's.
func TestJSONDottedKey(t *testing.T) {
	ctx := context.Background()
	ring := mustParseRing(t, "correct-horse-battery-staple-001!")
	cr, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), mustParseRing(t, indexRoot))
	if err != nil {
		t.Fatal(err)
	}
	s, err := schema.ParseConfig([]byte(`{"version":1,"units":{"oauth.tokens":{"fields":{
	  "data": {"nested": [{"path":["oauth2.refresh_token"],"search":true}]}
	}}}}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cd, err := schema.NewCodec(schema.WithBase(cr), schema.WithBaseline(s))
	if err != nil {
		t.Fatal(err)
	}

	// The doc has BOTH a literal dotted key and a nested oauth2 object: only the
	// literal key must be encrypted/indexed.
	rec := schema.Record{
		"id":   1,
		"data": json.RawMessage(`{"oauth2.refresh_token":"qwerty","oauth2":{"refresh_token":"nested-plain"}}`),
	}
	if err := cd.EncodeRecords(ctx, "oauth.tokens", []schema.Record{rec}); err != nil {
		t.Fatalf("EncodeRecords: %v", err)
	}

	var doc map[string]any
	json.Unmarshal(rec["data"].([]byte), &doc)
	if doc["oauth2.refresh_token"] == "qwerty" {
		t.Fatalf("literal dotted key not encrypted: %#v", doc["oauth2.refresh_token"])
	}
	if nested := doc["oauth2"].(map[string]any); nested["refresh_token"] != "nested-plain" {
		t.Fatalf("nested oauth2.refresh_token must be untouched: %#v", nested)
	}

	// Index slot uses the escaped key; it must not collide with the nested path.
	var idx map[string]string
	json.Unmarshal(rec[schema.IndexField].(json.RawMessage), &idx)
	if idx[`data.oauth2\.refresh_token`] == "" {
		t.Fatalf("missing escaped index slot; idx=%v", idx)
	}
	if _, ok := idx["data.oauth2.refresh_token"]; ok {
		t.Fatal("escaped key collided with the nested-path slot")
	}

	// Query round-trip: the token and key match what was stored.
	key, tok, err := cd.SearchToken(ctx, "oauth.tokens", "data", "qwerty", "oauth2.refresh_token")
	if err != nil {
		t.Fatal(err)
	}
	if key != `data.oauth2\.refresh_token` {
		t.Fatalf("search key = %q, want escaped form", key)
	}
	if tok != idx[key] {
		t.Fatalf("token mismatch: query %s stored %s", tok, idx[key])
	}

	if err := cd.DecodeRecords(ctx, "oauth.tokens", []schema.Record{rec}); err != nil {
		t.Fatalf("DecodeRecords: %v", err)
	}
	json.Unmarshal(rec["data"].([]byte), &doc)
	if doc["oauth2.refresh_token"] != "qwerty" {
		t.Fatalf("dotted key round-trip: %#v", doc["oauth2.refresh_token"])
	}
}

func TestConfigMergeBaseline(t *testing.T) {
	base, _ := schema.ParseConfig([]byte(`{"version":1,"units":{"u":{"fields":{"a":{"search":true}}}}}`))
	overlay, _ := schema.ParseConfig([]byte(`{"version":1,"units":{"u":{"fields":{"a":{},"b":{}}}}}`))
	merged := schema.MergeConfig(base, overlay)
	if p := merged.Unit("u").Field("a"); p == nil || !p.Search {
		t.Fatal("baseline search flag must survive overlay")
	}
	if merged.Unit("u").Field("b") == nil {
		t.Fatal("overlay field b must be added")
	}
}

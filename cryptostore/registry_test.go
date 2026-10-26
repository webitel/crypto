package cryptostore

import (
	"context"
	"testing"
)

// TestSchemaless confirms the driver-declared record/schemaless capability: Register
// marks a scheme record-oriented (Schemaless == false), RegisterSchemaless marks it
// schemaless (true), and an unregistered scheme reports false — the fail-closed default
// an agent relies on to still apply a field-schema baseline to schemes it doesn't know.
func TestSchemaless(t *testing.T) {
	nop := func(context.Context, StoreOptions) (Store, error) { return nil, nil }
	Register("test-record", nop)
	RegisterSchemaless("test-blob", nop)

	if Schemaless("test-record") {
		t.Error("Register should mark the scheme record-oriented (Schemaless == false)")
	}
	if !Schemaless("test-blob") {
		t.Error("RegisterSchemaless should mark the scheme schemaless (Schemaless == true)")
	}
	if Schemaless("test-unregistered") {
		t.Error("unknown scheme must report Schemaless == false (fail-closed)")
	}
}

// Test_getScheme exercises the DSN scheme splitter (adapted from net/url.getScheme):
// a scheme must start with a letter and contain only [a-zA-Z0-9+.-]; the ":" ends it
// and everything after is the driver's opaque remainder. Our one adaptation: a string
// with NO ":" is a stand-alone scheme with an empty opaque (bare "postgres"), where
// net/url would report no scheme at all.
func Test_getScheme(t *testing.T) {
	tests := []struct {
		name       string
		rawDSN     string
		wantScheme string
		wantOpaque string
		wantErr    bool
	}{
		// bare scheme, no opaque (our adaptation of net/url's no-colon case)
		{name: "bare", rawDSN: "postgres", wantScheme: "postgres", wantOpaque: ""},
		{name: "bare short", rawDSN: "s3", wantScheme: "s3", wantOpaque: ""},

		// scheme + opaque in each transport shape we register
		{name: "empty opaque", rawDSN: "postgres:", wantScheme: "postgres", wantOpaque: ""},
		{name: "keyword opaque", rawDSN: "postgres:host=example.org port=5432", wantScheme: "postgres", wantOpaque: "host=example.org port=5432"},
		{name: "url opaque", rawDSN: "postgres://user:pass@host:5432/db", wantScheme: "postgres", wantOpaque: "//user:pass@host:5432/db"},
		{name: "path opaque", rawDSN: "blobfs:/var/lib/cryptoctl/blobs", wantScheme: "blobfs", wantOpaque: "/var/lib/cryptoctl/blobs"},
		{name: "bucket opaque", rawDSN: "s3://my-bucket", wantScheme: "s3", wantOpaque: "//my-bucket"},

		// legal scheme punctuation ([+.-] allowed after the first letter)
		{name: "scheme with plus", rawDSN: "s3+v4://b", wantScheme: "s3+v4", wantOpaque: "//b"},
		{name: "scheme with dot", rawDSN: "a.b:c", wantScheme: "a.b", wantOpaque: "c"},

		// the opaque may itself contain ":" — only the FIRST colon splits
		{name: "colon in opaque", rawDSN: "postgres://u:p@h/db", wantScheme: "postgres", wantOpaque: "//u:p@h/db"},

		// not a valid scheme → no scheme, whole string is the (opaque) remainder
		{name: "leading digit", rawDSN: "123:x", wantScheme: "", wantOpaque: "123:x"},
		{name: "leading plus", rawDSN: "+abc:x", wantScheme: "", wantOpaque: "+abc:x"},
		{name: "invalid char before colon", rawDSN: "a b:c", wantScheme: "", wantOpaque: "a b:c"},
		{name: "no colon, invalid char", rawDSN: "a/b", wantScheme: "", wantOpaque: "a/b"},
		{name: "empty", rawDSN: "", wantScheme: "", wantOpaque: ""},

		// leading colon is the only error: a colon with no scheme in front
		{name: "leading colon", rawDSN: ":opaque", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScheme, gotOpaque, gotErr := getScheme(tt.rawDSN)
			if gotErr != nil {
				if !tt.wantErr {
					t.Fatalf("getScheme(%q) failed: %v", tt.rawDSN, gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatalf("getScheme(%q) = (%q, %q), want error", tt.rawDSN, gotScheme, gotOpaque)
			}
			if gotScheme != tt.wantScheme {
				t.Errorf("getScheme(%q) scheme = %q, want %q", tt.rawDSN, gotScheme, tt.wantScheme)
			}
			if gotOpaque != tt.wantOpaque {
				t.Errorf("getScheme(%q) opaque = %q, want %q", tt.rawDSN, gotOpaque, tt.wantOpaque)
			}
		})
	}
}

// TestScheme confirms the exported Scheme wrapper: it returns getScheme's scheme and
// swallows the opaque/error, so an invalid or empty DSN yields "" (→ unknown-scheme
// error at OpenStore), and a bare/opaque DSN yields the scheme.
func TestScheme(t *testing.T) {
	cases := map[string]string{
		"postgres":          "postgres",
		"postgres:":         "postgres",
		"postgres://h/db":   "postgres",
		"blobfs:/var/lib/x": "blobfs",
		"s3://bucket":       "s3",
		"123:x":             "", // invalid scheme → ""
		":opaque":           "", // leading-colon error swallowed → ""
		"":                  "",
	}
	for dsn, want := range cases {
		if got := Scheme(dsn); got != want {
			t.Errorf("Scheme(%q) = %q, want %q", dsn, got, want)
		}
	}
}

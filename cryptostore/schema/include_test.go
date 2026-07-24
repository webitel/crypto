package schema_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptostore/schema"
)

func TestIncludeConfig(test *testing.T) {

	config := struct {
		Schema schema.IncludeConfig `json:"schema,omitempty"`
	}{}

	source := []byte(
		`{ "schema": { "dir": "" } }`,
	)

	err := json.Unmarshal(source, &config)
	if err != nil {
		test.Error(err)
	}

	sh, err := config.Schema.Config("../../../.crypto")
	if err != nil {
		test.Error(err)
	}

	_ = sh
}

func decodeInclude(t *testing.T, raw string) schema.IncludeConfig {
	t.Helper()
	var inc schema.IncludeConfig
	if err := json.Unmarshal([]byte(raw), &inc); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return inc
}

func TestIncludeEmpty(t *testing.T) {
	for _, raw := range []string{`null`, `{}`} {
		inc := decodeInclude(t, raw)
		got, err := inc.Config(".")
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got != nil {
			t.Fatalf("%s: want nil config, got %+v", raw, got)
		}
	}
}

func TestIncludeInline(t *testing.T) {
	inc := decodeInclude(t, `{"version":1,"units":{"a.b":{"fields":{"x":{}}}}}`)
	got, err := inc.Config(".")
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got.Unit("a.b").Field("x") == nil {
		t.Fatal("inline schema.Config not parsed")
	}
}

func TestIncludeFilesRequired(t *testing.T) {
	// A non-empty dir without files is an error (files are required in include mode).
	var inc schema.IncludeConfig
	if err := json.Unmarshal([]byte(`{"dir":"schemas"}`), &inc); err == nil {
		t.Fatal("expected error: files required in include mode")
	}
}

func TestIncludeMerge(t *testing.T) {
	dir := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("directory.jsonc", `{"version":1,"units":{"directory.users":{"fields":{"email":{"search":true}}}}}`)
	must("call_center.jsonc", `{"version":1,"units":{"call_center.agents":{"fields":{"phone":{}}}}}`)

	inc := decodeInclude(t, `{"dir":"`+dir+`","files":["directory.jsonc","call_center.jsonc"]}`)
	got, err := inc.Config(".")
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got.Unit("directory.users") == nil || got.Unit("call_center.agents") == nil {
		t.Fatalf("merge missing units: %+v", got.Units)
	}
}

func TestIncludeDefaultDir(t *testing.T) {
	wd := t.TempDir()
	sd := filepath.Join(wd, "schema.d")
	if err := os.Mkdir(sd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sd, "u.jsonc"),
		[]byte(`{"version":1,"units":{"s.t":{"fields":{"c":{}}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// No dir → defaults to schema.d relative to wd.
	inc := decodeInclude(t, `{"files":["u.jsonc"]}`)
	got, err := inc.Config(wd)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got.Unit("s.t") == nil {
		t.Fatal("default schema.d not used")
	}
}

func TestBaselinePinned(t *testing.T) {
	// Baseline is the pinned minimum; an overlay may add but never relax it.
	base := schema.MustParseConfig(`{"version":1,"units":{"a.b":{"fields":{"secret":{"search":true}}}}}`)
	overlay := schema.MustParseConfig(`{"version":1,"units":{"a.b":{"fields":{"secret":{}}},"c.d":{"fields":{"x":{}}}}}`)
	merged := schema.MergeConfig(base, overlay)
	if p := merged.Unit("a.b").Field("secret"); p == nil || !p.Search {
		t.Fatal("baseline search flag relaxed by overlay")
	}
	if merged.Unit("c.d").Field("x") == nil {
		t.Fatal("overlay unit not added")
	}
}

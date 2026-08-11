package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLoadStoresDir: every *.json/*.jsonc in store-dir becomes a store; names default to
// the file stem; non-config files are skipped; each store carries its file's directory.
func TestLoadStoresDir(t *testing.T) {
	sd := t.TempDir()
	write(t, filepath.Join(sd, "directory.json"), `{"dsn":"postgres:"}`)
	write(t, filepath.Join(sd, "recordings.jsonc"), `{"dsn":"blobfs:/srv/rec"} // comment ok`)
	write(t, filepath.Join(sd, "notes.txt"), `ignored`) // non-config extension skipped

	stores, err := loadStores(sd, "", nil)
	if err != nil {
		t.Fatalf("loadStores: %v", err)
	}
	got := map[string]string{}
	for _, s := range stores {
		got[s.Name] = cryptostore.Scheme(s.DSN)
		if s.BaseDir != sd {
			t.Errorf("store %q: BaseDir = %q, want %q", s.Name, s.BaseDir, sd)
		}
	}
	want := map[string]string{"directory": "postgres", "recordings": "blobfs"}
	if len(got) != len(want) {
		t.Fatalf("stores: got %v want %v", got, want)
	}
	for n, k := range want {
		if got[n] != k {
			t.Fatalf("store %q: scheme %q, want %q", n, got[n], k)
		}
	}
}

// TestLoadStoresFilter: --store selects specific files in store-dir (with or without
// extension), leaving the rest unloaded; a missing selection is an error.
func TestLoadStoresFilter(t *testing.T) {
	sd := t.TempDir()
	write(t, filepath.Join(sd, "directory.jsonc"), `{"dsn":"postgres:"}`)
	write(t, filepath.Join(sd, "call_center.jsonc"), `{"dsn":"postgres:"}`)
	write(t, filepath.Join(sd, "workflow.jsonc"), `{"dsn":"postgres:"}`)

	stores, err := loadStores(sd, "", []string{"directory", "call_center.jsonc"})
	if err != nil {
		t.Fatalf("loadStores: %v", err)
	}
	if len(stores) != 2 {
		t.Fatalf("stores = %d, want 2 (workflow excluded)", len(stores))
	}
	for _, s := range stores {
		if s.Name == "workflow" {
			t.Fatal("workflow should be excluded by --store filter")
		}
	}

	if _, err := loadStores(sd, "", []string{"nope"}); err == nil {
		t.Fatal("expected error for missing --store file")
	}
}

// TestLoadStoresSchemaMerge: a store's include {files} with no dir resolves against the
// shared --schema-dir, merging several service schema files into one.
func TestLoadStoresSchemaMerge(t *testing.T) {
	root := t.TempDir()
	sd := filepath.Join(root, "store.d")
	if err := os.Mkdir(sd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(sd, "pg.jsonc"), `{"dsn":"postgres:","schema":{"files":["directory.jsonc","call_center.jsonc"]}}`)

	scd := filepath.Join(root, "schema.d")
	if err := os.Mkdir(scd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(scd, "directory.jsonc"), `{"version":1,"units":{"directory.users":{"fields":{"email":{"search":true}}}}}`)
	write(t, filepath.Join(scd, "call_center.jsonc"), `{"version":1,"units":{"call_center.agents":{"fields":{"phone":{}}}}}`)

	stores, err := loadStores(sd, scd, nil)
	if err != nil {
		t.Fatalf("loadStores: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("stores = %d, want 1", len(stores))
	}
	merged, err := schema.ParseConfig(stores[0].Schema)
	if err != nil {
		t.Fatalf("merged schema does not parse: %v", err)
	}
	for _, unit := range []string{"directory.users", "call_center.agents"} {
		if merged.Unit(unit) == nil {
			t.Errorf("merged schema missing unit %q", unit)
		}
	}
}

// TestLoadStoresSchemaEmpty: null, {}, and an absent schema section all yield no schema.
// TestLoadStoresSchemaBaseline: with no explicit schema, the compiled-in baseline
// (registered by the imported plugin's init) is merged into record-oriented stores
// (postgres) but never into schemaless stores (blobfs) — see resolveSchema/recordOriented.
func TestLoadStoresSchemaBaseline(t *testing.T) {
	sd := t.TempDir()
	write(t, filepath.Join(sd, "a.json"), `{"dsn":"postgres:","name":"a","schema":null}`)
	write(t, filepath.Join(sd, "b.json"), `{"dsn":"postgres:","name":"b","schema":{}}`)
	write(t, filepath.Join(sd, "c.json"), `{"dsn":"blobfs:/x","name":"c"}`)

	stores, err := loadStores(sd, "", nil)
	if err != nil {
		t.Fatalf("loadStores: %v", err)
	}

	// want is the marshaled baseline the record-oriented stores should carry ("" if none
	// is registered, which also makes this test pass in a build without the plugin).
	want := ""
	if base := schema.Baseline(); base != nil {
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		want = string(raw)
	}
	byName := map[string]string{}
	for _, sc := range stores {
		byName[sc.Name] = string(sc.Schema)
	}
	if byName["a"] != want {
		t.Errorf("store %q (postgres): schema = %s, want baseline %s", "a", byName["a"], want)
	}
	if byName["b"] != want {
		t.Errorf("store %q (postgres): schema = %s, want baseline %s", "b", byName["b"], want)
	}
	if byName["c"] != "" {
		t.Errorf("store %q (blobfs): schema = %s, want empty (baseline not merged into schemaless store)", "c", byName["c"])
	}
}

// TestLoadStoresDuplicateName: two stores resolving to the same name is an error.
func TestLoadStoresDuplicateName(t *testing.T) {
	sd := t.TempDir()
	write(t, filepath.Join(sd, "a.json"), `{"dsn":"postgres:","name":"dup"}`)
	write(t, filepath.Join(sd, "b.json"), `{"dsn":"blobfs:/x","name":"dup"}`)
	if _, err := loadStores(sd, "", nil); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}

// TestResolveDir: a bare name resolves under the CWD (the first well-known base); a
// relative spec matching nowhere is ""; an absolute spec is returned verbatim.
func TestResolveDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "store.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir) // CWD is the first well-known base

	got := resolveDir("store.d")
	if got == "" || filepath.Base(got) != "store.d" {
		t.Fatalf("resolveDir(store.d) = %q, want a .../store.d under CWD", got)
	}
	if resolveDir("nope.d") != "" {
		t.Fatal("resolveDir returned a path for a missing relative dir")
	}
	abs := filepath.Join(dir, "store.d")
	if resolveDir(abs) != abs {
		t.Fatalf("resolveDir(abs) = %q, want %q", resolveDir(abs), abs)
	}
}

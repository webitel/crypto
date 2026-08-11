package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
	"github.com/webitel/crypto/encoding/jsonc"
)

// StoreConfig is one managed store: a data source name, a name, the impl-specific
// config, and (for record-oriented stores) the field schema. cryptoctl has no other
// configuration — keys come from the environment via cryptostore.Default (see open.go),
// so the whole config reduces to the set of stores. Each store is one JSON/JSONC file
// (loadStores); the DSN scheme selects the registered driver, and the opaque remainder,
// Config and Schema are passed verbatim to cryptostore.OpenStore.
type StoreConfig struct {
	DSN    string          `json:"dsn"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config,omitempty"`
	Schema json.RawMessage `json:"schema,omitempty"`

	// BaseDir is the directory of the file this store was loaded from (loader-set, not
	// decoded); it becomes StoreOptions.BaseDir so relative driver paths resolve against
	// the config file, not the process CWD.
	BaseDir string `json:"-"`
}

// storeFileExts are the recognized per-store config file extensions in a store-dir.
var storeFileExts = map[string]bool{".json": true, ".jsonc": true}

// loadStores discovers the managed stores. Each store is one JSON/JSONC file in storeDir.
// When only is empty, every *.json/*.jsonc file there is loaded; otherwise only the named
// ones are — each resolved with resolveStoreFile (a bare name looked up in storeDir, a
// path taken verbatim). schemaDir is the shared base for record stores' schema includes
// ({files} with no explicit dir). Store names must be unique; an empty name defaults to
// the file stem.
func loadStores(storeDir, schemaDir string, only []string) ([]StoreConfig, error) {
	var files []string
	if len(only) > 0 {
		for _, name := range only {
			p, err := resolveStoreFile(storeDir, name)
			if err != nil {
				return nil, err
			}
			files = append(files, p)
		}
	} else if storeDir != "" {
		fs, err := storeFilesIn(storeDir)
		if err != nil {
			return nil, err
		}
		files = fs
	}

	var stores []StoreConfig
	seen := map[string]string{} // store name → origin file, for collision detection
	for _, p := range files {
		sc, err := loadStoreConfigFile(p)
		if err != nil {
			return nil, err
		}
		if sc.Name == "" {
			sc.Name = nameFromPath(p)
		}
		if cryptostore.Scheme(sc.DSN) == "" {
			return nil, fmt.Errorf("%s: store %q has no dsn scheme", p, sc.Name)
		}
		if prev, dup := seen[sc.Name]; dup {
			return nil, fmt.Errorf("%s: duplicate store name %q (already from %s)", p, sc.Name, prev)
		}
		// The driver resolves relative filesystem paths (a blobfs directory, a sqlite
		// catalog) against the config file's directory, not the process CWD.
		sc.BaseDir = filepath.Dir(p)
		if err := resolveSchema(&sc, schemaDir); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		seen[sc.Name] = p
		stores = append(stores, sc)
	}
	return stores, nil
}

// loadStoreConfigFile reads a single StoreConfig from a JSON or JSONC file.
func loadStoreConfigFile(path string) (StoreConfig, error) {
	var sc StoreConfig
	if err := decodeFile(path, &sc); err != nil {
		return StoreConfig{}, fmt.Errorf("store config %s: %w", path, err)
	}
	return sc, nil
}

// decodeFile strictly decodes a JSONC file into as.
func decodeFile(path string, as any) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	return decodeStrict(fd, as)
}

// decodeStrict decodes JSONC from r into v, rejecting unknown fields and trailing content.
func decodeStrict(r io.Reader, v any) error {
	dec := jsonc.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing content")
	}
	return nil
}

// resolveStoreFile locates one --store selector. A name that is absolute or contains a
// path separator is used verbatim (an escape hatch outside storeDir); a bare name is
// looked up in storeDir, trying the name as given and then with .jsonc / .json appended.
func resolveStoreFile(storeDir, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty --store name")
	}
	if filepath.IsAbs(name) || strings.ContainsRune(name, filepath.Separator) {
		if _, err := os.Stat(name); err != nil {
			return "", fmt.Errorf("store %q: %w", name, err)
		}
		return name, nil
	}
	if storeDir == "" {
		return "", fmt.Errorf("store %q: no store dir (set --store-dir / WBTL_CRYPTO_STORE_DIR)", name)
	}
	cands := []string{name}
	if !storeFileExts[strings.ToLower(filepath.Ext(name))] {
		cands = append(cands, name+".jsonc", name+".json")
	}
	for _, c := range cands {
		p := filepath.Join(storeDir, c)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("store %q: not found in %s", name, storeDir)
}

// resolveSchema interprets the store's "schema" section (schema.IncludeConfig: inline
// schema.Config, an include directive {dir, files}, or empty), resolves it relative to
// the store file's directory, then merges the process-wide baseline (schema.Baseline)
// as the pinned base — so an ops build's unconditionally-encrypted fields can never be
// relaxed by the admin config. An include with files but no explicit dir uses schemaDir
// (the shared --schema-dir), so services' schema files can live in one place rather than
// beside each store file. The result is written back to sc.Schema (nil when it ends up
// with no schema).
func resolveSchema(sc *StoreConfig, schemaDir string) error {
	var inc schema.IncludeConfig
	if len(sc.Schema) > 0 {
		if err := json.Unmarshal(sc.Schema, &inc); err != nil {
			return fmt.Errorf("store %q schema: %w", sc.Name, err)
		}
	}
	if len(inc.Files) > 0 && inc.Dir == "" && schemaDir != "" {
		inc.Dir = schemaDir
	}
	overlay, err := inc.Config(sc.BaseDir)
	if err != nil {
		return fmt.Errorf("store %q schema: %w", sc.Name, err)
	}
	// The compiled-in baseline is a field schema — meaningful only for record-oriented
	// stores that encode fields and fill the search-index column. A schemaless store
	// (blob/object storage) ignores the field schema, so merging the baseline into it
	// only forces a search keyring it never uses; skip it there and honor just the
	// store's own overlay.
	merged := overlay
	if recordOriented(sc.DSN) {
		merged = schema.MergeConfig(schema.Baseline(), overlay)
	}
	if merged == nil {
		sc.Schema = nil // no schema (and no baseline)
		return nil
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	sc.Schema = raw
	return nil
}

// recordOriented reports whether a store's DSN scheme is record-oriented — i.e. its
// driver consumes a field schema and fills the search-index column, so the compiled-in
// baseline field schema applies. It defers entirely to the driver's own registration
// (cryptostore.Schemaless), so cryptoctl keeps no scheme list of its own; a schemaless
// (blob/object) driver returns false. Unknown schemes count as record-oriented
// (fail-closed) — they fail to open later regardless.
func recordOriented(dsn string) bool {
	return !cryptostore.Schemaless(cryptostore.Scheme(dsn))
}

// resolveDir resolves a --store-dir / --schema-dir spec to a path. An absolute spec is
// used verbatim; a relative spec (a bare "store.d" or a multi-segment path) is searched
// under the well-known bases — the working directory, the cryptoctl executable's
// directory, then the system dir (cryptostore.SystemDir) — and the first existing match
// wins. This is config, not secrets, so the CWD is allowed; key material is deliberately
// NOT discovered this way. Returns "" when a relative spec matches nowhere.
func resolveDir(spec string) string {
	if spec == "" {
		return ""
	}
	if filepath.IsAbs(spec) {
		return spec
	}
	var bases []string
	if wd, err := os.Getwd(); err == nil {
		bases = append(bases, wd)
	}
	if exe, err := os.Executable(); err == nil {
		bases = append(bases, filepath.Dir(exe))
	}
	bases = append(bases, cryptostore.SystemDir())

	seen := map[string]bool{}
	for _, b := range bases {
		if b == "" || seen[b] {
			continue // skip empties and the common CWD==exeDir case
		}
		seen[b] = true
		p := filepath.Join(b, spec)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	return ""
}

// storeFilesIn returns the sorted store-config files directly in dir.
func storeFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store dir %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if storeFileExts[strings.ToLower(filepath.Ext(e.Name()))] {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// nameFromPath derives a default store name from a file path: its base name minus
// extension (e.g. "/etc/store.d/recordings.jsonc" → "recordings").
func nameFromPath(path string) string {
	name := filepath.Base(path)
	return strings.TrimSuffix(name, filepath.Ext(name))
}

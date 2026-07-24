package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// defaultSchemaDir is the schema-include directory assumed when Dir is omitted,
// resolved relative to the config context (the store config file's directory).
const defaultSchemaDir = "schema.d"

// IncludeConfig is a store's "schema" section. It is one of:
//
//   - empty (JSON null or {}) — the store has no field schema;
//   - inline — a schema.Config document ({"version":1,"units":{…}}), kept in Raw;
//   - include — a directive {"dir":…,"files":[…]} naming schema.Config files to
//     load and merge. Files is required in include mode; Dir defaults to "schema.d",
//     relative to the config file context.
//
// Decode it from the raw section, then call Config to resolve it to a *Config.
type IncludeConfig includeConfig

type includeConfig struct {
	Raw   json.RawMessage `json:"-"`               // inline schema.Config source (config mode)
	Dir   string          `json:"dir,omitempty"`   // base dir for Files (default "schema.d")
	Files []string        `json:"files,omitempty"` // schema files to merge (required in include mode)
}

var _ json.Unmarshaler = (*IncludeConfig)(nil)

// UnmarshalJSON distinguishes the three forms. It first tries the include shape
// {dir, files} with unknown fields rejected: success (including null / {}) means
// include-or-empty; failure means the value is an inline schema.Config, kept raw.
func (c *IncludeConfig) UnmarshalJSON(data []byte) error {
	*c = IncludeConfig{}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode((*includeConfig)(c)); err != nil {
		// Unknown fields → this is an inline schema.Config document (config mode).
		*c = IncludeConfig{Raw: append([]byte(nil), data...)}
		return nil
	}

	// Include shape — also how null / {} decode (all fields empty).
	if len(c.Files) == 0 {
		if c.Dir != "" {
			return fmt.Errorf("schema: \"files\" is required in include mode (dir %q)", c.Dir)
		}
		return nil // null / {} → no schema
	}
	// Dir left as given (possibly ""); Config defaults an empty Dir to defaultIncludeDir.
	// A caller (e.g. the agent) may set an absolute Dir before Config to redirect it.
	return nil
}

// Config resolves the section into a *Config, or nil when the section is empty.
// wd is the config context base directory that anchors relative Dir/Files paths;
// absolute Dir/Files are used as-is. Config does not mutate the receiver.
func (c IncludeConfig) Config(wd string) (*Config, error) {
	if len(c.Raw) > 0 {
		return ParseConfig(c.Raw)
	}
	if len(c.Files) == 0 {
		return nil, nil // empty: no schema
	}

	dir := c.Dir
	if dir == "" {
		dir = defaultSchemaDir
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(wd, dir)
	}
	var merged *Config
	for _, name := range c.Files {
		if name == "" {
			return nil, fmt.Errorf("schema: empty file name in include list")
		}
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		part, err := LoadConfigFile(path)
		if err != nil {
			return nil, err
		}
		merged = MergeConfig(merged, part)
	}
	return merged, nil
}

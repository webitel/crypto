// Package schema is the field-oriented encryption layer: it encrypts named fields
// within records (a SQL row, a NoSQL document) according to a declarative Config,
// on top of the storage-agnostic cryptostore.Codec core.
//
// Ciphertext is stored in the field itself (self-marking — see cryptostore
// framing); the only companion is one per-unit search-index column holding blind
// index tokens. Record-oriented stores (cryptostore/postgres today, a document
// store later) reuse this layer.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/webitel/crypto/encoding/jsonc"
)

// Config declares which fields of which units are encrypted. A "unit" is a table
// (SQL) or collection (document); a "field" is a column or attribute. The schema
// is loaded from a JSON file kept separate from the data and may be hot-reloaded
// (see Codec.WatchConfig).
type Config struct {
	// Version is the schema version. Only version 1 is currently understood.
	Version int `json:"version"`

	// Units maps a fully-qualified unit name ("schema.table", "db.collection") to
	// its field policy.
	Units map[string]*Unit `json:"units"`
}

// Unit is the per-unit field policy.
type Unit struct {
	Fields map[string]*FieldPolicy `json:"fields"`
}

// FieldPolicy describes how a single field (or the nested attributes within it) is
// encrypted.
type FieldPolicy struct {
	// Search, when true, records a blind-index token for a scalar field in the
	// unit's search-index column, enabling exact-match lookups without exposing
	// the key. Only valid for scalar fields; for nested attributes use
	// FieldNested.Search.
	Search bool `json:"search,omitempty"`

	// Nested lists attributes to encrypt inside a document field (a json/jsonb
	// column today), each addressed by a path with an optional per-attribute search
	// flag. When set, only the named attributes are encrypted, leaving the document
	// shape intact. An entry accepts the shorthand string form ("$.ssn") or the
	// object form ({"path":["ssn"], "search":true}).
	Nested []FieldNested `json:"nested,omitempty"`
}

// FieldNested is one encrypted attribute within a document field: a path of object-key
// segments plus an optional blind-index search flag. It unmarshals from either a bare
// string (a "$.a.b" dot-path shorthand, encrypt only) or an object ({"path":[...],
// "search":true}).
type FieldNested struct {
	// Path is the object-key path to the attribute, as literal segments — a segment
	// may itself contain a dot (e.g. ["oauth2.refresh_token"]). As a convenience, a
	// single element that begins with "$" is parsed as a "$.a.b" dot-path shorthand
	// and split on dots (["$.a.b"] == ["a","b"]); every other form is taken verbatim,
	// so a dotted key name is expressed by giving it as its own segment.
	Path []string `json:"path,omitempty"`
	// Search, when true, records a blind-index token for this attribute in the
	// unit's search-index column under the key derived from the field and segments.
	Search bool `json:"search,omitempty"`
}

// Segments returns the attribute's canonical object-key segments. A single element
// beginning with "$" is the dot-path shorthand and is split ("$.a.b" → ["a","b"]);
// any other Path is taken as literal segments verbatim. Stores use it to build a
// json path expression for the migration predicate.
func (c FieldNested) Segments() ([]string, error) {
	if len(c.Path) == 1 && strings.HasPrefix(c.Path[0], "$") {
		return splitJSONPath(c.Path[0])
	}
	return validateSegments(c.Path)
}

// UnmarshalJSON accepts the shorthand string form ("$.a.b") or the object form
// ({"path":[...], "search":true}).
func (c *FieldNested) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		c.Path = []string{s}
		return nil
	}
	type raw FieldNested // avoid recursing into this method
	var r raw
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return err
	}
	*c = FieldNested(r)
	return nil
}

// Unit returns the policy for a fully-qualified unit name, or nil if unmanaged.
func (c *Config) Unit(name string) *Unit {
	if c == nil {
		return nil
	}
	return c.Units[name]
}

// Field returns the policy for a field, or nil if not managed.
func (c *Unit) Field(name string) *FieldPolicy {
	if c == nil {
		return nil
	}
	return c.Fields[name]
}

// HasNested reports whether the field encrypts nested attributes within a field value.
func (c *FieldPolicy) HasNested() bool { return c != nil && len(c.Nested) > 0 }

// HasSearchable reports whether the unit records any blind-index token (a scalar
// Search field or a nested attribute with Search), i.e. whether it needs a search
// keyring and uses the __cs_idx column.
func (c *Unit) HasSearchable() bool {
	if c == nil {
		return false
	}
	for _, p := range c.Fields {
		if p.Search {
			return true
		}
		for _, a := range p.Nested {
			if a.Search {
				return true
			}
		}
	}
	return false
}

// HasSearchable reports whether any unit has a searchable field — i.e. the schema
// requires a search keyring.
func (c *Config) HasSearchable() bool {
	if c == nil {
		return false
	}
	for _, u := range c.Units {
		if u.HasSearchable() {
			return true
		}
	}
	return false
}

// LoadConfigFile reads and validates a schema file from path.
func LoadConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cryptostore/schema: open schema: %w", err)
	}
	defer f.Close()
	return LoadConfig(f)
}

// LoadConfig reads and validates a schema from r.
func LoadConfig(r io.Reader) (*Config, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cryptostore/schema: read schema: %w", err)
	}
	return ParseConfig(raw)
}

// ParseConfig validates and normalizes a schema document. The input may be JSON or
// JSONC (comments and trailing commas are tolerated).
func ParseConfig(raw []byte) (*Config, error) {
	dec := jsonc.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Config
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("cryptostore/schema: parse schema: %w", err)
	}
	if err := s.normalize(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Config) normalize() error {
	if c.Version != 1 {
		return fmt.Errorf("cryptostore/schema: unsupported schema version %d (want 1)", c.Version)
	}
	for name, u := range c.Units {
		if err := u.validate(name); err != nil {
			return err
		}
	}
	return nil
}

// validate checks a unit's policies. It is run during schema normalization and by
// NewUnitCodec for dynamically-built units (e.g. per-flow variable configs).
func (c *Unit) validate(name string) error {
	if c == nil || len(c.Fields) == 0 {
		return fmt.Errorf("cryptostore/schema: unit %q has no fields", name)
	}
	for f, p := range c.Fields {
		if p == nil {
			return fmt.Errorf("cryptostore/schema: %s.%s has no policy", name, f)
		}
		if p.Search && p.HasNested() {
			return fmt.Errorf("cryptostore/schema: %s.%s: scalar search is invalid on a field with nested attributes (use per-attribute search)", name, f)
		}
		for _, a := range p.Nested {
			if _, err := a.Segments(); err != nil {
				return fmt.Errorf("cryptostore/schema: %s.%s: %w", name, f, err)
			}
		}
	}
	return nil
}

// MergeConfig overlays src onto a copy of base. Both must be normalized. The
// overlay may add units and fields but never relax the baseline: when a field
// exists in both, the baseline wins (Search and nested attributes are unioned,
// never dropped). Use it to pin an immutable minimum in code and let an external
// file extend it.
func MergeConfig(base, overlay *Config) *Config {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}
	out := &Config{Version: 1, Units: map[string]*Unit{}}
	for name, u := range base.Units {
		out.Units[name] = cloneUnit(u)
	}
	for name, ou := range overlay.Units {
		bu := out.Units[name]
		if bu == nil {
			out.Units[name] = cloneUnit(ou)
			continue
		}
		for f, op := range ou.Fields {
			if bp := bu.Fields[f]; bp != nil {
				bp.Search = bp.Search || op.Search
				bp.Nested = unionAttrs(bp.Nested, op.Nested)
				continue
			}
			p := *op
			p.Nested = append([]FieldNested(nil), op.Nested...)
			bu.Fields[f] = &p
		}
	}
	return out
}

func cloneUnit(u *Unit) *Unit {
	out := &Unit{Fields: make(map[string]*FieldPolicy, len(u.Fields))}
	for f, p := range u.Fields {
		c := *p
		c.Nested = append([]FieldNested(nil), p.Nested...)
		out.Fields[f] = &c
	}
	return out
}

// unionAttrs merges two nested-attribute lists by path, OR-ing the search flag so
// the baseline (or either side) never loses an encrypted-or-searchable attribute.
func unionAttrs(a, b []FieldNested) []FieldNested {
	idx := map[string]int{}
	var out []FieldNested
	for _, attr := range append(append([]FieldNested(nil), a...), b...) {
		id := attrID(attr)
		if i, ok := idx[id]; ok {
			out[i].Search = out[i].Search || attr.Search
			continue
		}
		idx[id] = len(out)
		out = append(out, attr)
	}
	sort.Slice(out, func(i, j int) bool { return attrID(out[i]) < attrID(out[j]) })
	return out
}

// attrID is a canonical, collision-free identity for a nested attribute, used to
// dedup and order attributes regardless of whether they were spelled as a dot-path
// shorthand or explicit literal segments. It mirrors the search-key encoding (dots
// inside a segment escaped), so two spellings of the same attribute share one identity.
func attrID(a FieldNested) string {
	segs, err := a.Segments()
	if err != nil {
		return strings.Join(a.Path, ".") // invalid attribute: fall back to the raw path
	}
	parts := make([]string, len(segs))
	for i, s := range segs {
		parts[i] = escSeg(s)
	}
	return strings.Join(parts, ".")
}

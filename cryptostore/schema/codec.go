package schema

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/webitel/crypto/cryptostore"
)

// IndexField is the single per-unit companion column holding blind-index tokens
// for every searchable field (a json object: search-key → base64url token). The key
// is the escaped join of the field name and, for a nested attribute, its object-key
// segments (a literal dot inside a segment is escaped, so it never collides with a
// nested path). Build both the key and token with (*Codec).SearchToken.
const IndexField = "__cs_idx"

// Record is a single record as a field→value map. For a SQL store it is a row;
// for a document store, a document. EncodeRecords/DecodeRecords mutate it in place.
type Record = map[string]any

// Codec is the field-oriented codec over a whole Config. It owns the base core
// and hands out a UnitCodec per unit (see Unit); its top-level EncodeRecords /
// DecodeRecords / SearchToken simply delegate to the addressed unit. Ciphertext is
// self-marking and stored in the field itself, so encrypted and legacy plaintext
// values coexist and migration is opportunistic. Search tokens for the whole unit
// go into one IndexField json column (GIN-indexed); key versions are read back
// from the ciphertext (no companion key-version column).
//
// The service routes its records through EncodeRecords/DecodeRecords and writes
// its own queries; which fields are encrypted comes entirely from the Config, so
// adding a field needs only a schema change plus a one-time migration. A Codec is
// safe for concurrent use; its schema may be hot-reloaded via WatchConfig.
type Codec struct {
	base     *cryptostore.Codec
	idxField string
	baseline *Config
	active   atomic.Pointer[Config]
}

// buildCodec assembles a Codec from a base core, a pinned baseline, and an initial
// overlay: active = MergeConfig(baseline, overlay). The baseline is retained so
// WatchConfig / SetBaseline re-merge later reloads onto it. NewCodec is the public
// entry point (see schema.go).
func buildCodec(base *cryptostore.Codec, baseline, overlay *Config) *Codec {
	c := &Codec{base: base, idxField: IndexField, baseline: baseline}
	c.setConfig(overlay)
	return c
}

// Base returns the underlying value codec (used by stores for migration).
func (c *Codec) Base() *cryptostore.Codec { return c.base }

// Schema returns the active schema configuration.
func (c *Codec) Schema() *Config { return c.active.Load() }

// IndexField returns the name of the per-unit search-index json column.
func (c *Codec) IndexField() string { return c.idxField }

// SetBaseline pins an immutable minimum schema merged onto every reload.
func (c *Codec) SetBaseline(base *Config) {
	c.baseline = base
	c.setConfig(c.active.Load())
}

func (c *Codec) setConfig(overlay *Config) {
	merged := MergeConfig(c.baseline, overlay)
	if merged == nil {
		merged = &Config{Version: 1} // never nil: Schema()/stores dereference it
	}
	c.active.Store(merged)
}

// Unit returns a UnitCodec for the named unit from the active schema, or nil if
// the unit is unmanaged. The returned codec is a snapshot of the current schema.
func (c *Codec) Unit(name string) *UnitCodec {
	u := c.Schema().Unit(name)
	if u == nil {
		return nil
	}
	return buildUnitCodec(c.base, name, u, c.idxField)
}

// EncodeRecords encrypts managed fields in place and fills the search-index column
// for the addressed unit. Unmanaged units are skipped. See UnitCodec.EncodeRecords.
func (c *Codec) EncodeRecords(ctx context.Context, unit string, rows []Record) error {
	uc := c.Unit(unit)
	if uc == nil {
		return nil
	}
	return uc.EncodeRecords(ctx, rows)
}

// DecodeRecords decrypts managed fields in place for the addressed unit.
func (c *Codec) DecodeRecords(ctx context.Context, unit string, rows []Record) error {
	uc := c.Unit(unit)
	if uc == nil {
		return nil
	}
	return uc.DecodeRecords(ctx, rows)
}

// SearchToken returns the base64url blind-index token for value and the IndexField
// key it is stored under. field is the field name; pass the json attribute's
// object-key segments as path (a segment may contain a dot), or no path for a
// scalar field. Build the exact-match query from the returned key and token, e.g.
// `WHERE __cs_idx @> jsonb_build_object($1::text, $2::text)` with $1 = key, $2 = token.
func (c *Codec) SearchToken(ctx context.Context, unit, field string, value any, path ...string) (key, token string, err error) {
	uc := c.Unit(unit)
	if uc == nil {
		return "", "", fmt.Errorf("%w: %s", ErrUnmanaged, unit)
	}
	return uc.SearchToken(ctx, field, value, path...)
}

// UnitCodec is the codec for a single unit (a SQL table, a document collection).
// It is the unit of work the stores operate on, and can be built directly from a
// *Unit with NewUnitCodec — used to encrypt a flow's variable dump under a config
// that lives next to the flow definition rather than in the central schema.
type UnitCodec struct {
	base       *cryptostore.Codec
	unit       string
	fields     map[string]*FieldPolicy
	idxField   string
	searchKeys map[string]bool // valid SearchToken keys (scalar fields + searchable nested attrs)
}

// NewUnitCodec builds a standalone codec for one unit from a (possibly
// dynamically-constructed) *Unit. The unit is validated like a schema unit.
func NewUnitCodec(base *cryptostore.Codec, name string, u *Unit) (*UnitCodec, error) {
	if err := u.validate(name); err != nil {
		return nil, err
	}
	return buildUnitCodec(base, name, u, IndexField), nil
}

// buildUnitCodec assumes u is already valid (schema-normalized or validated).
func buildUnitCodec(base *cryptostore.Codec, name string, u *Unit, idxField string) *UnitCodec {
	uc := &UnitCodec{
		base:       base,
		unit:       name,
		fields:     u.Fields,
		idxField:   idxField,
		searchKeys: map[string]bool{},
	}
	for f, p := range u.Fields {
		if p.HasNested() {
			for _, a := range p.Nested {
				if a.Search {
					if keys, err := a.Segments(); err == nil {
						uc.searchKeys[searchKey(f, keys)] = true
					}
				}
			}
			continue
		}
		if p.Search {
			uc.searchKeys[searchKey(f, nil)] = true
		}
	}
	return uc
}

// Unit returns the unit's fully-qualified name.
func (c *UnitCodec) Unit() string { return c.unit }

// IndexField returns the name of the search-index json column.
func (c *UnitCodec) IndexField() string { return c.idxField }

// EncodeRecords encrypts managed fields in place and fills the search-index column.
// A scalar field's value is replaced by a self-marking ciphertext (bytea framing);
// a document field has its configured attributes encrypted in place (text framing).
// Searchable scalar fields and nested attributes set IndexField to a json object of
// {key: base64urlToken}. Absent fields, NULL values and values already encrypted are
// skipped (idempotent).
func (c *UnitCodec) EncodeRecords(ctx context.Context, rows []Record) error {
	for i, rec := range rows {
		idx := map[string]string{}
		for f, p := range c.fields {
			v, ok := rec[f]
			if !ok || v == nil {
				continue
			}
			if p.HasNested() {
				enc, err := c.encryptJSON(ctx, f, p, v, idx)
				if err != nil {
					return fmt.Errorf("cryptostore/schema: encode %s.%s rec %d: %w", c.unit, f, i, err)
				}
				rec[f] = enc
				continue
			}
			b, err := toJsonBytes(v)
			if err != nil {
				return fmt.Errorf("cryptostore/schema: encode %s.%s rec %d: %w", c.unit, f, i, err)
			}
			if len(b) == 0 {
				continue // empty/NULL: nothing to encrypt or index (saves storage)
			}
			if _, framed := cryptostore.UnframeBinary(b); framed {
				continue // already encrypted
			}
			if p.Search {
				k := searchKey(f, nil)
				tok, err := c.base.SearchToken(ctx, domain(c.unit, k), b)
				if err != nil {
					return fmt.Errorf("cryptostore/schema: index %s.%s rec %d: %w", c.unit, f, i, err)
				}
				idx[k] = base64.RawURLEncoding.EncodeToString(tok)
			}
			out, err := c.base.Encrypt(ctx, b)
			if err != nil {
				return fmt.Errorf("cryptostore/schema: encrypt %s.%s rec %d: %w", c.unit, f, i, err)
			}
			rec[f] = out
		}
		if len(idx) > 0 {
			raw, err := json.Marshal(idx)
			if err != nil {
				return err
			}
			rec[c.idxField] = json.RawMessage(raw)
		}
	}
	return nil
}

// DecodeRecords decrypts managed fields in place. A scalar field is decrypted if
// it carries the ciphertext marker, else left as legacy plaintext. A document field
// has its tagged configured attributes decrypted (others left). The search-index
// column is left untouched.
func (c *UnitCodec) DecodeRecords(ctx context.Context, rows []Record) error {
	for i, rec := range rows {
		for f, p := range c.fields {
			v, ok := rec[f]
			if !ok || v == nil {
				continue
			}
			if p.HasNested() {
				dec, err := c.decryptJSON(ctx, p, v)
				if err != nil {
					return fmt.Errorf("cryptostore/schema: decode %s.%s rec %d: %w", c.unit, f, i, err)
				}
				rec[f] = dec
				continue
			}
			b, err := toJsonBytes(v)
			if err != nil {
				return fmt.Errorf("cryptostore/schema: decode %s.%s rec %d: %w", c.unit, f, i, err)
			}
			data, _, err := c.base.Decrypt(ctx, b)
			if err != nil {
				return fmt.Errorf("cryptostore/schema: decrypt %s.%s rec %d: %w", c.unit, f, i, err)
			}
			rec[f] = data
		}
	}
	return nil
}

// SearchToken returns the base64url blind-index token for value and the IndexField
// key it is stored under. field is the field name; path is the nested attribute's
// object-key segments (empty for a scalar field). The key matches what EncodeRecords
// writes into the search-index column.
func (c *UnitCodec) SearchToken(ctx context.Context, field string, value any, path ...string) (key, token string, err error) {
	key = searchKey(field, path)
	if !c.searchKeys[key] {
		return "", "", fmt.Errorf("%w: %s.%s", ErrNotSearchable, c.unit, key)
	}
	b, err := tokenInput(value)
	if err != nil {
		return "", "", err
	}
	tok, err := c.base.SearchToken(ctx, domain(c.unit, key), b)
	if err != nil {
		return "", "", err
	}
	return key, base64.RawURLEncoding.EncodeToString(tok), nil
}

// --- json attribute framing -----------------------------------------------------

func (c *UnitCodec) encryptJSON(ctx context.Context, field string, p *FieldPolicy, v any, idx map[string]string) ([]byte, error) {
	raw, err := toJsonBytes(v)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return raw, nil // <nil> -or- [0]byte
	}
	obj, err := toJsonObject(v)
	if err != nil {
		return nil, err
	}
	if len(obj) == 0 {
		// JObject has NO attributes
		return raw, nil // "{}" -or- "null"
	}
	for _, attr := range p.Nested {
		keys, err := attr.Segments()
		if err != nil {
			return nil, err
		}
		leaf, ok := jsonGet(obj, keys)
		if !ok || leaf == nil {
			continue // null
		}
		if s, isStr := leaf.(string); isStr {
			if s == "" {
				continue // empty attribute: nothing to encrypt or index
			}
			if _, framed := cryptostore.UnframeText(s); framed {
				continue // already encrypted
			}
		}
		if attr.Search {
			tb, err := tokenInput(leaf)
			if err != nil {
				return nil, err
			}
			tok, err := c.base.SearchToken(ctx, domain(c.unit, searchKey(field, keys)), tb)
			if err != nil {
				return nil, err
			}
			idx[searchKey(field, keys)] = base64.RawURLEncoding.EncodeToString(tok)
		}
		raw, err := json.Marshal(leaf)
		if err != nil {
			return nil, err
		}
		tagged, err := c.base.EncryptText(ctx, raw)
		if err != nil {
			return nil, err
		}
		jsonSet(obj, keys, tagged)
	}
	return json.Marshal(obj)
}

func (c *UnitCodec) decryptJSON(ctx context.Context, p *FieldPolicy, v any) ([]byte, error) {
	raw, err := toJsonBytes(v)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil // NULL
	}
	obj, err := toJsonObject(raw)
	if err != nil {
		return nil, err
	}
	if len(obj) == 0 {
		// JObject has NO attributes
		// preserve original [in/out]put
		return raw, nil // "{}" -or- "null"
	}
	for _, attr := range p.Nested {
		keys, err := attr.Segments()
		if err != nil {
			return nil, err
		}
		leaf, ok := jsonGet(obj, keys)
		if !ok {
			continue
		}
		s, isStr := leaf.(string)
		if !isStr {
			continue
		}
		data, encrypted, err := c.base.DecryptText(ctx, s)
		if err != nil || !encrypted {
			continue // not our ciphertext → leave as-is
		}
		var leafVal any
		if err := json.Unmarshal(data, &leafVal); err != nil {
			return nil, err
		}
		jsonSet(obj, keys, leafVal)
	}
	return json.Marshal(obj)
}

// --- keys & value coercion ------------------------------------------------------

// domain scopes a blind-index token to one search location.
func domain(unit, key string) string { return unit + "." + key }

// escSeg escapes the path delimiter inside a single segment so that joining
// segments with "." is injective: a literal dot in a key name can never be
// confused with a separator. Backslash is escaped first so the encoding is
// unambiguous. For a dot-free segment it is a no-op (the common case).
func escSeg(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, ".", `\.`)
}

// SearchKey returns the __cs_idx slot name for a field and optional nested-path
// segments. It matches the key the Codec writes into the search-index column.
// Use it together with (*cryptostore.Codec).SearchToken to compute lookup
// values without opening a store.
func SearchKey(field string, nested ...string) string { return searchKey(field, nested) }

// searchKey is the IndexField key (and blind-index domain suffix) for a field and
// its nested-attribute path. The field and each segment are escaped and joined with
// ".", so a key name containing a literal dot maps to a distinct slot from a nested
// path. Pass no keys for a scalar field.
func searchKey(field string, keys []string) string {
	var b strings.Builder
	b.WriteString(escSeg(field))
	for _, k := range keys {
		b.WriteByte('.')
		b.WriteString(escSeg(k))
	}
	return b.String()
}

// validateSegments checks an explicit key-segment list (FieldNested.Path): non-empty
// list, no empty segment. Segments are taken verbatim — a dot inside a segment is a
// literal key character, not a separator.
func validateSegments(keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: empty key list", ErrFieldPath)
	}
	for _, k := range keys {
		if k == "" {
			return nil, fmt.Errorf("%w: empty key segment", ErrFieldPath)
		}
	}
	return keys, nil
}

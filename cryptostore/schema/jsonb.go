package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/webitel/crypto/cryptostore"
)

// DecryptJSONB walks thru <jsonb> structure looking for encrypted values to be decrypted.
// Returns fully decrypted & valid JSON bytes or an error if any occurs.
func DecryptJSONB(base *cryptostore.Codec, jsonb []byte) ([]byte, error) {
	if len(jsonb) == 0 {
		return jsonb, nil // NULL
	}
	// Cast to JSON value
	var raw any
	err := json.Unmarshal(jsonb, &raw)
	if err != nil {
		// invalid JSON ?
		return jsonb, err
	}
	if raw == nil {
		// NULL ; <jsonb> preserves original value ; MABE "null"
		return jsonb, nil
	}
	var mod bool // decrypted ? modified ?
	raw, mod, err = decryptJSON(base, raw)
	if err != nil || !mod {
		// got an error ? none encrypted ?
		// <jsonb> preserves original value
		// MABE: "null" | {} | []
		return jsonb, err // ?
	}
	// backpack decrypted value(s)
	return json.Marshal(raw)
}

// walks down thru generic JSON <src> structure decrypting value(s)..
func decryptJSON(base *cryptostore.Codec, src any) (dst any, decrypted bool, err error) {
	// json.Unmarshal stores one of these in the interface value:
	//
	//   - bool, for JSON booleans
	//   - float64, for JSON numbers
	//   - string, for JSON strings
	//   - []any, for JSON arrays
	//   - map[string]any, for JSON objects
	//   - nil for JSON null
	//
	switch data := src.(type) {
	case map[string]any: // object
		{
			for att, val := range data {
				raw, mod, err := decryptJSON(base, val)
				if err != nil {
					return src, decrypted, err
				}
				if mod {
					data[att] = raw // rewrite / plain
					decrypted = true
				}
			}
			return data, decrypted, nil
		}
	case []any: // array
		{
			for num, val := range data {
				raw, mod, err := decryptJSON(base, val)
				if err != nil {
					return src, decrypted, err
				}
				if mod {
					data[num] = raw // rewrite / plain
					decrypted = true
				}
			}
			return data, decrypted, nil
		}
	case string: // string
		{
			jsonb, mod, err := base.DecryptText(
				context.Background(), data,
			)
			if err != nil || !mod {
				// unavailable cipher key used ?
				// not our ciphertext → leave as-is
				return data, mod, err // src || err
			}
			var raw any
			err = json.Unmarshal(jsonb, &raw)
			return raw, true, err
		}
	}
	// as-is: src, false, nil
	return src, decrypted, err
}

// tokenInput is the byte representation a value is tokenized under. Strings and
// byte slices are used verbatim (so a scalar column and the query agree); other
// json leaf values fall back to their canonical JSON encoding.
func tokenInput(v any) ([]byte, error) {
	switch t := v.(type) {
	case []byte:
		return t, nil
	case string:
		return []byte(t), nil
	case json.RawMessage:
		return t, nil
	default:
		return json.Marshal(v)
	}
}

func toJsonBytes(src any) ([]byte, error) {
	var raw json.RawMessage
	switch data := src.(type) {
	case []byte:
		raw = data
	case string:
		raw = []byte(data)
	case json.RawMessage:
		raw = data
	default:
		return nil, fmt.Errorf("%w: %T", ErrValueType, src)
	}
	// if len(raw) == 0 {
	// 	raw = nil
	// }
	return raw, nil
}

func toJsonObject(src any) (map[string]any, error) {
	raw, err := toJsonBytes(src)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil // NULL
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("cryptostore/schema: json field: %w", err)
	}
	return doc, nil
}

// splitJSONPath parses a "$.a.b" dot path into ["a","b"]. Only object keys are
// supported (no arrays or wildcards), which covers attribute-level encryption.
func splitJSONPath(path string) ([]string, error) {
	p := strings.TrimPrefix(path, "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return nil, fmt.Errorf("%w: %q", ErrFieldPath, path)
	}
	keys := strings.Split(p, ".")
	for _, k := range keys {
		if k == "" {
			return nil, fmt.Errorf("%w: %q", ErrFieldPath, path)
		}
	}
	return keys, nil
}

func jsonGet(obj map[string]any, path []string) (any, bool) {
	val := any(obj)
	for _, key := range path {
		obj, ok := val.(map[string]any)
		if !ok {
			return nil, false
		}
		val, ok = obj[key]
		if !ok {
			return nil, false
		}
	}
	return val, true
}

func jsonSet(obj map[string]any, path []string, val any) {
	cur := obj
	for _, key := range path[:len(path)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	cur[path[len(path)-1]] = val
}

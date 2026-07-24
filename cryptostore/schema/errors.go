package schema

import "errors"

var (
	// ErrNotSearchable is returned by SearchToken for a field that is managed but
	// not configured with "search": true.
	ErrNotSearchable = errors.New("cryptostore/schema: field is not searchable")

	// ErrUnmanaged is returned when SearchToken targets a unit or field the active
	// schema does not manage.
	ErrUnmanaged = errors.New("cryptostore/schema: unit or field is not managed")

	// ErrValueType is returned when a record value cannot be coerced to bytes for
	// encryption (or back) — e.g. a number where text/[]byte was expected.
	ErrValueType = errors.New("cryptostore/schema: unsupported value type")

	// ErrFieldPath signals a malformed nested-attribute path in a field schema.
	ErrFieldPath = errors.New("cryptostore/schema: invalid field path")
)

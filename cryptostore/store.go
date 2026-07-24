package cryptostore

import (
	"context"

	"github.com/webitel/crypto/cryptobox"
)

// FieldRef identifies one encrypted location ("schema.table"."column") within a
// store, for usage reporting and migration scoping.
type FieldRef struct {
	Table  string
	Column string
}

// KeyUsage is the count of encrypted values a store holds under one key version.
// It answers "what share of data sits under each key?" — the signal that drives
// migration planning and the "is this key safe to retire?" check.
type KeyUsage struct {
	KID   cryptobox.KID
	Count int64 // number of encrypted values sealed under this key
}

// Store is a physical backing store of encrypted data (a Postgres database, a
// blob bucket, …). It exposes only the two operations that need to enumerate
// stored ciphertext: per-key usage and key migration. The codec itself stays in
// the codec — a Store re-encrypts values through its schema.Codec (Decode → Encode).
//
// Implementations live in their own modules (cryptostore/postgres, …) because
// each carries its own driver dependencies.
type Store interface {
	// Name is a short identifier used in status output (e.g. "postgres:main").
	Name() string

	// Usage reports per-key counts across every field the store manages, grouped by
	// the key version recorded for each value.
	Usage(ctx context.Context) ([]KeyUsage, error)

	// Migrate re-encrypts values not yet under the primary key and reports
	// progress. It must be resumable (safe to call repeatedly until Remaining is
	// 0) and safe under concurrent writes: a value a natural write already moved
	// to the primary key must not be clobbered (guard the write with the old key
	// version). With opt.DryRun it only counts what would be migrated.
	Migrate(ctx context.Context, opt MigrateOptions) (MigrateResult, error)
}

// MigrateOptions tunes an eager migration pass.
type MigrateOptions struct {
	// DryRun counts the work without writing.
	DryRun bool
	// BatchSize is the number of values re-encrypted per transaction. 0 picks a
	// store-defined default.
	BatchSize int
	// RatePerSec throttles re-encryption to at most this many values per second.
	// 0 means unlimited.
	RatePerSec int
	// OnProgress, if set, is called periodically (typically per batch) during a
	// long operation with the cumulative progress so far. It must not block.
	OnProgress func(Progress)
}

// Progress reports the cumulative state of a long-running migration or backfill.
type Progress struct {
	Store string // store name
	Unit  string // unit/table, for field-level operations (else empty)
	Field string // field/column, for field-level operations (else empty)
	Done  int64  // items processed so far
	Total int64  // total items to process, or -1 when unknown
}

// MigrateResult summarizes one Migrate call.
type MigrateResult struct {
	Store     string
	Scanned   int64
	Recrypted int64
	Remaining int64 // values still under a non-primary key after this pass
}

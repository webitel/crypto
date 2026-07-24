package cryptostore

import (
	"context"
	"fmt"

	"github.com/webitel/crypto/cryptobox"
)

// MigrateMode selects how re-encryption to a new primary key proceeds after a
// key rotation.
type MigrateMode int

const (
	// MigrateLazy performs no active re-encryption. Data moves to the new key
	// opportunistically: because EncodeRows always seals with the primary key,
	// any natural write of a row migrates that row for free. Stragglers remain
	// readable (every non-retired key stays in the keyring). This is the safe
	// default — it adds zero extra writes and never turns a read into a write.
	MigrateLazy MigrateMode = iota

	// MigrateEager actively re-encrypts all data under non-primary keys now, via a
	// throttled, resumable background pass over each store. Use it before retiring
	// an old key, or when policy requires prompt re-encryption.
	MigrateEager
)

func (m MigrateMode) String() string {
	switch m {
	case MigrateLazy:
		return "lazy"
	case MigrateEager:
		return "eager"
	default:
		return fmt.Sprintf("MigrateMode(%d)", int(m))
	}
}

// Migration coordinates usage reporting and eager re-encryption across a set of
// stores. It is the engine behind the standalone agent: it answers "what share
// of data is under each key?", drives eager migration, and reports when an old
// key is safe to retire.
type Migration struct {
	stores []Store
}

// NewMigration builds a controller over the given stores.
func NewMigration(stores ...Store) *Migration {
	return &Migration{stores: stores}
}

// StoreUsage is one store's per-key usage, as returned by UsageByStore.
type StoreUsage struct {
	Store string
	Keys  []KeyUsage
}

// UsageByStore reports each store's per-key usage in a single scan per store,
// preserving store order. Callers that want both the per-store breakdown and the
// combined total (e.g. the status/usage commands) should call this once and fold
// the result with AggregateUsage — rather than calling Usage and then re-scanning
// each store.
func (m *Migration) UsageByStore(ctx context.Context) ([]StoreUsage, error) {
	out := make([]StoreUsage, 0, len(m.stores))
	for _, s := range m.stores {
		us, err := s.Usage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cryptostore: usage of %s: %w", s.Name(), err)
		}
		out = append(out, StoreUsage{Store: s.Name(), Keys: us})
	}
	return out, nil
}

// AggregateUsage folds per-store usage into a combined per-key total, keyed by KID.
// It performs no I/O — pass it the result of UsageByStore to avoid a second scan.
func AggregateUsage(stores []StoreUsage) map[cryptobox.KID]KeyUsage {
	total := map[cryptobox.KID]KeyUsage{}
	for _, this := range stores {
		for _, usage := range this.Keys {
			sum := total[usage.KID]
			sum.KID = usage.KID
			sum.Count += usage.Count
			total[usage.KID] = sum
		}
	}
	return total
}

// Usage aggregates per-key usage across every store, keyed by KID.
func (m *Migration) Usage(ctx context.Context) (map[cryptobox.KID]KeyUsage, error) {
	byStore, err := m.UsageByStore(ctx)
	if err != nil {
		return nil, err
	}
	return AggregateUsage(byStore), nil
}

// Run performs an eager migration pass over every store, returning each store's
// result. Stores are migrated sequentially so the global rate limit and load are
// predictable. Call repeatedly until every result reports Remaining == 0.
func (m *Migration) Run(ctx context.Context, req MigrateOptions) ([]MigrateResult, error) {
	results := make([]MigrateResult, 0, len(m.stores))
	for _, s := range m.stores {
		res, err := s.Migrate(ctx, req)
		if err != nil {
			return results, fmt.Errorf("cryptostore: migrate %s: %w", s.Name(), err)
		}
		res.Store = s.Name()
		results = append(results, res)
	}
	return results, nil
}

// CanRetire reports whether no data remains under kid across all stores, i.e.
// whether the key can be retired in the keyring without orphaning ciphertext
// (which would otherwise surface as cryptobox.ErrKeyRetired on read).
func (m *Migration) CanRetire(ctx context.Context, kid cryptobox.KID) (bool, error) {
	usage, err := m.Usage(ctx)
	if err != nil {
		return false, err
	}
	return usage[kid].Count == 0, nil
}

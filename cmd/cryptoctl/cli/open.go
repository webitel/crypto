package cli

import (
	"context"
	"fmt"

	"github.com/webitel/crypto/cryptostore"
)

// openCodec is the value codec cryptoctl operates with: cryptostore.Default — the
// process-wide codec assembled from the environment (CRYPTO_CIPHER_{KEYRING,KEYFILE} or
// <SystemDir>/.cipher for value encryption; CRYPTO_SEARCH_{KEYRING,KEYFILE} or .search for
// the blind index). cryptoctl deliberately has no key config of its own, so it reads and
// rewrites data with exactly the keys the services use. It is a var so a test (or an
// embedder) can substitute a codec.
var openCodec = cryptostore.Default

// openStores opens every configured store via its registered DSN driver
// (cryptostore.OpenStore), all sharing openCodec, and returns them behind one Migration.
// Stores that own resources may implement io.Closer; the caller closes them on shutdown.
func openStores(ctx context.Context, stores []StoreConfig, verbose bool) ([]cryptostore.Store, *cryptostore.Migration, error) {
	codec, err := openCodec()
	if err != nil {
		return nil, nil, err
	}
	opened := make([]cryptostore.Store, 0, len(stores))
	for _, sc := range stores {
		st, err := cryptostore.OpenStore(ctx, cryptostore.StoreOptions{
			DSN:       sc.DSN,
			Name:      sc.Name,
			Codec:     codec,
			ConfigRaw: sc.Config,
			SchemaRaw: sc.Schema,
			Verbose:   verbose,
			BaseDir:   sc.BaseDir,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("open store %q: %w", sc.Name, err)
		}
		opened = append(opened, st)
	}
	return opened, cryptostore.NewMigration(opened...), nil
}

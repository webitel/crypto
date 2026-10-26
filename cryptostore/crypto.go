package cryptostore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/env"
)

// Default returns the process-wide value codec assembled from the environment:
// cryptobox.Default (CRYPTO_CIPHER_{KEYRING,KEYFILE}, or the well-known
// <SystemDir>/.cipher) for value encryption, and the optional SearchKeys
// (CRYPTO_SEARCH_{KEYRING,KEYFILE}, or <SystemDir>/.search) for the blind index. It
// is built once, on the first call, and the same codec (or the same error) is
// returned thereafter — so a service obtains a ready *Codec without wiring keyrings:
//
//	base, err := cryptostore.Default()
//	codec := schema.NewCodec(base, baseline)
//
// The cipher keyring is required (Default errors if it is unset everywhere); the
// search keyring is optional — when absent, search is disabled and SearchToken
// returns ErrIndexKey. For keys supplied inline in code, or a second independent
// codec, build one with cryptobox.NewKeyring + NewCodec instead.
func Default() (*Codec, error) {
	mod.codec.init.Do(func() {
		cipher, err := cryptobox.Default()
		if err != nil {
			mod.codec.err = fmt.Errorf("cryptostore: cipher keyring: %w", err)
			return
		}
		searchKeys, err := SearchKeys()
		if err != nil {
			mod.codec.err = fmt.Errorf("cryptostore: search keyring: %w", err)
			return
		}
		mod.codec.base, mod.codec.err = NewCodec(cipher, searchKeys)
	})
	return mod.codec.base, mod.codec.err
}

// SearchKeys returns the blind-index keyring, resolved from the environment exactly
// once (mirrors cryptobox.DefaultKeys, minus the Box): CRYPTO_SEARCH_KEYRING / _KEYFILE,
// and when neither is set, the well-known system file <SystemDir>/.search. Search is
// OPTIONAL: with nothing configured anywhere it returns (nil, nil) and search stays
// disabled. The result is memoized for the life of the process.
func SearchKeys() (*cryptobox.Keyring, error) {
	mod.index.init.Do(func() {
		var keyring, filename string // input
		cryptobox.Environment("SEARCH").Apply(
			env.String("KEYRING", func(v string, _ bool) { keyring = v }),
			env.String("KEYFILE", func(v string, _ bool) { filename = v }),
		)
		if keyring == "" && filename == "" {
			filename = systemFile(systemSearchFile)
			if filename == "" {
				return // no keys anywhere → (nil, nil): search disabled
			}
		}
		mod.index.ring, mod.index.err = cryptobox.NewKeyring(
			cryptobox.KeyringOptions{Keyring: keyring, Filename: filename},
		)
	})
	return mod.index.ring, mod.index.err
}

// Base module environment to deal with default configuration
func Environment(namespace ...string) env.Options {
	return mod.env.WithNamespace(namespace...)
}

// systemSearchFile is the well-known blind-index keyring file within SystemDir, tried
// when no search keys are given in config or env. The leading dot marks it as secret
// material, distinct from the config directories (store.d/, schema.d/). The cipher
// keyring's well-known file (.cipher) is owned by cryptobox — its Default already
// falls back to it, so cipherKeys need not check it here.
const systemSearchFile = ".search" // search keyring → CRYPTO_SEARCH_{KEYRING,KEYFILE}

// SystemDir is the well-known directory for system-level crypto configuration:
// CRYPTO_DIR, or /var/lib/cryptoctl by default. DevOps populates it
// (.cipher, .search, and — for cryptoctl — store.d/, schema.d/) so a deployment can
// run with no environment variables at all. It delegates to cryptobox.SystemDir, the
// single source of truth for the directory.
func SystemDir() string { return cryptobox.SystemDir() }

// systemFile returns <SystemDir>/name when it exists as a regular file, else "".
func systemFile(name string) string {
	if !filepath.IsAbs(name) {
		name = filepath.Join(SystemDir(), name)
	}
	info, err := os.Stat(name)
	if err == nil && !info.IsDir() {
		return name
	}
	return ""
}

// global (module) configuration
var mod = struct {
	env   env.Options
	index struct {
		init sync.Once
		ring *cryptobox.Keyring
		err  error
	}
	codec struct {
		init sync.Once
		base *Codec
		err  error
	}
}{
	env: cryptobox.Environment(), // CRYPTO_*
}

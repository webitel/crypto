// Package cli implements cryptoctl, a standalone CLI for operating cryptostore deployments: it
// reports per-key data share, drives key migration (re-encrypting data to the primary
// key, in place), and checks whether a key is safe to retire. It also has standalone
// crypto helpers that need only the keys (no store): encrypt/decrypt a value,
// stream-encrypt/decrypt a file, generate a key, and derive a blind-index search token.
//
// It has no key configuration of its own: the value codec comes from cryptostore.Default
// — the same environment-resolved keyring the services use (CRYPTO_CIPHER_{KEYRING,KEYFILE}
// or <SystemDir>/.cipher for encryption; CRYPTO_SEARCH_{KEYRING,KEYFILE} or .search for the
// blind index) — so cryptoctl reads and rewrites data with exactly those keys. Its whole
// configuration is the set of stores to manage: one JSON/JSONC file per store in a
// store-dir, each opened via cryptostore.OpenStore behind a single Migration. Store kinds
// are enabled by importing their packages (postgres, blobstore) for their registration
// side effect.
//
// Stores are discovered from --store-dir (default store.d, searched under
// [CWD, exeDir, SystemDir]); --store selects specific files there (repeatable), else all
// are loaded. Record stores' schema includes resolve their files against --schema-dir
// (default schema.d, searched the same way). Config files are JSON or JSONC (comments and
// trailing commas tolerated).
//
// Usage:
//
//	cryptoctl [--store-dir <dir>] [--schema-dir <dir>] [--store <file>]... [--verbose] [--unsafe-keys] <command> [flags]
//
// Commands:
//
//	status                         config summary + per-key usage
//	usage                          per-key value count, per store then aggregate
//	migrate [--rate N] [--batch N] [--dry-run]   re-encrypt data to the primary key
//	can-retire <kid>               report whether a key holds no data (safe to retire)
//	keygen [--kid K] [--file path [--bytes N]]   generate a fresh high-entropy key
//	encrypt [--text] [--out fmt] <plain>         seal a value (debug/round-trip)
//	decrypt <value>                decrypt a stored value (\x…/0x…, hex:…, base64:…, file:…, json cbox:…)
//	encrypt-file <src> <dst>       stream-encrypt a large file (bounded memory)
//	decrypt-file <src> <dst>       stream-decrypt a large file
//	search <unit> <field> [nested...] <plain>   blind-index key+token for a lookup
//	version                        print build/version info (module, revision, go)
//	help [command]                 show usage, or a command's details and flags
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"

	// Register store schemes (init side effects): "postgres", "blobfs", "s3"/"gs"/"file"/"mem".
	// blobstore itself is imported (named) by cmd_crypto.go for its stream codec,
	// which also runs its "blobfs" registration.
	_ "github.com/webitel/crypto/cryptostore/blobstore/gocloud"
	_ "github.com/webitel/crypto/cryptostore/postgres"
)

// stringList is a repeatable string flag (e.g. --store a --store b → ["a", "b"]).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// envOr returns the environment value for key, or def when it is unset/empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Main runs cryptoctl with os.Args and exits the process on error. A distribution
// can wrap it, e.g. to register a field-schema baseline (schema.Register) first.
func Main() {
	top := flag.NewFlagSet("cryptoctl", flag.ExitOnError)
	storeDir := top.String("store-dir", envOr("CRYPTO_STORE_DIR", "store.d"), "directory of per-store config files (JSON/JSONC), one per store")
	schemaDir := top.String("schema-dir", envOr("CRYPTO_SCHEMA_DIR", "schema.d"), "shared directory of field-schema files for record stores")
	var only stringList
	top.Var(&only, "store", "select a specific store file in --store-dir (repeatable); default: all files")
	verbose := top.Bool("verbose", false, "enable store-level debug logging (e.g. SQL query tracing for postgres)")
	unsafeKeys := top.Bool("unsafe-keys", false, "load key files that are not private (world/group-accessible) with only a warning, instead of failing")
	top.Usage = usage
	_ = top.Parse(os.Args[1:])

	// By default cryptobox rejects key files that are not private (owner/group-read only).
	// --unsafe-keys relaxes that to a warning — same as CRYPTO_KEYFILE_POLICY=unsafe.
	// Set before any keyring is read (openCodec / loadStores).
	if *unsafeKeys {
		cryptobox.KeyFilePolicy = cryptobox.KeyFileWarnUnlessPrivate
	}

	cmd, args := "", top.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, args = args[0], args[1:]

	// help needs no config or keys: `cryptoctl help [command]`.
	if cmd == "help" {
		if err := cmdHelp(args); err != nil {
			fatal(err)
		}
		return
	}

	// version reads the binary's embedded build info — no config or keys.
	if cmd == "version" {
		if err := cmdVersion(args); err != nil {
			fatal(err)
		}
		return
	}

	// keygen creates fresh key material — it needs no existing config or keys, so
	// it is handled before the config/Open requirement below.
	if cmd == "keygen" {
		if err := cmdKeygen(args); err != nil {
			fatal(err)
		}
		return
	}

	ctx := context.Background()

	// Codec-only commands need only the codec — no store connections and no store
	// config. The codec is built from the environment (cryptostore.Default).
	switch cmd {
	case "encrypt", "decrypt", "search",
		"encrypt-file", "decrypt-file":
		codec, err := openCodec()
		if err != nil {
			fatal(err)
		}
		switch cmd {
		case "search":
			err = cmdSearch(ctx, codec, args)
		case "encrypt":
			err = cmdEncrypt(ctx, codec, args)
		case "decrypt":
			err = cmdDecrypt(ctx, codec, args)
		case "encrypt-file":
			err = cmdEncryptFile(ctx, codec, args)
		case "decrypt-file":
			err = cmdDecryptFile(ctx, codec, args)
		}
		if err != nil {
			fatal(err)
		}
		return
	}

	// Store commands require at least one configured store.
	stores, err := loadStores(resolveDir(*storeDir), resolveDir(*schemaDir), only)
	if err != nil {
		fatal(err)
	}
	if len(stores) == 0 {
		fatal(fmt.Errorf("no stores configured (store-dir %q, --store %v); set --store-dir / CRYPTO_STORE_DIR or --store", *storeDir, []string(only)))
	}
	opened, mig, err := openStores(ctx, stores, *verbose)
	if err != nil {
		fatal(err)
	}
	defer closeStores(opened)

	var err2 error
	switch cmd {
	case "usage":
		err2 = cmdUsage(ctx, mig)
	case "status":
		err2 = cmdStatus(ctx, opened, mig)
	case "migrate":
		err2 = cmdMigrate(ctx, mig, args)
	case "can-retire":
		err2 = cmdCanRetire(ctx, mig, args)
	default:
		usage()
		os.Exit(2)
	}
	if err2 != nil {
		fatal(err2)
	}
}

// closeStores closes any store that owns resources (a pool, a catalog).
func closeStores(stores []cryptostore.Store) {
	for _, s := range stores {
		if c, ok := s.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "cryptoctl:", err)
	os.Exit(1)
}

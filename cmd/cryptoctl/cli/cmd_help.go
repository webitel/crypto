package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/webitel/crypto/cryptostore"
)

// cmdHelp implements `cryptoctl help [command|topic]`: general usage with no argument,
// else the named command's synopsis/description/flags, or a guide topic's text — all to
// stdout.
func cmdHelp(args []string) error {
	if len(args) == 0 {
		writeUsage(os.Stdout)
		return nil
	}
	name := args[0]
	t, ok := lookupTopic(name)
	if !ok {
		usage()
		return fmt.Errorf("unknown help topic %q", name)
	}
	w := os.Stdout
	fmt.Fprintln(w) // leading blank line: set the block off from the prompt
	if t.command {
		fmt.Fprintf(w, "Usage: cryptoctl %s\n\n", t.usage)
	}
	if t.long != "" {
		fmt.Fprintln(w, t.long)
	}
	if t.flags != nil {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		t.flags(fs)
		fmt.Fprintln(w, "\nFlags:")
		printFlags(w, fs)
	}
	fmt.Fprintln(w) // trailing blank line: separate help output from the next prompt
	return nil
}

// printFlags lists a flagset's flags as "--name type\tusage", double-dash and aligned
// (flag.PrintDefaults would render single-dash).
func printFlags(w io.Writer, fs *flag.FlagSet) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fs.VisitAll(func(f *flag.Flag) {
		name := "--" + f.Name
		if typ, _ := flag.UnquoteUsage(f); typ != "" {
			name += " " + typ
		}
		fmt.Fprintf(tw, "  %s\t%s\n", name, f.Usage)
	})
	tw.Flush()
}

// writeUsage renders the top-level help: global flags, the command list (one line each,
// no per-command flags — those live under `help <command>`), and the help-topic list.
func writeUsage(w io.Writer) {
	fmt.Fprintln(w) // leading blank line: set the block off from the prompt
	fmt.Fprint(w, `cryptoctl — operate cryptostore deployments

Usage:
  cryptoctl [global flags] <command> [command flags] [args]

Global flags:
  --schema-dir <dir>   shared field-schema files for record stores (default: schema.d)
  --store-dir <dir>    per-store config files, one *.json/*.jsonc each (default: store.d)
  --store <file>       use only this store file in --store-dir (repeatable; default: all)
  --verbose            store-level debug logging (SQL query tracing for postgres)
  --unsafe-keys        warn (don't fail) on key files that are not private (else 0600/0640 required)

Commands:
`)
	listTopics(w, true)
	fmt.Fprint(w, "\nHelp topics:\n")
	listTopics(w, false)
	fmt.Fprint(w, "\nRun \"cryptoctl help <command|topic>\" for details.\n\n")
}

// usage prints the top-level help to stderr (the flag.Usage / error path).
func usage() { writeUsage(os.Stderr) }

// topic is a `help <name>` entry. A command is a topic with command=true — listed
// under "Commands", dispatched by main, and possibly carrying flags. A guide is a
// topic with command=false — listed under "Help topics", documentation only (no
// synopsis line, no flags). `help <name>` resolves a name across both kinds, so a
// topic may or may not coincide with a command. Add a guide by appending to topics.
type topic struct {
	name    string
	command bool                // true → an actual command (runnable, under "Commands")
	usage   string              // argument synopsis for a command's `help <cmd>`
	short   string              // one-liner for the listing
	long    string              // the paragraph shown by `help <name>`
	flags   func(*flag.FlagSet) // registers a command's flags (nil otherwise) — the SAME
	//                             function the command parses with, so help never drifts
}

// listTopics prints the name/short of every topic whose command flag matches, aligned.
func listTopics(w io.Writer, command bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, t := range topics {
		if t.command == command {
			fmt.Fprintf(tw, "  %s\t%s\n", t.name, t.short)
		}
	}
	tw.Flush()
}

// lookupTopic finds a topic (command or guide) by name.
func lookupTopic(name string) (topic, bool) {
	for _, t := range topics {
		if t.name == name {
			return t, true
		}
	}
	return topic{}, false
}

// topics is the ordered help registry: commands first (in display order), then guides.
var topics = []topic{
	{
		name: "status", command: true,
		usage: "status",
		short: "config summary + per-key usage",
		long:  "Print a configuration summary — the registered store drivers and the managed\nstores — followed by the per-key usage across all stores.",
	},
	{
		name: "usage", command: true,
		usage: "usage",
		short: "per-key value count, per store then aggregate",
		long:  "Report how many encrypted values sit under each key: per store, then aggregated.\nUse it to watch rotation progress or see whether a key still holds data.",
	},
	{
		name: "migrate", command: true,
		usage: "migrate [--dry-run] [--batch N] [--rate N]",
		short: "re-encrypt data to the primary key",
		long: "Re-encrypt data to the primary key across all stores, batched and resumable.\n" +
			"A natural write already re-encrypts a row; migrate catches up the rest. It\n" +
			"prints a live progress line on stderr (except --dry-run), then a per-store\n" +
			"SCANNED/RECRYPTED/REMAINING table on stdout. See `cryptoctl help migration`.",
		flags: func(fs *flag.FlagSet) { migrateFlags(fs) },
	},
	{
		name: "can-retire", command: true,
		usage: "can-retire <kid>",
		short: "report whether a key is safe to retire",
		long:  "Report whether the key with the given KID still holds data — \"safe to retire\"\nonly when none remains (run migrate first otherwise). KID is decimal or 0x-hex.",
	},
	{
		name: "keygen", command: true,
		usage: "keygen [--kid K] [--file <path> [--bytes N]]",
		short: "generate a fresh high-entropy key",
		long: "Generate a fresh, high-entropy key from crypto/rand — needs no config, so it\n" +
			"makes the very first key. By default prints a ready-to-paste keyring phrase\n" +
			"(random length, keyring/shell-safe); --file writes raw key bytes (0600) for\n" +
			"the *_FILE / FileMaterial form. See `cryptoctl help keys`.",
		flags: func(fs *flag.FlagSet) { keygenFlags(fs) },
	},
	{
		name: "encrypt", command: true,
		usage: "encrypt [--text] [--out fmt] <plaintext|file:path>",
		short: "seal a value (debug/round-trip)",
		long: "Seal a plaintext for storage. Encryption is randomized (fresh nonce each run),\n" +
			"so the output differs every time, cannot match a row, and does not populate\n" +
			"the __cs_idx search slot — use search for lookups. --text selects json (cbox:)\n" +
			"framing instead of the default binary bytea.",
		flags: func(fs *flag.FlagSet) { encryptFlags(fs) },
	},
	{
		name: "decrypt", command: true,
		usage: "decrypt <value>",
		short: "decrypt a stored value",
		long:  "Decrypt one stored value back to plaintext. Accepts the forms data takes in the\ndatabase plus explicit encodings: \\x…/0x… (psql bytea), hex:…, base64:…, file:<path>,\nor a json/text cbox: value. Legacy plaintext is returned as-is.",
	},
	{
		name: "encrypt-file", command: true,
		usage: "encrypt-file <src|-> <dst|->",
		short: "stream-encrypt a large file (bounded memory)",
		long:  "Stream-encrypt a whole file (or stdin, \"-\") to another file (or stdout) with\nbounded memory, for objects too large for the inline commands. The output is the\nblobstore WBS stream format — read it back with decrypt-file, not decrypt.",
	},
	{
		name: "decrypt-file", command: true,
		usage: "decrypt-file <src|-> <dst|->",
		short: "stream-decrypt a large file",
		long:  "Stream-decrypt a WBS file (or stdin, \"-\") to another file (or stdout).",
	},
	{
		name: "search", command: true,
		usage: "search <unit> <field> [nested...] <plaintext>",
		short: "blind-index key + token for an exact-match lookup",
		long: "Print the __cs_idx slot key and blind-index token for a plaintext, so you can\n" +
			"find a row without the keys by hand. The token is domain-scoped, so pass the\n" +
			"unit and field; for a value nested inside a json document also pass nested — the\n" +
			"full path to that attribute, one argument per object-key segment. Example:\n" +
			"`cryptoctl search directory.users profile ssn <value>` (field \"profile\", nested\n" +
			"path \"ssn\"). No schema check is done — the token is computed from the location.",
	},
	{
		name: "version", command: true,
		usage: "version",
		short: "print build/version info (module, revision, go)",
		long: "Print the binary's version and build metadata in Go module form, read from the\n" +
			"embedded build info (no -ldflags needed): the module version — a tag when\n" +
			"installed with `go install …@version`, else \"(devel)\" — the module path, the Go\n" +
			"toolchain, and the VCS revision/time/dirty state stamped by the build.",
	},
	{
		name: "help", command: true,
		usage: "help [command|topic]",
		short: "show usage, or a command/topic's details",
		long:  "With no argument, print the general usage. With a command name, print that\ncommand's synopsis, description, and flags; with a topic name (see the list),\nprint that guide.",
	},

	// --- guides (not commands) ---
	{
		name:  "keys",
		short: "how encryption keys are configured and loaded",
		long: "cryptoctl uses two cryptobox keyrings, read ONLY from the environment (never\n" +
			"flags), so the tool and the services share exactly the same keys:\n" +
			"\n" +
			"  cipher (value encryption)   CRYPTO_CIPHER_KEYRING | _KEYFILE\n" +
			"  search (blind index)        CRYPTO_SEARCH_KEYRING | _KEYFILE\n" +
			"\n" +
			"Resolution order, per keyring: _KEYRING (inline keys) or _KEYFILE (a path) from\n" +
			"the environment first; if neither is set, the well-known system file under\n" +
			"<SystemDir> — .cipher / .search — where SystemDir is CRYPTO_DIR, else the\n" +
			"build default (here: " + cryptostore.SystemDir() + "). The search keyring is\n" +
			"optional: absent everywhere, search is simply disabled.\n" +
			"\n" +
			"Key files must be private — owner (and tolerated group) read only: 0600, 0400,\n" +
			"0640, 0440; a wider mode is rejected. Relax to a warning with --unsafe-keys or\n" +
			"CRYPTO_KEYFILE_POLICY=unsafe.\n" +
			"\n" +
			"Keys are never discovered from $PWD or next to the binary — only the environment\n" +
			"or the system dir, so secrets come from a trusted location. Generate or rotate a\n" +
			"key with `cryptoctl keygen` (see `cryptoctl help keygen`).",
	},
	{
		name:  "store",
		short: "how individual stores are configured",
		long: "cryptoctl's whole configuration is the set of stores to manage — one JSON/JSONC\n" +
			"file per store, discovered from --store-dir (default store.d, searched\n" +
			"$PWD → exe dir → SystemDir). --store <file> selects specific files (repeatable);\n" +
			"otherwise every *.json/*.jsonc there is loaded. Enable a store kind by importing\n" +
			"its package for the registration side effect (postgres, blobstore).\n" +
			"\n" +
			"Each store file:\n" +
			"  dsn     <scheme>[:opaque] — the scheme picks the driver (postgres, blobfs,\n" +
			"          s3/gs/file/mem); the opaque part is the driver's connection string.\n" +
			"  name    store label (defaults to the file name).\n" +
			"  config  driver extras not in the DSN (postgres: schema; blobstore: catalog).\n" +
			"  schema  field schema for record stores: an inline Config, or an include\n" +
			"          directive {dir, files} merged from --schema-dir (default schema.d).\n" +
			"\n" +
			"Relative filesystem paths in a driver (a blobfs dir, a file:// bucket path, a\n" +
			"sqlite catalog) resolve against the store file's directory, not $PWD.\n" +
			"\n" +
			"Field-level encryption for record stores is described by a schema — see\n" +
			"`cryptoctl help schema`.",
	},
	{
		name:  "schema",
		short: "how field-level encryption is declared",
		long: "Record stores (postgres today) encrypt named fields per a declarative field\n" +
			"schema — which fields of which units (a table / document collection) are\n" +
			"encrypted, and which allow exact-match search. A store's `schema` section is an\n" +
			"inline Config or an include directive; see `cryptoctl help store`.\n" +
			"\n" +
			"A field policy is one of:\n" +
			"  {\"search\": true}     scalar field: encrypt, and record a blind-index token in\n" +
			"                      the unit's __cs_idx column for exact-match lookup.\n" +
			"  {}                  scalar field: encrypt only (no search).\n" +
			"  {\"nested\": [ … ]}   json/jsonb field: encrypt only the listed attributes. Each\n" +
			"                      entry is a \"$.a.b\" shorthand or {\"path\":[…],\"search\":true};\n" +
			"                      a single \"$\"-prefixed path is split on dots, any other is\n" +
			"                      literal segments (so a dotted key name is one segment).\n" +
			"\n" +
			"Search tokens for a whole unit live in one __cs_idx json column; key versions are\n" +
			"read straight from the ciphertext (no companion column). A code baseline can be\n" +
			"pinned so an admin overlay may add fields or enable search but never relax it.\n" +
			"Compute a lookup token with `cryptoctl search`.",
	},
	{
		name:  "migration",
		short: "how key rotation and migration work",
		long: "Ciphertext is stored inline and self-marking, and migration is IN PLACE — there\n" +
			"is no expand/contract, and originals are never dropped. Encrypt always uses the\n" +
			"primary key, so every natural write (INSERT/UPDATE) re-encrypts that row for\n" +
			"free (opportunistic). `cryptoctl migrate` sweeps the rest:\n" +
			"\n" +
			"  - batched and resumable; each batch re-encodes rows through the codec and\n" +
			"    writes them back in one set-based UPDATE, guarded by a CAS on the old value,\n" +
			"    so a concurrent natural write is skipped, not clobbered;\n" +
			"  - it encrypts plaintext (first-time encryption) and re-encrypts non-primary\n" +
			"    values (rotation) alike, and skips NULL/empty;\n" +
			"  - --dry-run only counts; --batch and --rate bound throughput.\n" +
			"\n" +
			"After rotating a key in, run migrate until nothing remains under the old KID;\n" +
			"`cryptoctl can-retire <kid>` then confirms it holds no data and is safe to\n" +
			"tombstone. See `cryptoctl help migrate`.",
	},
}

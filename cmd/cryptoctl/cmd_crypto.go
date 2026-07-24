package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/blobstore"
	"github.com/webitel/crypto/cryptostore/schema"
)

// maxInlineFileBytes caps a file:<path> read for the inline encrypt/decrypt
// commands. Inline framing is a single AEAD blob held wholly in memory and is meant
// for small column/attribute values; large files must use the streaming
// encrypt-file/decrypt-file commands. A var (not const) so tests can lower it.
var maxInlineFileBytes int64 = 4 << 20 // 4 MiB

// cmdDecrypt decrypts one stored value back to plaintext. It accepts the forms the
// data takes in the database plus explicit encodings of the raw bytes: a bytea
// column value (psql prints it as \x-hex; 0x too), an explicit hex:… / base64:…, a
// file:<path> holding the value, or a json/text attribute value (the cbox: tag). A
// value that is not encrypted (legacy plaintext) is returned as-is with a note.
func cmdDecrypt(ctx context.Context, codec *cryptostore.Codec, args []string) error {
	if len(args) != 1 {
		return errors.New(`usage: decrypt <value>   (\x…/0x…, hex:…, base64:…, file:…, or json cbox:…)`)
	}
	data, encrypted, err := decryptValue(ctx, codec, args[0])
	if err != nil {
		return err
	}
	if !encrypted {
		fmt.Fprintln(os.Stderr, "cryptoctl: value is not encrypted (returned as-is)")
	}
	os.Stdout.Write(data)
	fmt.Fprintln(os.Stdout)
	return nil
}

// byteaForms maps an inline value prefix to the decoder for the raw bytes behind it.
// The psql \x/0x forms and the explicit hex:/base64: forms all describe raw bytes.
var byteaForms = []struct {
	prefix string
	decode func(string) ([]byte, error)
}{
	{"base64:", decodeBase64},
	{"hex:", hex.DecodeString},
	{`\x`, hex.DecodeString}, // psql bytea default (bytea_output = hex)
	{"0x", hex.DecodeString},
}

// resolveBytes decodes a scheme-prefixed value to raw bytes: file:<path> (file
// contents) or an inline base64:/hex:/\x…/0x… encoding. ok is false when arg
// carries no recognized scheme, so the caller decides how to treat a bare value.
func resolveBytes(arg string) (data []byte, ok bool, err error) {
	if path, isFile := strings.CutPrefix(arg, "file:"); isFile {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, true, err
		}
		if fi.Size() > maxInlineFileBytes {
			return nil, true, fmt.Errorf("file %s is %s: inline encryption is for small column values — "+
				"use `encrypt-file`/`decrypt-file` (streaming) for large objects", path, humanBytes(fi.Size()))
		}
		b, err := os.ReadFile(path)
		return b, true, err
	}
	for _, f := range byteaForms {
		if rest, has := strings.CutPrefix(arg, f.prefix); has {
			b, err := f.decode(rest)
			if err != nil {
				return nil, true, fmt.Errorf("decode %s value: %w", strings.TrimSuffix(f.prefix, ":"), err)
			}
			return b, true, nil
		}
	}
	return nil, false, nil
}

// decryptValue is the testable core of cmdDecrypt: it resolves in to the value bytes
// (a file:/hex:/base64:/\x/0x scheme, else the argument itself) and decrypts them —
// a cbox:-tagged value via DecryptText, otherwise binary framing via Decrypt.
// encrypted is false for a legacy-plaintext passthrough.
func decryptValue(ctx context.Context, codec *cryptostore.Codec, in string) (data []byte, encrypted bool, err error) {
	raw, ok, err := resolveBytes(in)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		raw = []byte(in) // no byte-scheme: the argument itself carries the value
	}
	// Text framing (cbox:base64…) — DecryptText decodes its own base64.
	if _, framed := cryptostore.UnframeText(string(raw)); framed {
		return codec.DecryptText(ctx, string(raw))
	}
	// Binary framing. Without a scheme and without the text tag the encoding of a
	// bare argument is unknown, so reject it.
	if !ok {
		return nil, false, fmt.Errorf(`unrecognized value: expected \x…/0x…, hex:…, base64:…, file:… or a json cbox:… value`)
	}
	return codec.Decrypt(ctx, raw)
}

// decodeBase64 decodes s under whichever standard base64 variant matches (padded or
// raw, standard or URL alphabet) — operators paste whatever their tooling produced.
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

// encryptFlags registers the encrypt command's flags on fs (shared by cmdEncrypt and
// `help encrypt`).
func encryptFlags(fs *flag.FlagSet) (text *bool, out *string) {
	text = fs.Bool("text", false, "text framing (cbox:…) for a json attribute (default: binary bytea)")
	out = fs.String("out", "", "output encoding: pgbytea|hex|base64|raw|file:<path> (default: pgbytea; the cbox string with --text)")
	return
}

// cmdEncrypt seals a plaintext for storage. --text selects text framing (cbox:…,
// for a json attribute) instead of the default binary bytea framing. --out picks
// the output encoding of the sealed value. The plaintext may be given inline or as
// file:<path>. NOTE: encryption is randomized (a fresh nonce each run), so the
// output differs every time and cannot be used to match/find a row — use `search`
// for that — and it does not populate the __cs_idx search slot.
func cmdEncrypt(ctx context.Context, codec *cryptostore.Codec, args []string) error {
	cmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	text, out := encryptFlags(cmd)
	// Go's flag stops at the first non-flag argument; re-parse around the single
	// positional so flags may appear before or after the plaintext.
	var pos []string
	for rem := args; len(rem) > 0; {
		if err := cmd.Parse(rem); err != nil {
			return err
		}
		if cmd.NArg() == 0 {
			break
		}
		pos = append(pos, cmd.Arg(0))
		rem = cmd.Args()[1:]
	}
	if len(pos) != 1 {
		return errors.New("usage: encrypt [--text] [--out fmt] <plaintext|file:path>")
	}
	data, err := readPlaintext(pos[0])
	if err != nil {
		return err
	}
	if *text {
		s, err := codec.EncryptText(ctx, data)
		if err != nil {
			return err
		}
		if *out == "" {
			fmt.Fprintln(os.Stdout, s) // the cbox string, verbatim
			return nil
		}
		return emitValue([]byte(s), *out)
	}
	framed, err := codec.Encrypt(ctx, data)
	if err != nil {
		return err
	}
	o := *out
	if o == "" {
		o = "pgbytea"
	}
	return emitValue(framed, o)
}

// readPlaintext resolves the plaintext source for encrypt: a file:<path>, an inline
// hex:/base64:/\x/0x encoding, or a bare literal string.
func readPlaintext(arg string) ([]byte, error) {
	if b, ok, err := resolveBytes(arg); ok {
		return b, err
	}
	return []byte(arg), nil
}

// emitValue writes value under the --out spec: file:<path> (raw bytes to a file),
// raw (verbatim to stdout), or an encoding (pgbytea|hex|base64) printed to stdout.
func emitValue(value []byte, out string) error {
	if path, isFile := strings.CutPrefix(out, "file:"); isFile {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "cryptoctl: wrote %d bytes to %s\n", len(value), path)
		return nil
	}
	if out == "raw" {
		_, err := os.Stdout.Write(value)
		return err
	}
	s, err := encodeValue(value, out)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, s)
	return nil
}

// encodeValue renders value under an inline output encoding.
func encodeValue(value []byte, out string) (string, error) {
	switch out {
	case "pgbytea":
		return `\x` + hex.EncodeToString(value), nil
	case "hex":
		return hex.EncodeToString(value), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(value), nil
	default:
		return "", fmt.Errorf("unknown --out %q (want pgbytea|hex|base64|raw|file:<path>)", out)
	}
}

// cmdSearch prints the __cs_idx slot key and blind-index token for a plaintext, so
// an operator can find the row without knowing the encryption keys by hand. The
// token is domain-scoped, so the unit and field are required; for a value nested in a
// json document, the trailing args are nested — the full path (object-key segments)
// to that attribute. The same value hashes differently per location. No store
// connection is required: the token is derived purely from the search key.
//
// It performs NO schema check — the token is computed from the location alone, so
// naming an unmanaged or non-searchable field still returns a token; it just won't
// match anything stored. The plaintext is taken as raw UTF-8 bytes: for a scalar or
// string attribute pass the value verbatim; for a non-string json attribute (number,
// bool) pass its canonical JSON form (e.g. 123, true), matching how the record codec
// tokenizes it.
func cmdSearch(ctx context.Context, codec *cryptostore.Codec, args []string) error {
	if len(args) < 3 {
		return errors.New("usage: search <unit> <field> [nested...] <plaintext>")
	}
	// Domain: unit, field, optional nested path; plaintext is the last arg.
	unit, fld := args[0], args[1]
	path := args[2 : len(args)-1]
	data := []byte(args[len(args)-1])

	key := schema.SearchKey(fld, path...)
	tok, err := codec.SearchToken(ctx, unit+"."+key, data)
	if err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(tok)

	w := newTab()
	fmt.Fprintf(w, "unit:\t%s\n", unit)
	fmt.Fprintf(w, "key:\t%s\n", key)
	fmt.Fprintf(w, "token:\t%s\n", token)
	w.Flush()
	fmt.Printf("\n  WHERE __cs_idx @> jsonb_build_object(%s, %s)\n", sqlLiteral(key), sqlLiteral(token))
	return nil
}

// sqlLiteral renders s as a single-quoted SQL string literal (single quotes doubled).
func sqlLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// --- streaming file encryption --------------------------------------------------

// cmdEncryptFile stream-encrypts a whole file (or stdin) to another file (or stdout)
// with bounded memory, for objects too large for the inline commands. The output is
// the blobstore WBS stream format (envelope DEK + chunked body) — NOT an inline
// column value; read it back with decrypt-file.
func cmdEncryptFile(ctx context.Context, codec *cryptostore.Codec, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: encrypt-file <src|-> <dst|->")
	}
	kid, n, err := streamEncryptFile(ctx, codec, args[0], args[1])
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "cryptoctl: encrypted %d bytes under kid %d → %s\n", n, kid, args[1])
	return nil
}

// cmdDecryptFile stream-decrypts a WBS file (or stdin) to another file (or stdout).
func cmdDecryptFile(ctx context.Context, codec *cryptostore.Codec, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: decrypt-file <src|-> <dst|->")
	}
	n, err := streamDecryptFile(ctx, codec, args[0], args[1])
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "cryptoctl: decrypted %d bytes → %s\n", n, args[1])
	return nil
}

// streamEncryptFile is the testable core of cmdEncryptFile.
func streamEncryptFile(ctx context.Context, codec *cryptostore.Codec, srcPath, dstPath string) (kid uint32, n int64, err error) {
	in, closeIn, err := openIn(srcPath)
	if err != nil {
		return 0, 0, err
	}
	defer closeIn()
	out, closeOut, err := openOut(dstPath)
	if err != nil {
		return 0, 0, err
	}
	k, n, err := blobstore.Seal(ctx, codec, out, in)
	if cerr := closeOut(); err == nil {
		err = cerr
	}
	return uint32(k), n, err
}

// streamDecryptFile is the testable core of cmdDecryptFile.
func streamDecryptFile(ctx context.Context, codec *cryptostore.Codec, srcPath, dstPath string) (n int64, err error) {
	in, closeIn, err := openIn(srcPath)
	if err != nil {
		return 0, err
	}
	defer closeIn()
	r, err := blobstore.OpenReader(ctx, codec, in)
	if err != nil {
		return 0, err
	}
	out, closeOut, err := openOut(dstPath)
	if err != nil {
		return 0, err
	}
	n, err = io.Copy(out, r)
	if cerr := closeOut(); err == nil {
		err = cerr
	}
	return n, err
}

// openIn opens a read source: a file path, or "-" for stdin.
func openIn(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// openOut opens a write sink: a file path (0600), or "-" for stdout.
func openOut(path string) (io.Writer, func() error, error) {
	if path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

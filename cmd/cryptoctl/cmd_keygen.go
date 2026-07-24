package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/webitel/crypto/cryptobox"
)

// randomInt returns a uniform random integer in [0, max) from crypto/rand. max > 0.
func randomInt(max int) (int, error) {
	gen, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(gen.Int64()), nil
}

// randomString returns a length-character string: one crypto/rand read, each byte
// mapped to a character by byte % len(alphabet).
//
// That mapping carries a small, deliberate modulo bias: 256 is not a multiple of
// len(alphabet) (85), so 256 mod 85 = 1 character is ~33% more likely than the
// rest. It is accepted on purpose — the effect on a >=40-char phrase is negligible
// (min-entropy ~6.0 vs 6.409 bits/char → still >=240 bits, far beyond brute force,
// and the IKM is HKDF'd to 256 bits regardless). A single batched read keeps it
// cheap; the only hard requirement is not to swallow a rand.Read failure.
func randomString(length int, alphabet string) (string, error) {
	gen := make([]byte, length)
	if _, err := rand.Read(gen); err != nil {
		return "", err
	}
	max := len(alphabet)
	for e, i := range gen {
		gen[e] = alphabet[int(i)%max]
	}
	return string(gen), nil
}

// keygenAlpha is the phrase alphabet, chosen so a generated phrase is safe to use
// verbatim in both places it lands:
//   - the keyring parser: excludes its control/escape chars  , [ ] / - \  so the
//     phrase can't be misread as a separator, KID, file path, tombstone or escape;
//   - a shell: excludes the quotes  " ' `  so pasting it inline into an env var,
//     e.g.  export WBTL_CRYPTO_CIPHER_KEYRING="<phrase>"  , can't break the quoting.
const keygenAlpha = "!#$%&()*+.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz{|}~"

const (
	minPhraseLen = 40
	maxPhraseLen = 64
)

// randomPhrase generates a random keyring passphrase of random length in
// [minPhraseLen, maxPhraseLen], each character from keygenAlpha. At ~6.4 bits/char
// and >= 40 chars it carries >= 256 bits of entropy.
func randomPhrase() (string, error) {
	span, err := randomInt(maxPhraseLen - minPhraseLen + 1) // [0, 24]
	if err != nil {
		return "", err
	}
	return randomString(minPhraseLen+span, keygenAlpha)
}

// --- keygen command ---------------------------------------------------------------

const (
	minKeyBytes  = 16  // 128-bit floor for a generated key
	minFileBytes = 20  // cryptobox FileMaterial minimum
	maxKeyBytes  = 256 // cryptobox FileMaterial maximum
)

// cmdKeygen generates a fresh, high-entropy key from crypto/rand. By default it
// prints a ready-to-paste keyring entry (hex, safe from keyring control chars) for
// WBTL_CRYPTO_CIPHER_KEYRING / WBTL_CRYPTO_SEARCH_KEYRING. With --file it writes raw key bytes
// to a file (0600) for the *_FILE / FileMaterial form. It needs no existing config.
// keygenFlags registers the keygen command's flags on fs (shared by cmdKeygen and
// `help keygen`).
func keygenFlags(fs *flag.FlagSet) (nBytes, kid *int, file *string) {
	nBytes = fs.Int("bytes", 32, "raw key bytes for --file (20..256); ignored for the printed phrase")
	kid = fs.Int("kid", 0, "explicit [KID] prefix for the keyring entry (0 = implicit, 1..65535)")
	file = fs.String("file", "", "write raw key bytes to this file (0600) for the *_FILE form")
	return
}

func cmdKeygen(args []string) error {
	cmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	nBytes, kid, file := keygenFlags(cmd)
	_ = cmd.Parse(args)

	if *file != "" {
		if *nBytes < minFileBytes {
			return fmt.Errorf("keygen: --file needs >= %d bytes (FileMaterial minimum), got %d", minFileBytes, *nBytes)
		}
		buf, err := randomKey(*nBytes)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*file, buf, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "cryptoctl: wrote %d random bytes to %s (use as *_FILE / FileMaterial)\n", *nBytes, *file)
		return nil
	}

	// The printed phrase has a random length, so --bytes has no effect here.
	bytesSet := false
	cmd.Visit(func(arg *flag.Flag) {
		if bytesSet {
			return
		}
		if arg.Name == "bytes" {
			bytesSet = true
		}
	})
	if bytesSet {
		return errors.New("keygen: --bytes applies only to --file; the printed keyring phrase uses a random length")
	}

	entry, err := keygenEntry(*kid)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, entry)
	return nil
}

// randomKey returns nBytes of cryptographically-random data after range-checking.
func randomKey(nBytes int) ([]byte, error) {
	if nBytes < minKeyBytes || nBytes > maxKeyBytes {
		return nil, fmt.Errorf("keygen: --bytes must be in [%d,%d], got %d", minKeyBytes, maxKeyBytes, nBytes)
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("keygen: read random: %w", err)
	}
	return buf, nil
}

// keygenEntry builds a keyring entry string: a random passphrase (printable ASCII,
// free of the keyring's control chars), optionally prefixed with an explicit [kid].
// It is validated by parsing it back as a keyring.
func keygenEntry(kid int) (string, error) {
	if kid < 0 || kid > 65535 {
		return "", fmt.Errorf("keygen: --kid must be in [1,65535], got %d", kid)
	}
	entry, err := randomPhrase()
	if err != nil {
		return "", err
	}
	if kid > 0 {
		entry = fmt.Sprintf("[%d]%s", kid, entry)
	}
	if _, err := cryptobox.ParseKeyring(entry); err != nil {
		return "", fmt.Errorf("keygen: generated an invalid keyring entry: %w", err)
	}
	return entry, nil
}

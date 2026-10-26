package cryptobox

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestNotPrivate pins the permission policy: owner-only and group-read are private;
// any world access or group-write is not.
func TestNotPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	private := []fs.FileMode{0o600, 0o400, 0o640, 0o440}
	for _, m := range private {
		if r := keyFilePrivacyViolation(m); r != "" {
			t.Errorf("mode %04o should be private, got %q", m, r)
		}
	}
	notPriv := map[fs.FileMode]string{
		0o644: "world-readable",
		0o604: "world-readable",
		0o666: "world-readable",
		0o620: "group-writable",
		0o660: "group-writable",
		0o402: "world-writable",
	}
	for m, want := range notPriv {
		if r := keyFilePrivacyViolation(m); r != want {
			t.Errorf("mode %04o: reason %q, want %q", m, r, want)
		}
	}
}

// TestKeyFilePolicyFromEnv: only CRYPTO_KEYFILE_POLICY=unsafe relaxes the check;
// empty, "strict", and any typo all fail safe to strict (reject a not-private file).
func TestKeyFilePolicyFromEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil { // not private
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{ // value → should the resolved policy reject 0644?
		"":       true,
		"strict": true,
		"bogus":  true,
		"unsafe": false,
	}
	for v, wantReject := range cases {
		t.Setenv("CRYPTO_KEYFILE_POLICY", v)
		gotReject := keyFilePolicyFromEnv()(p, info) != nil
		if gotReject != wantReject {
			t.Errorf("policy=%q: reject=%v, want %v", v, gotReject, wantReject)
		}
	}
}

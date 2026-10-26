package env_test

import (
	"testing"

	"github.com/webitel/crypto/env"
)

var testEnv = env.Options{
	Namespace: env.Name("CRYPTO"),
	LookupEnv: env.LookupEnv,
}

func TestNestedNamespace(test *testing.T) {

	test.Setenv("CRYPTO_CIPHER_KEYS", "qwerty")

	if got, want := testEnv.Getenv("CIPHER_KEYS"), "qwerty"; got != want {
		test.Errorf("sdk/env.Getenv: got %s, want %s", got, want)
	}

}

// TestEnvironmentRootIsUnprefixed: the package root namespace is empty, so a component
// owns its whole prefix: Environment("CRYPTO", "CIPHER") reads CRYPTO_CIPHER_*.
func TestEnvironmentRootIsUnprefixed(t *testing.T) {
	t.Setenv("CRYPTO_CIPHER_KEYS", "qwerty")
	if got := env.Environment("CRYPTO", "CIPHER").Getenv("KEYS"); got != "qwerty" {
		t.Fatalf("Environment(CRYPTO, CIPHER).Getenv(KEYS) = %q, want %q", got, "qwerty")
	}
	if got := env.Getenv("CRYPTO_CIPHER_KEYS"); got != "qwerty" {
		t.Fatalf("Getenv(CRYPTO_CIPHER_KEYS) = %q, want %q", got, "qwerty")
	}
}

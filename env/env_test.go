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

	test.Setenv("WBTL_CRYPTO_CIPHER_KEYS", "qwerty")

	if got, want := testEnv.Getenv("CIPHER_KEYS"), "qwerty"; got != want {
		test.Errorf("sdk/env.Getenv: got %s, want %s", got, want)
	}

}

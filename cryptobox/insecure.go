package cryptobox

import "context"

type insecureCipher struct{}

// Insecure returns a Cipher that passes data through without any encryption.
// Intended for tests and environments where encryption is explicitly disabled.
func Insecure() Cipher { return insecureCipher{} }

func (insecureCipher) Encrypt(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (insecureCipher) Decrypt(_ context.Context, blob []byte) ([]byte, error) {
	return blob, nil
}

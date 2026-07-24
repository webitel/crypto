package cryptobox

import "errors"

var (

	// ErrFileDir indicates that the configured path points to the directory, not file.
	ErrFileDir = errors.New("cryptobox: expect file, not directory")

	ErrKeyNotFound  = errors.New("cryptobox: key version not in keyring")
	ErrKeyRetired   = errors.New("cryptobox: key is retired; re-encrypt data with Recrypt before removing")
	ErrBlobTooShort = errors.New("cryptobox: blob too short")
	ErrInvalidIKM   = errors.New("cryptobox: invalid key material")

	// ErrDecrypt reports that a blob whose key was resolved could not be authenticated:
	// the AEAD Open step failed. By design (an AEAD must not leak why) this does not
	// distinguish its causes — the key material behind the blob's KID no longer matches
	// what sealed it (a changed or wrong key), or the blob is corrupt/truncated/not a
	// cryptobox blob. Box.Decrypt wraps the algorithm's error under it, naming the KID;
	// match it with errors.Is and read the wrapped cause for the algorithm detail.
	ErrDecrypt = errors.New("cryptobox: decryption failed")
)

package cryptostore

import "errors"

// ErrIndexKey signals invalid or missing blind-index root key material.
var ErrIndexKey = errors.New("cryptostore: invalid blind index key")

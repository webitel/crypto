module github.com/webitel/crypto/cryptostore

go 1.25.0

// until there is no git remote ..
replace (
  github.com/webitel/crypto/env => ../env
  github.com/webitel/crypto/cryptobox => ../cryptobox
  github.com/webitel/crypto/encoding/jsonc => ../encoding/jsonc
)

require (
	github.com/webitel/crypto/cryptobox v0.0.0
	github.com/webitel/crypto/encoding/jsonc v0.0.0
	github.com/webitel/crypto/env v0.0.0
)

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

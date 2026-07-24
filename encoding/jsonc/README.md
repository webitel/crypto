# encoding/jsonc

JSONC (JSON with comments and trailing commas) → JSON, as a thin streaming layer
over `encoding/json`. **Zero external dependencies.**

For human-edited config files: comments document intent and let admins disable
whole blocks by commenting them out; a forgiving trailing comma avoids churn.

```go
dec := jsonc.NewDecoder(f) // f is an *os.File / io.Reader of JSONC
dec.DisallowUnknownFields()
var cfg Config
err := dec.Decode(&cfg)

// or, in one shot:
err = jsonc.Unmarshal(data, &cfg)
```

Supported over strict JSON:

- `//` line comments and `/* block comments */`
- a single trailing comma before `}` or `]`

The transform is **length-preserving**: each stripped comment byte and dropped
comma becomes a space (newlines inside comments are kept), so byte offsets and
line numbers survive into `encoding/json` error messages. Comment markers and
commas inside string literals are left untouched.

`jsonc.Reader` is the core `io.Reader`; `NewDecoder` and `Unmarshal` are
conveniences. `ToJSON` returns the plain-JSON translation of a byte slice.

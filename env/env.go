package env

import (
	"os"
	"strconv"
)

// module is the process-wide reader rooted at the global WBTL_ namespace. It backs the
// package-level Getenv, LookupEnv and Environment helpers.
var module = Options{
	Namespace: Name("WBTL"),
	LookupEnv: os.LookupEnv,
}

// sep separates namespace segments in a key: WBTL_CRYPTO_CIPHER_KEYS.
const sep = "_"

// Getenv returns the value of key within the global WBTL_ namespace, or "" if it is unset.
// It is shorthand for the package reader's [Options.Getenv].
func Getenv(key string) string {
	return module.Getenv(key)
}

// LookupEnv returns the value of key within the global WBTL_ namespace and whether it was
// set — the namespaced counterpart of [os.LookupEnv].
func LookupEnv(key string) (string, bool) {
	return module.Lookup(key)
}

// Environment returns an [Options] rooted at the global WBTL_ namespace, nested under the
// given segments: Environment("CRYPTO", "SEARCH") reads WBTL_CRYPTO_SEARCH_* keys. Build
// one per component and share it, so every lookup is consistently scoped.
func Environment(namespace ...string) Options {
	return Options{
		Namespace: module.Namespace.With(namespace...),
	}
}

// Options is a namespaced environment reader: it prepends Namespace to every looked-up
// key and reads it through LookupEnv (the process environment when LookupEnv is nil).
type Options struct {
	Namespace Name                        // key prefix, e.g. "WBTL_CRYPTO"
	LookupEnv func(string) (string, bool) // value source; nil falls back to os.LookupEnv
}

// WithNamespace returns a copy of env nested one or more segments deeper.
func (env Options) WithNamespace(name ...string) Options {
	env.Namespace = env.Namespace.With(name...)
	return env
}

// Lookup resolves key within env's namespace and returns its value and whether it was
// set. A nil LookupEnv reads the process environment. An empty resolved key returns
// ("", false).
func (env Options) Lookup(key string) (string, bool) {
	key = env.Namespace.Name(key)
	if key == "" {
		return "", false
	}
	read := env.LookupEnv
	if read == nil {
		read = os.LookupEnv // system
	}
	return read(key)
}

// Getenv returns the value of key within env's namespace, or "" if it is unset.
func (env Options) Getenv(key string) string {
	raw, _ := env.Lookup(key)
	return raw
}

// Option reads one namespaced value from an [Options] and delivers it to a callback. Use
// the type-specific constructors ([String], [Bool], …) and pass them to [Options.Apply].
type Option func(env Options)

// Apply runs each Option against env, reading all requested values in a single call.
func (env Options) Apply(opts ...Option) {
	for _, option := range opts {
		option(env)
	}
}

// String returns an [Option] that looks key up and passes its value to getenv, together
// with whether the key was set. A value that is a quoted Go string literal is unquoted
// first (via [strconv.Unquote]), so shell-escaped or whitespace-bearing values round-trip.
func String(key string, getenv func(text string, set bool)) Option {
	return func(env Options) {
		raw, set := env.Lookup(key)
		vs, err := strconv.Unquote(raw)
		if err == nil {
			raw = vs // unquoted
		}
		getenv(raw, set)
	}
}

// Bool returns an [Option] that looks key up and passes its boolean value to getenv. An
// unset key yields (false, NotFound); a set but unparseable value yields the
// [strconv.ParseBool] error.
func Bool(key string, getenv func(yes bool, err error)) Option {
	return String(key, func(raw string, set bool) {
		if !set {
			getenv(false, NotFound)
			return
		}
		getenv(strconv.ParseBool(raw))
	})
}

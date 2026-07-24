package schema

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/env"
)

// The Default* helpers (DefaultConfig, DefaultOptions) resolve their values from the
// environment (the WBTL_CRYPTO_* variables). Anything named Default* is "what we take
// as configuration by default, from the environment"; every other constructor input
// is explicit. See also cryptostore.Default (the env-resolved value codec).

// DefaultConfig loads the admin overlay schema from the environment, in precedence
// order:
//
//   - WBTL_CRYPTO_SCHEMA_FILE — a path to a single schema.Config file; else
//   - WBTL_CRYPTO_SCHEMA — an inline value decoded as an IncludeConfig: either an
//     inline schema.Config document ({"version":1,"units":{…}}) or an include
//     directive naming files to load and merge ({"dir":"schema.d","files":["a.json",
//     "b.json"]}). Relative dir/files anchor to SystemDir (cryptostore.SystemDir),
//     so a deployment that populates the system dir selects schema files by name
//     alone; absolute paths are used as-is. Dir defaults to "schema.d".
//
// It returns (nil, nil) when neither is set — no overlay, not an error. The result
// is meant to be merged onto a code baseline (see MergeConfig / WithOverlay).
func DefaultConfig() (*Config, error) {
	var inline, filename string
	// [WBTL_CRYPTO_SCHEMA][_FILE]
	cryptostore.Environment().Apply(
		env.String("SCHEMA", func(v string, _ bool) { inline = v }),
		env.String("SCHEMA_FILE", func(v string, _ bool) { filename = v }),
	)
	if filename != "" {
		return LoadConfigFile(filename)
	}
	if inline != "" {
		var inc IncludeConfig // inline schema.Config, or an {dir, files} include directive
		if err := json.Unmarshal([]byte(inline), &inc); err != nil {
			return nil, fmt.Errorf("cryptostore/schema: WBTL_CRYPTO_SCHEMA: %w", err)
		}
		return inc.Config(cryptostore.SystemDir())
	}
	return nil, nil
}

// Register merges c into the process-wide baseline — the immutable minimum field
// schema. It is meant for ops tooling (e.g. a cryptoctl build) to compile in the
// unconditionally-encrypted fields WITHOUT baking them into a storage driver (which
// would force them on every store of that kind, including third-party ones). A
// deployment imports a small package that calls Register in init(); the agent then
// merges Baseline() as the pinned base under any admin overlay, so the overlay can
// add fields or enable search but never relax the baseline.
//
// Services do NOT use this — they pass their baseline explicitly via WithBaseline.
// Multiple registrations are merged (MergeConfig).
func Register(baseline *Config) {
	if baseline == nil {
		return
	}
	registry.sync.Lock()
	defer registry.sync.Unlock()
	registry.base = MergeConfig(registry.base, baseline)
}

// Baseline returns the process-wide baseline registered via Register, or nil if none.
// Merge it as the base under an admin overlay: MergeConfig(Baseline(), overlay).
func Baseline() *Config {
	registry.sync.Lock()
	defer registry.sync.Unlock()
	return registry.base
}

// registry holds the process-wide baseline (see Register).
var registry = struct {
	sync sync.Mutex
	base *Config
}{}

// MustParseConfig is ParseConfig for a schema literal embedded in code — a service's
// baseline, describing the fixed set of known columns/attributes it encrypts. It
// panics if raw does not parse, turning a malformed baseline into a startup failure
// (a program bug) rather than a runtime error:
//
//	var baseline = schema.MustParseConfig(`{"version":1,"units":{
//	    "public.users": {"fields": {"ssn": {"search": true}}}}}`)
func MustParseConfig(raw string) *Config {
	c, err := ParseConfig([]byte(raw))
	if err != nil {
		panic("cryptostore/schema: MustParseConfig: " + err.Error())
	}
	return c
}

// codecOptions collects the NewCodec inputs.
type codecOptions struct {
	base     *cryptostore.Codec
	baseline *Config
	overlay  *Config
}

// CodecOption configures NewCodec. An option that resolves values from the
// environment (DefaultOptions) may fail; the error is returned by NewCodec.
type CodecOption func(*codecOptions) error

// WithBase supplies the base value codec. Use it in tests, to share one core across
// several codecs, or with any explicitly-built cryptostore.Codec.
func WithBase(codec *cryptostore.Codec) CodecOption {
	return func(o *codecOptions) error { o.base = codec; return nil }
}

// WithBaseline pins the immutable minimum schema — a service's code-defined set of
// fields that are always encrypted. An overlay is merged onto it but can never
// relax it (see MergeConfig).
func WithBaseline(baseline *Config) CodecOption {
	return func(o *codecOptions) error { o.baseline = baseline; return nil }
}

// WithOverlay merges an admin-provided overlay onto the baseline (see MergeConfig):
// the overlay — the per-installation "extra encryption" config — may add units and
// fields or turn on search, but the baseline is pinned and can never be relaxed.
// Load the overlay with LoadConfigFile / ParseConfig, or DefaultConfig for the env one.
func WithOverlay(overlay *Config) CodecOption {
	return func(o *codecOptions) error { o.overlay = overlay; return nil }
}

// DefaultOptions resolves the entire codec from the environment/process defaults:
// base = cryptostore.Default(), baseline = Baseline() (registered via Register),
// overlay = DefaultConfig() (WBTL_CRYPTO_SCHEMA[_FILE]). It is the one-call assembly
// for an ops tool or a service that takes everything from the environment:
//
//	codec, err := schema.NewCodec(schema.DefaultOptions())
//
// A service with its own code baseline overrides just that part (later options win):
//
//	codec, err := schema.NewCodec(schema.DefaultOptions(), schema.WithBaseline(baseline))
func DefaultOptions() CodecOption {
	return func(o *codecOptions) error {
		codec, err := cryptostore.Default()
		if err != nil {
			return err
		}
		overlay, err := DefaultConfig()
		if err != nil {
			return err
		}
		o.base = codec
		o.baseline = Baseline()
		o.overlay = overlay
		return nil
	}
}

// NewCodec assembles a field Codec from the given options. The active schema is
// MergeConfig(baseline, overlay); the baseline stays pinned so WatchConfig reloads
// the overlay without relaxing it. A base value codec is required — supply it with
// WithBase or DefaultOptions:
//
//	codec, err := schema.NewCodec(schema.WithBase(core), schema.WithBaseline(cfg))
//	codec, err := schema.NewCodec(schema.DefaultOptions())
//
// NewCodec never touches the environment on its own: env resolution is opt-in via
// the Default* options.
func NewCodec(opts ...CodecOption) (*Codec, error) {
	var o codecOptions
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if o.base == nil {
		return nil, fmt.Errorf("cryptostore/schema: NewCodec: no base codec (use WithBase or DefaultOptions)")
	}
	return buildCodec(o.base, o.baseline, o.overlay), nil
}

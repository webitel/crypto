package schema_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

// Environment variables read by DefaultConfig for the admin overlay schema.
// EnvOverlayFile (a path) takes precedence over EnvOverlay (inline JSON/JSONC),
// mirroring the *_FILE precedence of the cipher and search keyrings.
const (
	EnvOverlay     = "CRYPTO_SCHEMA"
	EnvOverlayFile = "CRYPTO_SCHEMA_FILE"
)

func TestMustParseConfig(t *testing.T) {
	s := schema.MustParseConfig(`{"version":1,"units":{"a.b":{"fields":{"x":{}}}}}`)
	if s.Unit("a.b").Field("x") == nil {
		t.Fatal("baseline field a.b.x missing")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("MustParseConfig did not panic on invalid input")
		}
	}()
	schema.MustParseConfig(`{"version":2}`) // unsupported version → panic
}

func testCodec(t *testing.T) *cryptostore.Codec {
	t.Helper()
	ring := mustParseRing(t, "correct-horse-battery-staple-001!")
	c, err := cryptostore.NewCodec(cryptobox.NewBox(cryptobox.ChaCha20Poly1305, ring), mustParseRing(t, indexRoot))
	if err != nil {
		t.Fatalf("New codec: %v", err)
	}
	return c
}

func mustDefaultConfig(t *testing.T) *schema.Config {
	t.Helper()
	cfg, err := schema.DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	return cfg
}

func TestNewCodecWithBase(t *testing.T) {
	base := testCodec(t)
	baseline := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.users": {"fields": {"email": {"search": true}}}}}`)
	overlay := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.orders": {"fields": {"card": {"search": true}}}}}`)

	codec, err := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(baseline), schema.WithOverlay(overlay))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if codec.Base() != base {
		t.Fatal("WithBase not honored")
	}
	// Baseline is preserved and the overlay is merged in.
	if codec.Schema().Unit("directory.users").Field("email") == nil {
		t.Fatal("baseline unit lost after merge")
	}
	if codec.Schema().Unit("directory.orders").Field("card") == nil {
		t.Fatal("overlay unit not merged")
	}
}

func TestNewCodecBaselinePinned(t *testing.T) {
	base := testCodec(t)
	// Baseline turns search ON for email; an overlay must not be able to relax it.
	baseline := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.users": {"fields": {"email": {"search": true}}}}}`)
	overlay := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.users": {"fields": {"email": {}}}}}`)

	codec, err := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(baseline), schema.WithOverlay(overlay))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if p := codec.Schema().Unit("directory.users").Field("email"); p == nil || !p.Search {
		t.Fatal("baseline search flag was relaxed by the overlay")
	}
}

func TestNewCodecNoEnvByDefault(t *testing.T) {
	base := testCodec(t)
	baseline := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.users": {"fields": {"phone": {}}}}}`)

	// An env overlay is set, but NewCodec never reads the environment on its own —
	// only the Default* options do. Without one, the env overlay must be ignored.
	t.Setenv(EnvOverlay, `{"version":1,"units":{"x.y":{"fields":{"z":{}}}}}`)
	codec, err := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(baseline))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if codec.Schema().Unit("directory.users").Field("phone") == nil {
		t.Fatal("baseline lost")
	}
	if codec.Schema().Unit("x.y") != nil {
		t.Fatal("env overlay applied without a Default* option")
	}
}

func TestDefaultConfigInline(t *testing.T) {
	base := testCodec(t)
	baseline := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.users": {"fields": {"email": {"search": true}}}}}`)
	t.Setenv(EnvOverlay, `{"version":1,"units":{
	    "directory.orders": {"fields": {"card": {"search": true}}}}}`)

	// DefaultConfig reads the inline env overlay; WithOverlay merges it onto the baseline.
	codec, err := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(baseline), schema.WithOverlay(mustDefaultConfig(t)))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if codec.Schema().Unit("directory.users").Field("email") == nil {
		t.Fatal("baseline unit lost")
	}
	if codec.Schema().Unit("directory.orders").Field("card") == nil {
		t.Fatal("inline env overlay not merged")
	}
}

func TestDefaultConfigFileWins(t *testing.T) {
	base := testCodec(t)
	baseline := schema.MustParseConfig(`{"version":1,"units":{
	    "directory.users": {"fields": {"email": {}}}}}`)

	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.jsonc")
	overlay := `{"version":1,"units":{
	    // per-installation extra encryption
	    "directory.cards": {"fields": {"pan": {"search": true}}}}}`
	if err := os.WriteFile(path, []byte(overlay), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	// _FILE wins over inline SCHEMA.
	t.Setenv(EnvOverlay, `{"version":1,"units":{"ignored.unit":{"fields":{"z":{}}}}}`)
	t.Setenv(EnvOverlayFile, path)

	codec, err := schema.NewCodec(schema.WithBase(base), schema.WithBaseline(baseline), schema.WithOverlay(mustDefaultConfig(t)))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if codec.Schema().Unit("directory.cards").Field("pan") == nil {
		t.Fatal("file overlay not merged")
	}
	if codec.Schema().Unit("ignored.unit") != nil {
		t.Fatal("inline SCHEMA applied despite SCHEMA_FILE being set")
	}
}

func TestDefaultConfigIncludeFiles(t *testing.T) {
	// CRYPTO_SCHEMA as an include directive: a selective list of files (not a
	// whole-dir merge). Relative files anchor to SystemDir/schema.d.
	sysdir := t.TempDir()
	t.Setenv("CRYPTO_DIR", sysdir)
	schemaDir := filepath.Join(sysdir, "schema.d")
	if err := os.MkdirAll(schemaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(schemaDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("directory.json", `{"version":1,"units":{"directory.users":{"fields":{"email":{"search":true}}}}}`)
	write("cases.json", `{"version":1,"units":{"cc.cases":{"fields":{"subject":{}}}}}`)
	// A third file exists but is NOT listed — it must not be merged (no whole-dir sweep).
	write("secrets.json", `{"version":1,"units":{"should.not.load":{"fields":{"x":{}}}}}`)

	t.Setenv(EnvOverlayFile, "")
	t.Setenv(EnvOverlay, `{"files":["directory.json","cases.json"]}`)

	cfg, err := schema.DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	if cfg == nil || cfg.Unit("directory.users").Field("email") == nil {
		t.Fatalf("listed file directory.json not merged: %+v", cfg)
	}
	if cfg.Unit("cc.cases").Field("subject") == nil {
		t.Fatal("listed file cases.json not merged")
	}
	if cfg.Unit("should.not.load") != nil {
		t.Fatal("unlisted file was merged (should be selective, not whole-dir)")
	}
}

func TestDefaultConfigInlineStillWorks(t *testing.T) {
	// An inline schema.Config (not an {dir,files} directive) is still accepted.
	t.Setenv(EnvOverlayFile, "")
	t.Setenv(EnvOverlay, `{"version":1,"units":{"a.b":{"fields":{"x":{"search":true}}}}}`)
	cfg, err := schema.DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	if cfg == nil || cfg.Unit("a.b").Field("x") == nil {
		t.Fatalf("inline schema.Config not parsed: %+v", cfg)
	}
}

func TestDefaultConfigUnset(t *testing.T) {
	t.Setenv(EnvOverlay, "")
	t.Setenv(EnvOverlayFile, "")
	s, err := schema.DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil overlay when env is unset")
	}
}

func TestNewCodecRequiresBase(t *testing.T) {
	if _, err := schema.NewCodec(); err == nil {
		t.Fatal("NewCodec with no base should error")
	}
}

func TestRegisterMergesBaseline(t *testing.T) {
	// Register accumulates into the process-wide baseline (union, never relax).
	schema.Register(schema.MustParseConfig(`{"version":1,"units":{
	    "reg.unit": {"fields": {"a": {"search": true}}}}}`))
	schema.Register(schema.MustParseConfig(`{"version":1,"units":{
	    "reg.unit": {"fields": {"b": {}}}}}`))

	b := schema.Baseline()
	if b == nil {
		t.Fatal("Baseline nil after Register")
	}
	if b.Unit("reg.unit").Field("a") == nil || b.Unit("reg.unit").Field("b") == nil {
		t.Fatalf("registered fields not merged: %+v", b.Unit("reg.unit"))
	}
	if p := b.Unit("reg.unit").Field("a"); !p.Search {
		t.Fatal("registered search flag lost")
	}
}

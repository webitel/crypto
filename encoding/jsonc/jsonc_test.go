package jsonc_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/webitel/crypto/encoding/jsonc"
)

// roundtrip parses src as JSONC and compares the decoded value to want (decoded
// from canonical JSON).
func roundtrip(t *testing.T, src, want string) {
	t.Helper()
	var got, exp any
	if err := jsonc.Unmarshal([]byte(src), &got); err != nil {
		t.Fatalf("Unmarshal(%q): %v\ntranslated: %q", src, err, jsonc.ToJSON([]byte(src)))
	}
	if err := json.Unmarshal([]byte(want), &exp); err != nil {
		t.Fatalf("want is not valid JSON: %v", err)
	}
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("src %q\n got: %#v\nwant: %#v", src, got, exp)
	}
}

func TestStripping(t *testing.T) {
	cases := []struct{ src, want string }{
		{`{"a":1}`, `{"a":1}`}, // passthrough
		{"{\n// a comment\n\"a\":1\n}", `{"a":1}`},
		{`{"a":1 /* inline */, "b":2}`, `{"a":1,"b":2}`},
		{`{"a":1,}`, `{"a":1}`},       // trailing comma, object
		{`[1, 2, 3,]`, `[1,2,3]`},     // trailing comma, array
		{`[1, 2 /* x */ ]`, `[1,2]`},  // comment before bracket
		{`[1, 2, /* x */ ]`, `[1,2]`}, // trailing comma then comment then bracket
		{`{"a": [1,2,], "b": {"c":3,},}`, `{"a":[1,2],"b":{"c":3}}`},
		{`["http://x", "a//b", "/* not */"]`, `["http://x","a//b","/* not */"]`}, // markers inside strings
		{`{"s":"he said \"hi,\" ok",}`, `{"s":"he said \"hi,\" ok"}`},            // escaped quote, comma in string
		{"// lead\n{\"a\":1}\n// trail", `{"a":1}`},
		{"{\n  \"a\": 1, // keep this comma's value\n  \"b\": 2,\n}", `{"a":1,"b":2}`},
	}
	for _, c := range cases {
		roundtrip(t, c.src, c.want)
	}
}

func TestLengthPreserved(t *testing.T) {
	src := "{\n  \"a\": 1, // note\n  /* blk */ \"b\": 2,\n}"
	out := jsonc.ToJSON([]byte(src))
	if len(out) != len(src) {
		t.Fatalf("length not preserved: src %d, out %d\n%q", len(src), len(out), out)
	}
	// Newlines must survive at the same positions (line numbers preserved).
	if strings.Count(string(out), "\n") != strings.Count(src, "\n") {
		t.Fatalf("newline count changed: %q", out)
	}
}

func TestDecoderDisallowUnknown(t *testing.T) {
	type cfg struct {
		A int `json:"a"`
	}
	dec := jsonc.NewDecoder(strings.NewReader(`{
	  "a": 1, // ok
	}`))
	dec.DisallowUnknownFields()
	var c cfg
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if c.A != 1 {
		t.Fatalf("a=%d", c.A)
	}

	dec = jsonc.NewDecoder(strings.NewReader(`{"a":1,"x":2}`))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestBlockCommentMultiline(t *testing.T) {
	src := "{\n/*\n multi\n line\n*/\n\"a\":1}"
	roundtrip(t, src, `{"a":1}`)
}

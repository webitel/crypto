package schema_test

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/webitel/crypto/cryptostore"
	"github.com/webitel/crypto/cryptostore/schema"
)

// encText encrypts v exactly the way the schema codec stores a nested attribute:
// EncryptText(json.Marshal(v)). The returned "cbox:" string is what DecryptJSONB
// must recognise and reverse, restoring v's native JSON type.
func encText(t *testing.T, base *cryptostore.Codec, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal leaf: %v", err)
	}
	s, err := base.EncryptText(context.Background(), b)
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	return s
}

// TestDecryptJSONBRoundTrip encrypts leaves at every structural position (top-level
// object, nested object, array element) and of every scalar type, then confirms
// DecryptJSONB restores each to its original value AND native JSON type — while
// leaving plaintext siblings untouched.
func TestDecryptJSONBRoundTrip(t *testing.T) {
	base := newCodec(t, "round-trip-passphrase@v1!!").Base()

	doc := map[string]any{
		"id":     42.0, // plaintext number (untouched)
		"active": true, // plaintext bool   (untouched)
		"note":   "hi", // plaintext string (untouched)
		"ssn":    encText(t, base, "123-45-6789"),
		"profile": map[string]any{
			"name":  "Ann",                            // plaintext
			"phone": encText(t, base, "+15551234567"), // encrypted, nested
			"score": encText(t, base, 9000.0),         // encrypted number → must come back as number
			"admin": encText(t, base, true),           // encrypted bool   → must come back as bool
		},
		"tokens": []any{"plain", encText(t, base, "secret-token"), true},
	}
	in, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	got, err := schema.DecryptJSONB(base, in)
	if err != nil {
		t.Fatalf("DecryptJSONB: %v", err)
	}

	want := map[string]any{
		"id":     42.0,
		"active": true,
		"note":   "hi",
		"ssn":    "123-45-6789",
		"profile": map[string]any{
			"name":  "Ann",
			"phone": "+15551234567",
			"score": 9000.0,
			"admin": true,
		},
		"tokens": []any{"plain", "secret-token", true},
	}
	var gotAny any
	if err := json.Unmarshal(got, &gotAny); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !reflect.DeepEqual(gotAny, want) {
		t.Fatalf("round-trip mismatch:\n got: %#v\nwant: %#v", gotAny, want)
	}
}

// TestDecryptJSONBTopLevelScalar covers a document that is itself a single encrypted
// string (no surrounding object/array).
func TestDecryptJSONBTopLevelScalar(t *testing.T) {
	base := newCodec(t, "scalar-passphrase@v1!!!!!!").Base()
	in, err := json.Marshal(encText(t, base, "just-a-secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.DecryptJSONB(base, in)
	if err != nil {
		t.Fatalf("DecryptJSONB: %v", err)
	}
	if string(got) != `"just-a-secret"` {
		t.Fatalf("top-level scalar = %s, want %q", got, `"just-a-secret"`)
	}
}

// TestDecryptJSONBUnchanged asserts that a document with nothing to decrypt is
// returned byte-for-byte (original formatting preserved, no needless re-marshal).
func TestDecryptJSONBUnchanged(t *testing.T) {
	base := newCodec(t, "plain-passphrase@v1!!!!!!!").Base()
	for _, in := range [][]byte{
		[]byte(`{ "a": 1,  "b": "plain", "c": [true, null] }`), // odd spacing must survive
		[]byte(`"a plain string"`),
		[]byte(`12345`),
		[]byte(`[1, 2, 3]`),
		[]byte(`null`), // JSON null → preserved
		[]byte(`{ }`),  // empty object → preserved, spacing intact
		nil,            // nil / empty input → nil
	} {
		got, err := schema.DecryptJSONB(base, in)
		if err != nil {
			t.Fatalf("DecryptJSONB(%s): %v", in, err)
		}
		if !bytes.Equal(got, in) {
			t.Fatalf("plaintext altered: got %s, want %s", got, in)
		}
	}
}

// TestDecryptJSONBForeignKey confirms that ciphertext this codec cannot open (sealed
// under a different key) is left tagged and in place, without an error — DecryptJSONB
// is best-effort and never leaks a decrypt failure as a hard error.
func TestDecryptJSONBForeignKey(t *testing.T) {
	base := newCodec(t, "our-own-passphrase@v1!!!!!").Base()
	foreign := newCodec(t, "someone-elses-passphrase@v9").Base()

	in, err := json.Marshal(map[string]any{
		"mine":    encText(t, base, "readable"),
		"foreign": encText(t, foreign, "unreadable-here"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.DecryptJSONB(base, in)
	if err != nil {
		t.Fatalf("DecryptJSONB: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["mine"] != "readable" {
		t.Fatalf("own field not decrypted: %v", m["mine"])
	}
	// foreign value stays exactly the "cbox:" string it went in as.
	s, ok := m["foreign"].(string)
	if !ok || !isCboxTagged(s) {
		t.Fatalf("foreign ciphertext should be left tagged, got %v", m["foreign"])
	}
}

// TestDecryptJSONBInvalid confirms malformed JSON surfaces an error (and returns the
// input unchanged).
func TestDecryptJSONBInvalid(t *testing.T) {
	base := newCodec(t, "any-passphrase@v1!!!!!!!!!").Base()
	in := []byte(`{"a": }`)
	got, err := schema.DecryptJSONB(base, in)
	if err == nil {
		t.Fatal("want error for malformed JSON")
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("on error input should be returned unchanged: %s", got)
	}
}

func isCboxTagged(s string) bool { return len(s) >= 5 && s[:5] == "cbox:" }

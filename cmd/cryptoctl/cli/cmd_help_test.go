package cli

import (
	"strings"
	"testing"

	"github.com/webitel/crypto/cryptostore"
)

// TestKeysTopicShowsSystemDir: the keys guide names the effective SystemDir, so a build
// with a baked-in default (-ldflags -X …cryptobox.defaultSystemDir) documents its own path.
func TestKeysTopicShowsSystemDir(t *testing.T) {
	keys, ok := lookupTopic("keys")
	if !ok {
		t.Fatal(`lookupTopic("keys") not found`)
	}
	if dir := cryptostore.SystemDir(); !strings.Contains(keys.long, dir) {
		t.Fatalf("keys topic does not mention SystemDir %q:\n%s", dir, keys.long)
	}
}

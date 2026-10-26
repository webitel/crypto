package cryptobox

import (
	"testing"
	"time"
)

// TestParseKeyFilePoll covers CRYPTO_CIPHER_KEYFILE_POLL parsing: unset/zero disable
// the watch, a sub-minimum positive value is clamped up to MinKeyFilePoll, and a negative
// or malformed value is a loud error (never a silent "watch off").
func TestParseKeyFilePoll(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "unset", in: "", want: 0},
		{name: "explicit zero", in: "0s", want: 0},
		{name: "bare zero", in: "0", want: 0},
		{name: "above min", in: "5s", want: 5 * time.Second},
		{name: "at min", in: "1s", want: MinKeyFilePoll},
		{name: "below min clamps up", in: "10ms", want: MinKeyFilePoll},
		{name: "sub-second clamps up", in: "500ms", want: MinKeyFilePoll},
		{name: "large", in: "1h", want: time.Hour},
		{name: "negative", in: "-1s", wantErr: true},
		{name: "malformed", in: "5", wantErr: true}, // no unit
		{name: "garbage", in: "soon", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyFilePoll(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseKeyFilePoll(%q) = %v, want error", tt.in, got)
				}
				if got != 0 {
					t.Errorf("parseKeyFilePoll(%q) returned %v on error, want 0", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKeyFilePoll(%q) failed: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseKeyFilePoll(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

package cryptobox

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DefaultPollInterval is the file-change polling interval a KeyFile uses when its Poll is
// zero. It is a var so tests can lower it for fast reloads.
var DefaultPollInterval = 5 * time.Second

// KeyFile tracks a keyring file: its path, polling throttle, and reload state. Load
// respects the Poll interval to avoid hammering the filesystem on rapid calls; Watch
// starts a background goroutine that polls and reloads on mtime change.
type KeyFile struct {
	Name string        // required — absolute path to the keyring file
	Poll time.Duration // minimum interval between reload attempts; 0 uses DefaultPollInterval

	mu       sync.Mutex
	modTime  time.Time
	loadTime time.Time
	loadErr  error
}

// Err returns the error from the most recent Load attempt, nil if last load succeeded.
func (fd *KeyFile) Err() error {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.loadErr
}

func (fd *KeyFile) poll() time.Duration {
	if fd.Poll > 0 {
		return fd.Poll
	}
	return DefaultPollInterval
}

// Load reads the file (fd.Name) into ring, respecting the Poll throttle and mtime guard.
//
// Returns (true, nil) when the ring was updated, (false, nil) when nothing
// changed (throttled or same mtime), and (false, err) on any failure.
// On failure the ring state is never modified.
func (fd *KeyFile) Load(ring *Keyring) (changed bool, err error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	if time.Since(fd.loadTime) < fd.poll() {
		return false, fd.loadErr
	}
	fd.loadTime = time.Now()

	info, err := os.Stat(fd.Name)
	if err != nil {
		fd.loadErr = err
		return false, err
	}
	if info.IsDir() {
		fd.loadErr = ErrFileDir
		return false, ErrFileDir
	}
	if info.ModTime().Equal(fd.modTime) {
		fd.loadErr = nil
		return false, nil
	}

	// Audit the file's permissions on every real (re)load — the mtime guard above means
	// this runs on the initial load and on each change, not on throttled/no-op polls.
	if err := canTrustKeyFile(fd.Name, info); err != nil {
		fd.loadErr = err
		return false, err
	}

	data, err := os.ReadFile(fd.Name)
	if err != nil {
		fd.loadErr = err
		return false, err
	}
	if err := ring.Load(strings.TrimSpace(string(data))); err != nil {
		fd.loadErr = err
		return false, err
	}

	fd.modTime = info.ModTime()
	fd.loadErr = nil
	return true, nil
}

// Watch polls the file every poll() and calls Load on each tick.
// The initial load runs immediately in the goroutine before the first tick.
// Errors are forwarded to the returned buffered channel (capacity 1);
// if the channel is full, stale errors are dropped.
// The channel is closed when ctx is done.
func (fd *KeyFile) Watch(ctx context.Context, keys *Keyring) <-chan error {
	errc := make(chan error, 1)
	send := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}
	go func() {
		defer close(errc)
		if _, err := fd.Load(keys); err != nil {
			send(err)
		}
		t := time.NewTicker(fd.poll())
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				{
					ok, err := fd.Load(keys)
					if ok || err != nil {
						// <nil> error indicates that
						// [keys] was successfully updated
						send(err)
					}
				}
			}
		}
	}()
	return errc
}

// KeyFilePolicy decides whether a key file's permissions are acceptable before cryptobox
// reads it. It runs for every key file loaded from disk — the keyring file behind
// WBTL_CRYPTO_CIPHER_KEYFILE / WBTL_CRYPTO_SEARCH_KEYFILE (and the well-known
// <SystemDir>/.cipher and .search), plus each /path key referenced inside a keyring.
//
// A non-nil return rejects the file: the load fails with that error. nil accepts it. The
// default is KeyFileRequirePrivate (strict), overridable from the environment:
//
//	WBTL_CRYPTO_KEYFILE_POLICY=strict → KeyFileRequirePrivate   (default; also the empty value)
//	WBTL_CRYPTO_KEYFILE_POLICY=unsafe → KeyFileWarnUnlessPrivate (log a warning, load anyway)
//
// "off" is deliberately NOT reachable from the environment — turning the check off
// entirely is a code decision: cryptobox.KeyFilePolicy = nil. Assign the var to either
// ready policy, nil, or your own func (ownership, audit, KMS attestation, …). path is the
// file path; info is its os.Stat result (symlinks already resolved). Only file-sourced
// keys reach here — inline keyrings and environment values are not checked.
var KeyFilePolicy = keyFilePolicyFromEnv()

// keyFilePolicyFromEnv resolves the default policy from WBTL_CRYPTO_KEYFILE_POLICY.
// Only "unsafe" relaxes the check; everything else — the empty value and any typo alike —
// fails safe to strict, so a misspelled value can never silently weaken security.
func keyFilePolicyFromEnv() func(path string, info os.FileInfo) error {
	if strings.EqualFold(mod.env.Getenv("KEYFILE_POLICY"), "unsafe") {
		return KeyFileWarnUnlessPrivate // mode: unsafe
	}
	return KeyFileRequirePrivate // mode: strict
}

// keyFilePrivacyViolation reports why a key file's mode is not private, or "" when it is.
// Not private: any world (other) access, or group-write — anyone but the owner could then read
// or swap the key. Group-READ is tolerated: it is the standard, safe way to hand a secret to a
// non-root container (Kubernetes fsGroup → 0640/0440), where owner-only 0600 would leave
// the process unable to read its own key. Private modes: 0600, 0400, 0640, 0440. POSIX
// mode bits are meaningless on Windows, so nothing is flagged there.
func keyFilePrivacyViolation(mode fs.FileMode) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	switch perm := mode.Perm(); {
	case perm&0o004 != 0:
		return "world-readable"
	case perm&0o002 != 0:
		return "world-writable"
	case perm&0o020 != 0:
		return "group-writable"
	}
	return ""
}

// KeyFileWarnUnlessPrivate logs a warning via slog (the default logger) when a key file is
// not private, but loads it anyway. Select it with WBTL_CRYPTO_KEYFILE_POLICY=unsafe.
func KeyFileWarnUnlessPrivate(path string, info os.FileInfo) error {
	if reason := keyFilePrivacyViolation(info.Mode()); reason != "" {
		slog.Warn("cryptobox: key file is not private",
			"path", path,
			"mode", info.Mode().Perm().String(),
			"reason", reason,
			"want", "0600 (or 0640/0440 for a shared group)")
	}
	return nil
}

// KeyFileRequirePrivate rejects a key file that is not private. It is the default policy.
func KeyFileRequirePrivate(path string, info os.FileInfo) error {
	if reason := keyFilePrivacyViolation(info.Mode()); reason != "" {
		return fmt.Errorf("cryptobox: key file %s is not private: %s (mode %s); want 0600 (or 0640/0440 for a shared group)",
			path, reason, info.Mode().Perm().String())
	}
	return nil
}

// canTrustKeyFile applies KeyFilePolicy (a nil policy — the code-only "off" — is a no-op).
func canTrustKeyFile(path string, info os.FileInfo) error {
	if KeyFilePolicy == nil {
		return nil // mode: OFF
	}
	return KeyFilePolicy(path, info)
}

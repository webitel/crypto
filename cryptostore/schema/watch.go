package schema

import (
	"context"
	"os"
	"time"
)

// watchPollInterval is how often WatchConfig restats the file. It mirrors
// cryptobox's keyring watch cadence so a Kubernetes ConfigMap update is picked up
// within one interval.
const watchPollInterval = 5 * time.Second

// WatchConfig watches a schema file and hot-reloads it into the codec without a
// restart. It loads once on start, then restats every watchPollInterval and
// reloads on mtime change, merging with any baseline (see SetBaseline) and
// swapping atomically. On a failed reload the previous schema is kept and the
// next tick retries; the error is delivered (non-blocking) on the returned
// channel, which is closed when ctx is done.
func (c *Codec) WatchConfig(ctx context.Context, path string) <-chan error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)

		var modTime time.Time
		reload := func() {
			info, err := os.Stat(path)
			if err != nil {
				sendErr(errc, err)
				return
			}
			if info.ModTime().Equal(modTime) {
				return
			}
			s, err := LoadConfigFile(path)
			if err != nil {
				sendErr(errc, err)
				return
			}
			modTime = info.ModTime()
			c.setConfig(s)
		}

		reload()
		t := time.NewTicker(watchPollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reload()
			}
		}
	}()
	return errc
}

func sendErr(errc chan<- error, err error) {
	select {
	case errc <- err:
	default:
	}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/webitel/crypto/cryptobox"
	"github.com/webitel/crypto/cryptostore"
)

// cmdStatus prints a configuration summary — the registered store drivers and the
// managed stores — then the per-key usage (via cmdUsage).
func cmdStatus(ctx context.Context, stores []cryptostore.Store, mig *cryptostore.Migration) error {
	fmt.Printf("drivers: %v\n", cryptostore.Schemes())
	fmt.Printf("stores (%d):\n", len(stores))
	for _, s := range stores {
		fmt.Printf("  - %s\n", s.Name())
	}
	fmt.Println()
	return cmdUsage(ctx, mig)
}

// cmdUsage scans each store once (UsageByStore), printing its per-key share as it
// goes, and folds the combined total in memory (AggregateUsage) — so the aggregate
// is reported without a second pass over the stores.
func cmdUsage(ctx context.Context, mig *cryptostore.Migration) error {
	byStore, err := mig.UsageByStore(ctx)
	if err != nil {
		return err
	}
	for _, su := range byStore {
		fmt.Printf("%s:\n", su.Store)
		printUsage(su.Keys)
		fmt.Println()
	}
	// total: per-key aggregation
	fmt.Println("usage:")
	printUsage(mapToSlice(cryptostore.AggregateUsage(byStore)))
	return nil
}

// migrateFlags registers the migrate command's flags on fs (shared by cmdMigrate and
// `help migrate`, so the definitions live in one place).
func migrateFlags(fs *flag.FlagSet) (dry *bool, batch, rate *int) {
	dry = fs.Bool("dry-run", false, "only count what would be re-encrypted")
	batch = fs.Int("batch", 0, "values per batch (0 = store default)")
	rate = fs.Int("rate", 0, "max values/sec (0 = unlimited)")
	return
}

// cmdMigrate re-encrypts data to the primary key across all stores, batched and
// resumable. Flags: --dry-run (only count), --batch (values per batch), --rate
// (max values/sec). It renders a live progress line on stderr (except --dry-run),
// then prints a per-store SCANNED/RECRYPTED/REMAINING table.
func cmdMigrate(ctx context.Context, mig *cryptostore.Migration, args []string) error {
	cmd := flag.NewFlagSet("migrate", flag.ExitOnError)
	dry, batch, rate := migrateFlags(cmd)
	_ = cmd.Parse(args)

	req := cryptostore.MigrateOptions{BatchSize: *batch, RatePerSec: *rate, DryRun: *dry}
	if !*dry {
		req.OnProgress = newProgress()
	}
	results, err := mig.Run(ctx, req)
	finishProgress(req.OnProgress)
	if err != nil {
		return err
	}
	w := newTab()
	fmt.Fprintln(w, "STORE\tSCANNED\tRECRYPTED\tREMAINING")
	for _, this := range results {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\n", this.Store, this.Scanned, this.Recrypted, this.Remaining)
	}
	return w.Flush()
}

// cmdCanRetire reports whether a key (by KID) still holds data. It reads the per-key
// usage directly (rather than Migration.CanRetire) so it can print the exact count of
// values still under a non-retirable key.
func cmdCanRetire(ctx context.Context, mig *cryptostore.Migration, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: can-retire <kid>")
	}
	v, err := strconv.ParseUint(args[0], 0, 16)
	if err != nil {
		return fmt.Errorf("invalid kid %q: %w", args[0], err)
	}
	kid := cryptobox.KID(v)
	usage, err := mig.Usage(ctx)
	if err != nil {
		return err
	}
	n := usage[kid].Count
	if n == 0 {
		fmt.Printf("kid %d: safe to retire (no data under it)\n", kid)
		return nil
	}
	fmt.Printf("kid %d: NOT safe to retire — %d values still under it; run `migrate` first\n", kid, n)
	return nil
}

// --- output helpers -------------------------------------------------------------

func newTab() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
}

func mapToSlice(m map[cryptobox.KID]cryptostore.KeyUsage) []cryptostore.KeyUsage {
	out := make([]cryptostore.KeyUsage, 0, len(m))
	for _, u := range m {
		out = append(out, u)
	}
	return out
}

func printUsage(rows []cryptostore.KeyUsage) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].KID < rows[j].KID })
	if len(rows) == 0 {
		fmt.Println("  (no data)")
		return
	}
	w := newTab()
	fmt.Fprintln(w, "  KID\tCOUNT")
	for _, u := range rows {
		fmt.Fprintf(w, "  %d\t%d\n", u.KID, u.Count)
	}
	w.Flush()
}

// newProgress returns a cryptostore progress callback that renders a single,
// live-updating line on stderr, throttled to ~10 repaints/sec. Call
// finishProgress with the same callback to terminate the line before printing
// results to stdout.
func newProgress() func(cryptostore.Progress) {
	var last time.Time
	return func(p cryptostore.Progress) {
		final := p.Total >= 0 && p.Done >= p.Total
		now := time.Now()
		if !final && now.Sub(last) < 100*time.Millisecond {
			return
		}
		last = now
		label := p.Store
		if p.Field != "" {
			label += " " + p.Unit + "." + p.Field
		}
		if p.Total >= 0 {
			pct := 0.0
			if p.Total > 0 {
				pct = 100 * float64(p.Done) / float64(p.Total)
			}
			fmt.Fprintf(os.Stderr, "\r\033[K%s: %d/%d (%.0f%%)", label, p.Done, p.Total, pct)
		} else {
			fmt.Fprintf(os.Stderr, "\r\033[K%s: %d", label, p.Done)
		}
	}
}

// finishProgress terminates a live progress line (no-op if pr is nil).
func finishProgress(pr func(cryptostore.Progress)) {
	if pr != nil {
		fmt.Fprintln(os.Stderr)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

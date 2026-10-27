package cli

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"text/tabwriter"
)

// cmdVersion prints the binary's version and build metadata in Go module form. It reads
// the info the toolchain embeds (runtime/debug.ReadBuildInfo) — no -ldflags needed:
// `go build` / `go install` stamp the module version and, from a source tree, the VCS
// revision, commit time, and dirty flag.
func cmdVersion(args []string) error {
	writeVersion(os.Stdout)
	return nil
}

func writeVersion(w io.Writer) {
	fmt.Fprintln(w)       // leading blank line: set the block off from the prompt
	defer fmt.Fprintln(w) // trailing blank line

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Fprintln(w, "cryptoctl: build info unavailable")
		return
	}

	// Module version: a tag/pseudo-version when installed with `go install …@version`,
	// else "(devel)" for a plain `go build`.
	version := bi.Main.Version
	if version == "" {
		version = "(devel)"
	}
	fmt.Fprintf(w, "cryptoctl %s\n", version)

	settings := map[string]string{}
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  module\t%s\n", bi.Main.Path)
	fmt.Fprintf(tw, "  go\t%s\n", bi.GoVersion)
	if rev := settings["vcs.revision"]; rev != "" {
		if settings["vcs.modified"] == "true" {
			rev += " (modified)"
		}
		fmt.Fprintf(tw, "  revision\t%s\n", rev)
	}
	if t := settings["vcs.time"]; t != "" {
		fmt.Fprintf(tw, "  built\t%s\n", t)
	}
	tw.Flush()
}

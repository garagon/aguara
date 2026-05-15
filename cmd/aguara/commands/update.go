package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/osvimport"
	"github.com/spf13/cobra"
)

var (
	flagUpdateTimeout    time.Duration
	flagUpdateEcosystems []string
	flagUpdateAllowEmpty bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Refresh the local threat-intel snapshot from OSV.dev",
	Long: `Refresh Aguara's local threat-intel snapshot. Downloads OSV.dev
malicious-package dumps for the configured ecosystems (default: npm, PyPI),
filters to high-confidence records, and writes the merged snapshot to
~/.aguara/intel/snapshot.json.

This command is the only place 'aguara update' touches the network. Default
'aguara check' invocations stay offline; future checks will consult the local
snapshot in addition to the binary's embedded snapshot.

This command updates THREAT INTEL only. It does not update the Aguara binary.`,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().DurationVar(&flagUpdateTimeout, "timeout", intel.DefaultHTTPTimeout, "Overall HTTP timeout for the refresh")
	updateCmd.Flags().StringSliceVar(&flagUpdateEcosystems, "ecosystem", nil, "Ecosystems to refresh (default: npm, PyPI)")
	updateCmd.Flags().BoolVar(&flagUpdateAllowEmpty, "allow-empty", false, "Save a 0-record snapshot anyway (defaults to error so an upstream outage cannot wipe cached intel)")
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	store, err := intel.DefaultStore()
	if err != nil {
		return fmt.Errorf("aguara update: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), flagUpdateTimeout)
	defer cancel()

	progress := io.Writer(os.Stderr)
	if flagNoColor {
		// flagNoColor doubles as a "machine-readable mode"
		// hint set by --ci; suppressing progress keeps the
		// stderr clean for log scrapers.
		progress = io.Discard
	}

	res, err := intel.Update(ctx, intel.UpdateOptions{
		Ecosystems: flagUpdateEcosystems,
		Importer:   osvImporterAdapter,
		Stderr:     progress,
	})
	if err != nil {
		return fmt.Errorf("aguara update: %w", err)
	}

	// Refuse to overwrite the local cache with an empty snapshot.
	// Zero records here usually means OSV served a syntactically
	// valid but empty/malformed dump, or an upstream schema shift
	// made the importer drop every record. Saving in that
	// scenario silently wipes whatever intel the user had cached;
	// preserving the previous snapshot until the next successful
	// refresh is the safer default. --allow-empty exists for the
	// initial bootstrap case where the maintainer explicitly
	// wants the empty file written.
	if len(res.Snapshot.Records) == 0 && !flagUpdateAllowEmpty {
		return fmt.Errorf("aguara update: refresh produced 0 records; refusing to overwrite cached intel (pass --allow-empty to save anyway)")
	}

	if err := store.Save(res.Snapshot); err != nil {
		return fmt.Errorf("aguara update: save snapshot: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Aguara threat intel updated\n")
	for _, eco := range res.PerEcosystem {
		fmt.Fprintf(os.Stdout, "  %-8s -> %d records\n", eco.Ecosystem, eco.RecordsKept)
	}
	fmt.Fprintf(os.Stdout, "  Written: %s\n", store.Dir+"/snapshot.json")
	return nil
}

// osvImporterAdapter bridges intel.UpdateOptions.Importer (an
// internal-only func type) to osvimport.ImportFromZip. The bridge
// exists so the intel package does not import osvimport (which
// would create a cycle: intel imports osvimport which imports
// intel).
func osvImporterAdapter(r io.ReaderAt, size int64, ecosystems []string, generatedAt time.Time) (intel.Snapshot, error) {
	return osvimport.ImportFromZip(r, size, osvimport.Options{
		Ecosystems:  ecosystems,
		GeneratedAt: generatedAt,
	})
}

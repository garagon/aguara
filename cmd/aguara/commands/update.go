package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

Pass --ecosystem to refresh additional ecosystems. Supported (with
case-insensitive aliases in parentheses): npm, PyPI (python),
Go (golang), crates.io (cargo, rust), Packagist (php, composer),
RubyGems (ruby, gem), Maven (java), NuGet (dotnet, csharp). Repeat
--ecosystem or comma-separate the values to refresh several at once.

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
	// Runtime errors (HTTP failures, OSV outage producing 0
	// records) should not trigger Cobra's flag-usage block. Same
	// rationale as scan / check / audit.
	updateCmd.SilenceUsage = true
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	store, err := intel.DefaultStore()
	if err != nil {
		return fmt.Errorf("aguara update: %w", err)
	}

	// Guard: -o must not point at the snapshot path the store
	// is about to write. The Save happens BEFORE the output
	// writer runs, so without this check `aguara update -o
	// ~/.aguara/intel/snapshot.json` would first write the real
	// refreshed snapshot and then truncate the same file to a
	// terminal/JSON summary -- silently corrupting the cache.
	// Future offline checks would then fail to Load the snapshot
	// and fall back to the embedded data without telling the
	// user the refresh effectively disappeared.
	if err := assertOutputNotShadowingStore(flagOutput, store.Dir); err != nil {
		return err
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

	return writeUpdateOutput(res, store.Dir)
}

// updateOutput is the JSON-stable shape `aguara update --format json`
// emits. Field names match the snake_case scheme the rest of the JSON
// surface uses; the array is always non-nil so consumers parsing it
// in a typed language see []byte / [] cleanly.
type updateOutput struct {
	SnapshotPath string                  `json:"snapshot_path"`
	Records      int                     `json:"records"`
	GeneratedAt  time.Time               `json:"generated_at"`
	PerEcosystem []updateEcosystemOutput `json:"per_ecosystem"`
}

type updateEcosystemOutput struct {
	Ecosystem    string    `json:"ecosystem"`
	RecordsKept  int       `json:"records_kept"`
	BytesRead    int64     `json:"bytes_read"`
	DownloadedAt time.Time `json:"downloaded_at"`
}

// writeUpdateOutput dispatches between the JSON and terminal
// writers based on the global --format flag. The -o flag, when
// present, redirects EITHER format to a file; otherwise both go to
// stdout. Stderr is untouched so the per-ecosystem progress line
// the intel.Update Stderr hook prints stays visible regardless of
// --format. Network failures error out before this function is
// called, so this path is offline-only.
func writeUpdateOutput(res *intel.UpdateResult, storeDir string) error {
	snapshotPath := filepath.Join(storeDir, "snapshot.json")

	if strings.ToLower(flagFormat) == "json" {
		return writeUpdateJSON(res, snapshotPath)
	}
	return writeUpdateTerminal(res, snapshotPath)
}

func writeUpdateJSON(res *intel.UpdateResult, snapshotPath string) error {
	out := updateOutput{
		SnapshotPath: snapshotPath,
		Records:      len(res.Snapshot.Records),
		GeneratedAt:  res.Snapshot.GeneratedAt,
		PerEcosystem: make([]updateEcosystemOutput, 0, len(res.PerEcosystem)),
	}
	for _, eco := range res.PerEcosystem {
		out.PerEcosystem = append(out.PerEcosystem, updateEcosystemOutput{
			Ecosystem:    eco.Ecosystem,
			RecordsKept:  eco.RecordsKept,
			BytesRead:    eco.BytesRead,
			DownloadedAt: eco.DownloadedAt,
		})
	}

	w := io.Writer(os.Stdout)
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("aguara update: write --output: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeUpdateTerminal(res *intel.UpdateResult, snapshotPath string) error {
	w := io.Writer(os.Stdout)
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("aguara update: write --output: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	fmt.Fprintf(w, "Aguara threat intel updated\n")
	for _, eco := range res.PerEcosystem {
		fmt.Fprintf(w, "  %-8s -> %d records\n", eco.Ecosystem, eco.RecordsKept)
	}
	fmt.Fprintf(w, "  Written: %s\n", snapshotPath)
	return nil
}

// assertOutputNotShadowingStore returns an error if flagOutput
// would resolve to the same on-disk file the intel.Store writes
// the snapshot to. Compared by canonical absolute path so a
// relative -o (or one with redundant separators) is caught.
//
// On case-insensitive filesystems (macOS HFS+/APFS, Windows
// NTFS), `Snapshot.JSON` and `snapshot.json` resolve to the same
// file even though the bytes differ; we fold case for the
// comparison so the corruption guard fires for that scenario
// too. Linux's ext4/xfs are case-sensitive by default and the
// byte-for-byte compare is correct there; the case-fold path
// stays gated on runtime.GOOS so we do not over-reject.
//
// Symlink shenanigans across the two paths are still out of
// scope (a user who sets up a symlink farm pointing -o at the
// snapshot has asked for trouble).
//
// Returns nil for the common case (no -o, or -o pointing
// anywhere other than the snapshot path) so the rest of the
// happy path stays untouched.
func assertOutputNotShadowingStore(out, storeDir string) error {
	if out == "" {
		return nil
	}
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return nil // can't normalise; let the open() below fail with a real message
	}
	storeAbs, err := filepath.Abs(filepath.Join(storeDir, "snapshot.json"))
	if err != nil {
		return nil
	}
	if pathsCollide(filepath.Clean(outAbs), filepath.Clean(storeAbs)) {
		return fmt.Errorf("aguara update: --output %s would overwrite the threat-intel snapshot the command just wrote; pick a different path (the snapshot already lives there)", out)
	}
	return nil
}

// pathsCollide reports whether two canonical absolute paths
// resolve to the same on-disk file under the host's filesystem
// rules. macOS and Windows default to case-insensitive lookups,
// so `Snapshot.JSON` and `snapshot.json` open the same file even
// though the bytes differ. Linux ext4/xfs are case-sensitive by
// default and the byte compare is sufficient there.
func pathsCollide(a, b string) bool {
	if a == b {
		return true
	}
	if isCaseInsensitiveFS() && strings.EqualFold(a, b) {
		return true
	}
	return false
}

// isCaseInsensitiveFS reports whether the host's default
// filesystem treats paths case-insensitively. macOS APFS CAN be
// created case-sensitive, but the default (and the format every
// homebrew/installer assumes) is case-insensitive; treating both
// macOS and Windows as case-insensitive is the defensive choice
// vs running data-corruption risk for the small minority of
// case-sensitive macOS volumes.
func isCaseInsensitiveFS() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	default:
		return false
	}
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

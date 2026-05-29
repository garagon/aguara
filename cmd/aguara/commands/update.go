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
	"github.com/spf13/cobra"
)

var (
	flagUpdateTimeout    time.Duration
	flagUpdateEcosystems []string
	flagUpdateAllowEmpty bool
	flagUpdateInsecure   bool
)

// defaultIntelBundleBaseURL is where the signed advisory-intel bundle is
// published by the intel-publish workflow (a rolling prerelease). The
// three assets live directly under it: the gzipped snapshot blob, the
// manifest, and the manifest's Sigstore bundle.
const defaultIntelBundleBaseURL = "https://github.com/garagon/aguara/releases/download/intel-latest"

// intelBundleBaseURL is overridable so tests can point the fetch at a
// local httptest server.
var intelBundleBaseURL = defaultIntelBundleBaseURL

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Refresh the local threat-intel snapshot from Aguara's signed bundle",
	Long: `Refresh Aguara's local threat-intel snapshot. Downloads the latest
Aguara-signed advisory bundle, verifies its Sigstore signature against
the expected publisher identity and the manifest against the blob, and
only then writes the snapshot to ~/.aguara/intel/snapshot.json.

The bundle is produced from OSV.dev by the intel-publish workflow and
signed there; the update command only trusts a verified, signed bundle
and does not fetch OSV directly. A bundle that fails verification is not
used. 'aguara check --fresh' and 'aguara audit --fresh' use the same
verified bundle.

This command is the only place 'aguara update' touches the network.
Default 'aguara check' invocations stay offline.

This command updates THREAT INTEL only. It does not update the Aguara binary.`,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().DurationVar(&flagUpdateTimeout, "timeout", intel.DefaultHTTPTimeout, "Overall HTTP timeout for the refresh")
	// --ecosystem is retained for backward compatibility but ignored:
	// the published bundle is a single signed artifact covering every
	// supported ecosystem, so a partial fetch is not possible.
	updateCmd.Flags().StringSliceVar(&flagUpdateEcosystems, "ecosystem", nil, "Ignored: the signed bundle covers all supported ecosystems (a partial fetch is not possible)")
	updateCmd.Flags().BoolVar(&flagUpdateAllowEmpty, "allow-empty", false, "Save a 0-record snapshot anyway (defaults to error so a bad publish cannot wipe cached intel)")
	updateCmd.Flags().BoolVar(&flagUpdateInsecure, "insecure-intel", false, "Skip advisory-bundle signature verification (also requires AGUARA_INSECURE_INTEL=1; mirrors / air-gapped / tests only; manifest + blob digests are still checked)")
	// Runtime errors (HTTP failures, verification failures) should not
	// trigger Cobra's flag-usage block. Same rationale as scan / check.
	updateCmd.SilenceUsage = true
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	store, err := intel.DefaultStore()
	if err != nil {
		return fmt.Errorf("aguara update: %w", err)
	}

	// Guard: -o must not point at the snapshot path the store is about
	// to write (see assertOutputNotShadowingStore).
	if err := assertOutputNotShadowingStore(flagOutput, store.Dir); err != nil {
		return err
	}

	if len(flagUpdateEcosystems) > 0 {
		fmt.Fprintln(os.Stderr, "aguara update: --ecosystem is ignored for signed bundles; the published bundle covers all supported ecosystems")
	}

	insecure, err := resolveInsecureIntel(flagUpdateInsecure)
	if err != nil {
		return fmt.Errorf("aguara update: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), flagUpdateTimeout)
	defer cancel()

	// Fetch + verify EVERYTHING before anything is written: signature +
	// pinned identity (unless --insecure-intel), manifest schema, blob
	// name, gzip/json digests + sizes, and bundle_schema_version against
	// the decoded snapshot. A failure leaves the cache untouched (no
	// partial writes).
	snap, err := fetchVerifiedSnapshot(ctx, intelBundleBaseURL, insecure)
	if err != nil {
		return fmt.Errorf("aguara update: %w", err)
	}

	// A verified-but-empty bundle is almost certainly a publishing
	// fault; preserve cached intel unless the operator opts in.
	if len(snap.Records) == 0 && !flagUpdateAllowEmpty {
		return fmt.Errorf("aguara update: verified bundle has 0 records; refusing to overwrite cached intel (pass --allow-empty to save anyway)")
	}

	// SaveVerified writes a provenance marker so a later --allow-stale
	// fallback can prove this cache came from a verified signed bundle.
	if err := store.SaveVerified(snap); err != nil {
		return fmt.Errorf("aguara update: save snapshot: %w", err)
	}

	return writeUpdateOutput(snap, store.Dir)
}

// updateOutput is the JSON-stable shape `aguara update --format json`
// emits.
type updateOutput struct {
	SnapshotPath string    `json:"snapshot_path"`
	Records      int       `json:"records"`
	GeneratedAt  time.Time `json:"generated_at"`
	Ecosystems   []string  `json:"ecosystems"`
	Source       string    `json:"source"`
	Verified     bool      `json:"verified"`
}

func buildUpdateOutput(snap intel.Snapshot, storeDir string) updateOutput {
	ecos := intel.EcosystemsFromSources(snap.Sources)
	if ecos == nil {
		ecos = []string{}
	}
	return updateOutput{
		SnapshotPath: filepath.Join(storeDir, "snapshot.json"),
		Records:      len(snap.Records),
		GeneratedAt:  snap.GeneratedAt,
		Ecosystems:   ecos,
		Source:       "intel-latest",
		Verified:     true,
	}
}

// writeUpdateOutput dispatches between the JSON and terminal writers
// based on the global --format flag. The -o flag redirects either format
// to a file; otherwise both go to stdout.
func writeUpdateOutput(snap intel.Snapshot, storeDir string) error {
	out := buildUpdateOutput(snap, storeDir)
	if strings.ToLower(flagFormat) == "json" {
		return writeUpdateJSON(out)
	}
	return writeUpdateTerminal(out)
}

func writeUpdateJSON(out updateOutput) error {
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

func writeUpdateTerminal(out updateOutput) error {
	w := io.Writer(os.Stdout)
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("aguara update: write --output: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	fmt.Fprintf(w, "Aguara threat intel updated (verified signed bundle)\n")
	fmt.Fprintf(w, "  records:    %d\n", out.Records)
	fmt.Fprintf(w, "  ecosystems: %s\n", strings.Join(out.Ecosystems, ", "))
	fmt.Fprintf(w, "  written:    %s\n", out.SnapshotPath)
	return nil
}

// assertOutputNotShadowingStore returns an error if flagOutput would
// resolve to the same on-disk file the intel.Store writes the snapshot
// to. Compared by canonical absolute path so a relative -o (or one with
// redundant separators) is caught.
//
// On case-insensitive filesystems (macOS HFS+/APFS, Windows NTFS),
// `Snapshot.JSON` and `snapshot.json` resolve to the same file even
// though the bytes differ; we fold case for the comparison so the
// corruption guard fires for that scenario too. Linux ext4/xfs are
// case-sensitive by default and the byte-for-byte compare is correct
// there; the case-fold path stays gated on runtime.GOOS so we do not
// over-reject.
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

// pathsCollide reports whether two canonical absolute paths resolve to
// the same on-disk file under the host's filesystem rules.
func pathsCollide(a, b string) bool {
	if a == b {
		return true
	}
	if isCaseInsensitiveFS() && strings.EqualFold(a, b) {
		return true
	}
	return false
}

// isCaseInsensitiveFS reports whether the host's default filesystem
// treats paths case-insensitively (macOS and Windows by default).
func isCaseInsensitiveFS() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	default:
		return false
	}
}

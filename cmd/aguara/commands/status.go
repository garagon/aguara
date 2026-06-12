package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:     "status",
	GroupID: groupRules,
	Short:   "Show Aguara version and threat-intel freshness",
	Long: `Print the binary version, embedded threat-intel snapshot age, and
local cached snapshot status (if any).

This command does no network I/O. Run 'aguara update' to refresh the local
snapshot.`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	w := os.Stdout
	now := time.Now().UTC()

	fmt.Fprintf(w, "Aguara %s (commit %s)\n\n", Version, Commit)

	fmt.Fprintf(w, "Threat intel:\n")
	for _, snap := range incident.EmbeddedSnapshots() {
		label := snapshotLabel(snap)
		// Embedded intel ships with the binary: show its age for
		// provenance, never a stale warning.
		extra := ""
		if n := len(snap.AllVersions); n > 0 {
			extra = fmt.Sprintf(" + %d all-versions entries", n)
		}
		fmt.Fprintf(w, "  Embedded (%s): %s (%s), %d records%s\n",
			label, snap.GeneratedAt.Format("2006-01-02"),
			humanizeAgeDays(ageDaysSince(snap.GeneratedAt, now)), len(snap.Records), extra)
	}

	store, err := intel.DefaultStore()
	if err != nil {
		// A missing $HOME / unreadable user dir is exotic
		// enough that we still want to print everything else;
		// surface it as a warning line rather than aborting.
		fmt.Fprintf(w, "  Local:    unavailable: %v\n", err)
		return nil
	}
	st := store.Status()
	switch {
	case st.HasSnapshot:
		ageDays := ageDaysSince(st.GeneratedAt, now)
		fmt.Fprintf(w, "  Local:    %s (%s), %d records (%s)\n",
			st.GeneratedAt.Format("2006-01-02 15:04 UTC"),
			humanizeAgeDays(ageDays), st.RecordCount, st.Path,
		)
		// The local cache is user-fetched, so it can be stale (unlike
		// embedded). Same 30-day policy as check/audit; informational.
		if ageDays > intelStaleAfterDays {
			fmt.Fprintf(w, "            %s\n", intelStaleNote())
		}
	case st.LastUpdateErr != "":
		fmt.Fprintf(w, "  Local:    error reading %s: %s\n", st.Path, st.LastUpdateErr)
	default:
		fmt.Fprintf(w, "  Local:    none (run `aguara update` to fetch the latest)\n")
	}

	fmt.Fprintf(w, "\nNetwork:\n")
	fmt.Fprintf(w, "  Default checks do not use the network.\n")
	fmt.Fprintf(w, "  `aguara update` refreshes intel; `aguara check --fresh` refreshes then checks.\n")
	return nil
}

// snapshotLabel picks a short human-readable label for a snapshot.
// "manual" for the hand-curated emergency list, "osv" for the
// build-time generated stub, "unknown" for anything else (defensive
// against future snapshot sources that have not learned the
// convention).
func snapshotLabel(snap intel.Snapshot) string {
	if len(snap.Sources) == 0 {
		return "unknown"
	}
	switch snap.Sources[0].Kind {
	case intel.SourceManual:
		return "manual"
	case intel.SourceOSV:
		return "osv"
	default:
		return string(snap.Sources[0].Kind)
	}
}

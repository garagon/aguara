package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/spf13/cobra"
)

var (
	flagAuditPath       string
	flagAuditCI         bool
	flagAuditFailOn     string
	flagAuditFresh      bool
	flagAuditAllowStale bool
)

var auditCmd = &cobra.Command{
	Use:   "audit [path]",
	Short: "Run scan + check together and produce a single verdict",
	Long: `Audit a project: run the supply-chain check (compromised packages /
persistence artifacts) and the content scan (rule-based detection of
prompt injection, credential leaks, etc.) together, and report a
single combined verdict.

Default audits stay offline -- they use the same embedded threat intel
the standalone 'aguara check' uses. Pass --fresh to refresh OSV intel
before the audit. Pass --ci to fail-on critical with no color (the
default for unattended CI runs).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&flagAuditPath, "path", "", "Path to audit (also accepted as a positional argument; defaults to '.')")
	auditCmd.Flags().BoolVar(&flagAuditCI, "ci", false, "CI mode: --fail-on critical, no color")
	auditCmd.Flags().StringVar(&flagAuditFailOn, "fail-on", "", "Exit code 1 when findings reach this severity (critical, warning, info)")
	auditCmd.Flags().BoolVar(&flagAuditFresh, "fresh", false, "Refresh threat intel before the audit (network opt-in)")
	auditCmd.Flags().BoolVar(&flagAuditAllowStale, "allow-stale", false, "Continue with cached/embedded intel if --fresh refresh fails")
	rootCmd.AddCommand(auditCmd)
}

// AuditResult is the combined output of `aguara audit`. Both
// sub-results retain their full shape so JSON consumers can drill
// into either side; the verdict + summary fields are convenience
// for terminal output and CI gates.
type AuditResult struct {
	Target  string                 `json:"target"`
	Check   *incident.CheckResult  `json:"check"`
	Scan    *scanner.ScanResult    `json:"scan"`
	Verdict AuditVerdict           `json:"verdict"`
	Intel   incident.IntelSummary  `json:"intel"`
}

// AuditVerdict is the single-line summary the CLI prints under
// the two sub-result sections.
type AuditVerdict struct {
	Status            string `json:"status"` // "pass" | "fail"
	CheckCriticals    int    `json:"check_criticals"`
	CheckWarnings     int    `json:"check_warnings"`
	CheckInfos        int    `json:"check_infos"`
	ScanCriticals     int    `json:"scan_criticals"`
	ScanHighs         int    `json:"scan_highs"`
	ScanMediums       int    `json:"scan_mediums"`
	ScanLows          int    `json:"scan_lows"`
	ScanInfos         int    `json:"scan_infos"`
	ThresholdExceeded bool   `json:"threshold_exceeded"`
}

func runAudit(cmd *cobra.Command, args []string) error {
	applyAuditCIDefaults()

	target := flagAuditPath
	if target == "" && len(args) == 1 {
		target = args[0]
	}
	if target == "" {
		target = "."
	}

	// Intel override: reuse the standalone check's resolution
	// helper. We mirror audit's --fresh / --allow-stale flags
	// onto the check-side globals so resolveCheckIntel reads the
	// right intent. Restoring them on exit keeps the two surfaces
	// from leaking state across commands in long-lived test runs.
	prevFresh, prevAllowStale := flagCheckFresh, flagCheckAllowStale
	flagCheckFresh, flagCheckAllowStale = flagAuditFresh, flagAuditAllowStale
	defer func() { flagCheckFresh, flagCheckAllowStale = prevFresh, prevAllowStale }()

	intelOverride, err := resolveCheckIntel(cmd.Context())
	if err != nil {
		return err
	}

	// 1. Run the supply-chain check.
	checkEco, checkPath, err := resolveCheckTarget("", target)
	if err != nil {
		return err
	}
	checkOpts := incident.CheckOptions{Path: checkPath, Intel: intelOverride}
	var checkResult *incident.CheckResult
	switch checkEco {
	case ecoPython:
		checkResult, err = incident.Check(checkOpts)
	case ecoNPM:
		checkResult, err = incident.CheckNPM(checkOpts)
	default:
		return fmt.Errorf("audit: unresolved ecosystem %q", checkEco)
	}
	if err != nil {
		return fmt.Errorf("audit: check phase: %w", err)
	}

	// 2. Run the content scan.
	scanResult, err := auditRunScan(cmd, target)
	if err != nil {
		return fmt.Errorf("audit: scan phase: %w", err)
	}

	// 3. Compose result + verdict.
	result := &AuditResult{
		Target: target,
		Check:  checkResult,
		Scan:   scanResult,
		Intel:  checkResult.Intel,
	}
	verdict, vErr := computeAuditVerdict(result, flagAuditFailOn)
	if vErr != nil {
		// An invalid --fail-on value must error rather than
		// silently disable the gate. scan / check both do the
		// same; audit must not be the one path where a typo
		// (--fail-on critcal) ships green.
		return vErr
	}
	result.Verdict = verdict

	// 4. Emit.
	if flagFormat == "json" {
		if err := writeAuditJSON(result); err != nil {
			return err
		}
	} else {
		if err := writeAuditTerminal(result); err != nil {
			return err
		}
	}

	if result.Verdict.ThresholdExceeded {
		return ErrThresholdExceeded
	}
	return nil
}

// applyAuditCIDefaults mirrors check / scan: --ci implies
// --fail-on critical (unless the user set --fail-on explicitly)
// and disables color. NO_COLOR also disables color so the flag
// interacts cleanly with CI runners that set it by convention.
func applyAuditCIDefaults() {
	if flagAuditCI {
		if flagAuditFailOn == "" {
			flagAuditFailOn = "critical"
		}
		flagNoColor = true
	}
	if os.Getenv("NO_COLOR") != "" {
		flagNoColor = true
	}
}

// auditRunScan invokes the scanner against the target path using
// the same helpers runScan uses. Kept as a thin shim so the audit
// command does not duplicate scanner-construction logic; if the
// scan pipeline grows new flags, audit picks them up automatically.
//
// Note we do NOT honour --severity for audit: the audit's job is
// to be a strict gate, so we always run with SeverityInfo and let
// the verdict / --fail-on threshold filter what matters.
func auditRunScan(cmd *cobra.Command, targetPath string) (*scanner.ScanResult, error) {
	cfg := loadScanConfig(cmd, targetPath)

	compiled, err := loadAndCompileRules(cfg)
	if err != nil {
		return nil, err
	}

	s, store := buildScanner(compiled, cfg, scanner.SeverityInfo)
	sp := startSpinnerIfTerminal(s, "Auditing content...")

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	result, err := executeScan(ctx, s, targetPath)
	stopSpinner(sp)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(compiled)
	result.Target = targetPath

	if store != nil {
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving state: %v\n", err)
		}
	}

	if !flagNoRedact {
		types.RedactCredentialFindings(result.Findings)
	}
	return result, nil
}

// computeAuditVerdict tallies per-section severities and decides
// whether the --fail-on threshold trips. The threshold mapping
// between audit's vocabulary (critical / warning / info) and
// scan's numeric Severity is intentionally simple:
//
//	critical -> check critical, scan critical
//	warning  -> check warning,  scan high
//	info     -> check info,     scan info
//
// A finer-grained mapping (e.g. warning matches medium) would
// surprise users who expect "warning" to mean "the loudest of the
// non-critical buckets" in both vocabularies. The simple mapping
// also means a single --fail-on flag is unambiguous in CI logs.
func computeAuditVerdict(result *AuditResult, threshold string) (AuditVerdict, error) {
	v := AuditVerdict{Status: "pass"}

	for _, f := range result.Check.Findings {
		switch strings.ToUpper(f.Severity) {
		case incident.SevCritical:
			v.CheckCriticals++
		case incident.SevWarning:
			v.CheckWarnings++
		case incident.SevInfo:
			v.CheckInfos++
		}
	}
	for _, f := range result.Scan.Findings {
		switch f.Severity {
		case scanner.SeverityCritical:
			v.ScanCriticals++
		case scanner.SeverityHigh:
			v.ScanHighs++
		case scanner.SeverityMedium:
			v.ScanMediums++
		case scanner.SeverityLow:
			v.ScanLows++
		case scanner.SeverityInfo:
			v.ScanInfos++
		}
	}

	if threshold == "" {
		return v, nil
	}
	switch strings.ToUpper(strings.TrimSpace(threshold)) {
	case "CRITICAL":
		if v.CheckCriticals > 0 || v.ScanCriticals > 0 {
			v.ThresholdExceeded = true
		}
	case "WARNING":
		if v.CheckCriticals > 0 || v.CheckWarnings > 0 ||
			v.ScanCriticals > 0 || v.ScanHighs > 0 {
			v.ThresholdExceeded = true
		}
	case "INFO":
		// Any finding at all trips the gate, including INFO
		// on either side. The earlier shape silently dropped
		// INFO findings, so a custom INFO-only rule could
		// have passed `--fail-on info` cleanly. That broke the
		// "lowest threshold" contract; the explicit InfoCount
		// fields above feed this gate now.
		if v.CheckCriticals+v.CheckWarnings+v.CheckInfos > 0 ||
			v.ScanCriticals+v.ScanHighs+v.ScanMediums+v.ScanLows+v.ScanInfos > 0 {
			v.ThresholdExceeded = true
		}
	default:
		return v, fmt.Errorf("invalid --fail-on %q: choose critical, warning, or info", threshold)
	}
	if v.ThresholdExceeded {
		v.Status = "fail"
	}
	return v, nil
}

func writeAuditJSON(result *AuditResult) error {
	w := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeAuditTerminal(result *AuditResult) error {
	bold := "\033[1m"
	dim := "\033[2m"
	red := "\033[31m"
	green := "\033[32m"
	yellow := "\033[33m"
	reset := "\033[0m"
	if flagNoColor {
		bold, dim, red, green, yellow, reset = "", "", "", "", "", ""
	}

	fmt.Printf("\n%sAguara audit: %s%s\n\n", bold, result.Target, reset)

	fmt.Printf("%sSupply chain%s\n", bold, reset)
	if len(result.Check.Findings) == 0 {
		fmt.Printf("  %s✔ No compromised packages or artifacts found.%s\n", green, reset)
	} else {
		for _, f := range result.Check.Findings {
			sev := red
			if f.Severity == incident.SevWarning {
				sev = yellow
			}
			fmt.Printf("  %s%-10s%s %s\n", sev, f.Severity, reset, f.Title)
			if f.Path != "" {
				fmt.Printf("           %sPath: %s%s\n", dim, f.Path, reset)
			}
		}
	}

	fmt.Printf("\n%sContent scan%s\n", bold, reset)
	if len(result.Scan.Findings) == 0 {
		fmt.Printf("  %s✔ No content findings.%s\n", green, reset)
	} else {
		// Cap the verbose listing -- a noisy repo can dump
		// hundreds of low-severity findings into the audit
		// output. Showing all of them buries the verdict.
		const maxList = 10
		shown := 0
		for _, f := range result.Scan.Findings {
			if shown >= maxList {
				break
			}
			fmt.Printf("  %s%-9s%s %s (%s)\n", red, f.Severity.String(), reset, f.RuleName, f.RuleID)
			if f.FilePath != "" {
				fmt.Printf("           %s%s:%d%s\n", dim, f.FilePath, f.Line, reset)
			}
			shown++
		}
		if len(result.Scan.Findings) > maxList {
			fmt.Printf("  %s... +%d more (full list in --format json)%s\n",
				dim, len(result.Scan.Findings)-maxList, reset)
		}
	}

	fmt.Printf("\n%sIntel:%s mode=%s snapshot=%s sources=%v generated=%s\n",
		bold, reset, result.Intel.Mode, result.Intel.Snapshot,
		result.Intel.Sources, result.Intel.GeneratedAt.Format(time.DateOnly))

	verdictColor := green
	if result.Verdict.ThresholdExceeded {
		verdictColor = red
	}
	fmt.Printf("\n%s%sVerdict: %s%s (check: %d critical / %d warning, scan: %d critical / %d high)\n",
		verdictColor, bold, strings.ToUpper(result.Verdict.Status), reset,
		result.Verdict.CheckCriticals, result.Verdict.CheckWarnings,
		result.Verdict.ScanCriticals, result.Verdict.ScanHighs)
	return nil
}


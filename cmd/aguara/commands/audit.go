package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/baseline"
	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/packagecheck"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/spf13/cobra"
)

var (
	flagAuditPath          string
	flagAuditCI            bool
	flagAuditFailOn        string
	flagAuditFresh         bool
	flagAuditAllowStale    bool
	flagAuditBaseline      string
	flagAuditWriteBaseline string
	flagAuditInsecure      bool
	flagAuditVerbose       bool
	flagAuditProjectPolicy string
)

var auditCmd = &cobra.Command{
	Use:     "audit [path]",
	GroupID: groupScan,
	Short:   "Run scan + check together and produce a single verdict",
	Example: `  aguara audit .               Package check + content scan, one verdict
  aguara audit . --ci          CI gate: exit 1 on critical, no color
  aguara audit . --verbose     List every content finding (no cap)
  aguara audit . --fresh       Refresh threat intel first (network opt-in)`,
	Long: `Audit a project: run the supply-chain check (compromised packages /
persistence artifacts) and the content scan (rule-based detection of
prompt injection, credential leaks, etc.) together, and report a
single combined verdict.

Default audits stay offline -- they use the same embedded threat intel
the standalone 'aguara check' uses. Pass --fresh to refresh from Aguara's
signed advisory bundle (verified before use) before the audit. Pass --ci
to fail-on critical with no color (the default for unattended CI runs).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAudit,
}

func init() {
	addFormatFlag(auditCmd, "terminal", "json")
	addOutputFlag(auditCmd)
	addWorkersFlag(auditCmd)
	addRulesFlag(auditCmd)
	addDisableRuleFlag(auditCmd)
	auditCmd.Flags().StringVar(&flagAuditPath, "path", "", "Path to audit (also accepted as a positional argument; defaults to '.')")
	auditCmd.Flags().BoolVar(&flagAuditCI, "ci", false, "CI mode: --fail-on critical, no color")
	auditCmd.Flags().StringVar(&flagAuditFailOn, "fail-on", "", "Exit code 1 when findings reach this severity (critical, warning, info)")
	auditCmd.Flags().BoolVar(&flagAuditFresh, "fresh", false, "Refresh threat intel from Aguara's signed advisory bundle before the audit (network opt-in)")
	auditCmd.Flags().BoolVar(&flagAuditInsecure, "insecure-intel", false, "Skip advisory-bundle signature verification (also requires AGUARA_INSECURE_INTEL=1; mirrors / air-gapped / tests only; manifest + blob digests are still checked)")
	auditCmd.Flags().BoolVar(&flagAuditAllowStale, "allow-stale", false, "If --fresh fails, fall back to previously verified local intel (errors if none is cached)")
	auditCmd.Flags().StringVar(&flagAuditBaseline, "baseline", "", "Gate scan findings only on those NOT in this baseline file (package findings always gate; fails closed if missing/malformed)")
	auditCmd.Flags().StringVar(&flagAuditWriteBaseline, "write-baseline", "", "Write the scan findings as a baseline to this file (skips sensitive findings); package findings still gate")
	auditCmd.Flags().BoolVar(&flagAuditVerbose, "verbose", false, "List every content finding instead of capping at 10")
	auditCmd.Flags().StringVar(&flagAuditProjectPolicy, "project-policy", "auto", "Project-owned policy (.aguara.yml, .aguaraignore, inline directives): auto (ignore), trust, or ignore")
	// Runtime errors (ErrThresholdExceeded after the verdict
	// computes "fail", --fresh network failures) should not
	// trigger Cobra's flag-usage block. The verdict line plus the
	// JSON sub-results are already enough to act on; printing
	// --help on top of those makes the CI log read as command
	// misuse. See scan.go for the same rationale.
	auditCmd.SilenceUsage = true
	rootCmd.AddCommand(auditCmd)
}

// AuditResult is the combined output of `aguara audit`. Both
// sub-results retain their full shape so JSON consumers can drill
// into either side; the verdict + summary fields are convenience
// for terminal output and CI gates.
type AuditResult struct {
	Target  string                `json:"target"`
	Check   *incident.CheckResult `json:"check"`
	Scan    *scanner.ScanResult   `json:"scan"`
	Verdict AuditVerdict          `json:"verdict"`
	Triage  AuditTriage           `json:"triage"`
	Handoff AuditAgentHandoff     `json:"agent_handoff"`
	Plan    AuditActionPlan       `json:"action_plan"`
	Intel   incident.IntelSummary `json:"intel"`
	// Coverage states what the audit evaluated: files scanned, package
	// evidence read, and dependency files found but not evaluated.
	Coverage AuditCoverage `json:"coverage"`
	// Complete is false when the content scan is incomplete: scan.errors
	// lists what failed, the findings are partial, the verdict status is
	// "incomplete" (unless the gate failed) and the command exits 2.
	Complete bool `json:"complete"`

	scanGate    []types.Finding
	scanGateSet bool
}

// AuditVerdict is the single-line summary the CLI prints under
// the two sub-result sections.
type AuditVerdict struct {
	Status            string `json:"status"` // "pass" | "findings" | "incomplete" | "fail"
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

// AuditTriage translates the raw findings and CI gate into a product-level
// decision a human reviewer or agent workflow can act on. It is additive JSON:
// exit codes, verdict.status, and threshold_exceeded remain the compatibility
// contract for machines that already consume audit output.
type AuditTriage struct {
	Decision             string              `json:"decision"` // "proceed" | "review" | "stop"
	Summary              string              `json:"summary"`
	ContextObservations  int                 `json:"context_observations"`
	ReviewFindings       int                 `json:"review_findings"`
	Reasons              []AuditTriageReason `json:"reasons"`
	RecommendedNextSteps []string            `json:"recommended_next_steps"`
}

type AuditTriageReason struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// AuditAgentHandoff translates the triage decision into guidance for AI coding
// agents and other automation that might otherwise install, test, build, or run
// project-defined commands immediately after cloning a repository.
type AuditAgentHandoff struct {
	Status         string   `json:"status"` // "allowed" | "review_only" | "blocked"
	Summary        string   `json:"summary"`
	AllowedActions []string `json:"allowed_actions"`
	BlockedActions []string `json:"blocked_actions"`
}

// AuditActionPlan is a compact machine-readable contract for agents and
// wrappers that need booleans instead of prose before they decide whether to
// install dependencies, run tests, execute CI, or only inspect the repository.
type AuditActionPlan struct {
	TrustState             string   `json:"trust_state"` // "allowed" | "review_only" | "blocked"
	CanInstallDependencies bool     `json:"can_install_dependencies"`
	CanExecuteProjectCode  bool     `json:"can_execute_project_code"`
	CanRunCI               bool     `json:"can_run_ci"`
	CanUseRepoAgentConfig  bool     `json:"can_use_repo_agent_config"`
	CanEditFiles           bool     `json:"can_edit_files"`
	CanExplainFindings     bool     `json:"can_explain_findings"`
	Priority               []string `json:"priority"`
	NextCommands           []string `json:"next_commands"`
}

func runAudit(cmd *cobra.Command, args []string) error {
	if flagAuditBaseline != "" && flagAuditWriteBaseline != "" {
		return fmt.Errorf("--baseline and --write-baseline are mutually exclusive")
	}
	if _, err := resolveProjectPolicy(flagAuditProjectPolicy, false); err != nil {
		return err
	}
	applyAuditCIDefaults()

	target := flagAuditPath
	if target == "" && len(args) == 1 {
		target = args[0]
	}
	if target == "" {
		target = "."
	}

	// audit's --fresh / --allow-stale flags mirror onto the
	// check-side globals so resolveCheckIntel reads the right
	// intent. Restoring them on exit keeps the two surfaces from
	// leaking state across commands in long-lived test runs.
	prevFresh, prevAllowStale, prevInsecure := flagCheckFresh, flagCheckAllowStale, flagCheckInsecure
	flagCheckFresh, flagCheckAllowStale, flagCheckInsecure = flagAuditFresh, flagAuditAllowStale, flagAuditInsecure
	defer func() {
		flagCheckFresh, flagCheckAllowStale, flagCheckInsecure = prevFresh, prevAllowStale, prevInsecure
	}()

	// 1. Build the same check plan `aguara check` would build
	// for `target`. audit reuses buildCheckPlan + runCheckPlan
	// so a Go / Rust / .NET monorepo audit reports the same
	// `check.ecosystems` slice as a standalone `aguara check`
	// against the same path.
	plan, err := buildCheckPlanFor(nil, target, flagAuditPath == "" && len(args) == 0)
	if err != nil {
		return err
	}
	intelOverride, err := resolveCheckIntel(cmd.Context(), plan.intelEcosystems())
	if err != nil {
		return err
	}
	checkResult, err := runCheckPlan(plan, intelOverride)
	if err != nil {
		return fmt.Errorf("audit: check phase: %w", err)
	}
	// Set age/stale once on the check result; the AuditResult copies this
	// IntelSummary and the nested Check pointer shares it, so JSON and
	// terminal stay consistent.
	applyIntelFreshness(&checkResult.Intel, time.Now().UTC())

	// 2. Run the content scan. An incomplete scan still yields the partial
	// result; the audit reports it and then fails with the scan error.
	scanResult, scanErr := auditRunScan(cmd, target)
	if scanResult == nil {
		return fmt.Errorf("audit: scan phase: %w", scanErr)
	}
	if scanErr != nil {
		scanErr = fmt.Errorf("audit: scan phase: %w", scanErr)
	}

	// 3. Compose result + verdict.
	result := &AuditResult{
		Target:   target,
		Check:    checkResult,
		Scan:     scanResult,
		Intel:    checkResult.Intel,
		Coverage: auditCoverage(checkResult, scanResult),
		Complete: !scanResult.Incomplete,
	}

	// Baseline applies to the SCAN side only; package (check) findings
	// always gate exactly as today. Output keeps every scan finding (3A)
	// plus a baseline summary; the verdict tallies only the post-baseline
	// scan gate set, so we swap the scan findings for the verdict
	// computation and restore the full list before emitting.
	scanGate := scanResult.Findings
	switch {
	case flagAuditWriteBaseline != "" && scanErr != nil:
		// A baseline accepts the current findings; an incomplete scan did
		// not see them all.
		fmt.Fprintf(os.Stderr, "baseline: not written to %s: the scan is incomplete\n", flagAuditWriteBaseline)
	case flagAuditWriteBaseline != "":
		written, skipped, err := baseline.Write(flagAuditWriteBaseline, scanResult.Findings, Version)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "baseline: wrote %d fingerprint(s) to %s", written, flagAuditWriteBaseline)
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "; %d sensitive finding(s) skipped (remain non-baselineable)", skipped)
		}
		fmt.Fprintln(os.Stderr)
		// Establishing a scan baseline accepts all current scan findings,
		// so the scan side contributes nothing to the gate. The check
		// side still gates: package findings are never baselineable.
		scanGate = nil
	case flagAuditBaseline != "":
		set, err := baseline.Load(flagAuditBaseline)
		if err != nil {
			return err
		}
		var summary types.BaselineSummary
		scanGate, summary = baseline.Apply(scanResult.Findings, set, flagAuditBaseline)
		scanResult.Baseline = &summary
	}

	fullScan := scanResult.Findings
	result.scanGate = scanGate
	result.scanGateSet = true
	scanResult.Findings = scanGate
	verdict, vErr := computeAuditVerdict(result, flagAuditFailOn)
	scanResult.Findings = fullScan
	if vErr != nil {
		// An invalid --fail-on value must error rather than
		// silently disable the gate. scan / check both do the
		// same; audit must not be the one path where a typo
		// (--fail-on critcal) ships green.
		return vErr
	}
	result.Verdict = verdict
	result.Triage = computeAuditTriage(result)
	result.Handoff = computeAuditAgentHandoff(result.Triage)
	result.Plan = computeAuditActionPlan(result)

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

	// An incomplete scan is an error (exit 2) whatever the threshold.
	if scanErr != nil {
		return scanErr
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
// audit has no --severity flag: the audit's job is to be a strict
// gate, so it always runs with SeverityInfo and lets the verdict /
// --fail-on threshold decide what matters. Passing --severity to audit
// is rejected at parse time rather than silently ignored.
func auditRunScan(cmd *cobra.Command, targetPath string) (*scanner.ScanResult, error) {
	trustProjectPolicy, err := resolveProjectPolicy(flagAuditProjectPolicy, false)
	if err != nil {
		return nil, err
	}
	cfg := config.Config{}
	if trustProjectPolicy {
		if cfg, err = loadScanConfig(cmd, targetPath); err != nil {
			return nil, err
		}
	}

	// .aguara.yml `baseline:` feeds audit's --baseline when unset and we
	// are not establishing a new baseline.
	if cfg.Baseline != "" && !cmd.Flags().Changed("baseline") && flagAuditWriteBaseline == "" {
		flagAuditBaseline = cfg.Baseline
	}

	res, err := resolveCLIRules(cfg, flagDisableRules, os.Stderr)
	if err != nil {
		return nil, err
	}

	s, store := buildScanner(res, cfg, scanner.SeverityInfo, trustProjectPolicy)
	sp := startSpinnerIfTerminal(s, "Auditing content...")

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	result, err := executeScan(ctx, s, targetPath)
	stopSpinner(sp)
	result, scanErr := partialScan(result, err)
	if result == nil {
		return nil, err
	}
	result.RulesLoaded = len(res.Compiled)
	result.Target = targetPath
	result.Coverage = scanCoverage(result)
	if trustProjectPolicy {
		noteProjectPolicy(cmd, cfg, res, result)
	}

	if store != nil && scanErr == nil {
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving state: %v\n", err)
		}
	}

	// An incomplete scan returns its partial result with the error, so the
	// audit still reports what was found before it fails.
	return result, scanErr
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

	// Tri-state Status (#110). Previously the verdict was binary
	// pass / fail, which collapsed "no findings at all" and
	// "findings exist but no gate is enforced" into the same
	// "pass" output. Dashboards that read only `verdict.status`
	// would see green even when `check_criticals > 0`.
	//
	// The states now are:
	//   pass     -> zero findings on either side
	//   findings -> at least one finding, but the gate (--ci /
	//               --fail-on) was either not set or not crossed.
	//               exit code stays 0 so default `aguara audit` runs
	//               do not surprise users with non-zero exits.
	//   fail     -> gate was set and the threshold was crossed.
	//               exit code is non-zero via ErrThresholdExceeded.
	//
	// The threshold logic below upgrades "findings" to "fail" when
	// the gate trips; the exit-code path is unchanged so existing
	// CI integrations that read ThresholdExceeded keep behaving.
	totalFindings := v.CheckCriticals + v.CheckWarnings + v.CheckInfos +
		v.ScanCriticals + v.ScanHighs + v.ScanMediums + v.ScanLows + v.ScanInfos
	if totalFindings > 0 {
		v.Status = "findings"
	}
	// An incomplete content scan is never a pass: "incomplete" replaces
	// pass and findings (the counts still say what was found), and only a
	// crossed gate ("fail") outranks it.
	if result.Scan.Incomplete {
		v.Status = "incomplete"
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

func computeAuditTriage(result *AuditResult) AuditTriage {
	t := AuditTriage{
		Decision: "proceed",
		Summary:  "No package or content findings require review before proceeding.",
		RecommendedNextSteps: []string{
			"Proceed with normal review, install, CI, or agent handoff.",
		},
	}
	if result == nil || result.Check == nil || result.Scan == nil {
		return t
	}
	for _, f := range result.Scan.Findings {
		if f.DecisionImpact == rulemeta.DecisionImpactContext {
			t.ContextObservations++
		}
	}
	t.ReviewFindings = len(result.Check.Findings)
	for _, f := range auditScanGateFindings(result) {
		if f.DecisionImpact != rulemeta.DecisionImpactContext {
			t.ReviewFindings++
		}
	}

	addReason := func(kind, severity, message string) {
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     kind,
			Severity: severity,
			Message:  message,
		})
	}

	if result.Verdict.ThresholdExceeded {
		addReason("gate_exceeded", "critical", "The configured audit gate was crossed.")
	}
	if result.Verdict.CheckCriticals > 0 {
		addReason("known_malicious_package", "critical", "A package in the resolved dependency evidence is known malicious.")
	}
	if result.Verdict.ScanCriticals > 0 {
		addReason("critical_content_finding", "critical", "Critical content findings are present in files this repository asks you to trust.")
	}
	if result.Scan.Baseline != nil && result.Scan.Baseline.Applied {
		s := result.Scan.Baseline
		switch {
		case s.GateCount > 0:
			addReason("baseline_new_findings", "warning", "A baseline was applied, but new or non-baselineable scan findings still remain.")
		case s.Baselined > 0:
			addReason("baseline_existing_findings", "info", "Existing scan findings were kept visible but did not gate this run because they are in the baseline.")
		}
	}

	switch {
	case hasTriageReason(t.Reasons, "known_malicious_package") ||
		hasTriageReason(t.Reasons, "critical_content_finding"):
		t.Decision = "stop"
		t.Summary = "Do not install, execute CI, or hand this repository to an agent until the critical findings are resolved."
		t.RecommendedNextSteps = []string{
			"Do not run package install scripts or project automation yet.",
			"Review the critical package and content findings first.",
			"Remove or replace known-malicious packages and inspect flagged trust surfaces.",
		}
	case result.Verdict.ThresholdExceeded:
		t.Decision = "stop"
		t.Summary = "The configured audit gate was crossed; review the gated findings before executing this repository."
		t.RecommendedNextSteps = []string{
			"Do not run package install scripts or project automation yet.",
			"Review findings at or above the configured threshold.",
			"Proceed only when the repository satisfies the selected policy.",
		}
	case t.ReviewFindings > 0:
		t.Decision = "review"
		t.Summary = "Findings are present; review them before installing, running CI, or handing this repository to an agent."
		t.RecommendedNextSteps = []string{
			"Review the findings and remediation guidance.",
			"Use aguara explain <rule> for the highest-impact content finding.",
			"Proceed only after the trust decision is understood.",
		}
		if len(t.Reasons) == 0 {
			addReason("findings_present", "warning", "Package or content findings are present below the stop threshold.")
		}
	case result.Scan.Baseline != nil && result.Scan.Baseline.Applied &&
		result.Scan.Baseline.Baselined > 0:
		t.Summary = "Existing findings remain visible, but the baseline accepted them and no new finding requires review."
		t.RecommendedNextSteps = []string{
			"Proceed with normal review, install, CI, or agent handoff.",
			"Keep the baseline under version control and review new findings when they appear.",
		}
	case t.ContextObservations > 0:
		addReason("context_observations", "info",
			"Supporting observations are visible, but none independently requires review.")
		t.Summary = "Only supporting context was found; no finding independently requires review before proceeding."
		t.RecommendedNextSteps = []string{
			"Proceed with normal review, install, CI, or agent handoff.",
			"Use the context observations when reviewing nearby higher-impact findings.",
		}
	}

	if result.Scan.Incomplete {
		// The content scan's findings are partial: never proceed on them.
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "scan_incomplete",
			Severity: "warning",
			Message: fmt.Sprintf("The content scan could not complete %d operation(s), listed under scan.errors; its findings are partial.",
				max(result.Scan.FailedOperations, len(result.Scan.Errors))),
		})
		escalateForCoverage(&t,
			"The content scan is incomplete, so the audit cannot clear this target.",
			"Fix the failures listed under scan.errors and run the audit again.")
	}
	if names := hiddenSkippedNames(result.Scan.Skipped); names != "" {
		// An agent reading the target follows links and reads pipes; the
		// scan did neither, so what they stand for was not evaluated.
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "entries_not_evaluated",
			Severity: "warning",
			Message:  "These entries were not read and may stand for content an agent would load: " + names + ".",
		})
		escalateForCoverage(&t,
			"Some entries under the target were not evaluated, so the audit cannot clear it.",
			"Review the entries listed under coverage.skipped before trusting the target: links that are dangling, resolve outside it or reach content the scan skips, named pipes, sockets and devices.")
	}
	applyAuditCoverageTriage(&t, result)
	return t
}

// hiddenSkippedNames names up to five skipped entries that may stand for
// content no scan read (see types.SkippedFile.HidesContent), or "" when
// there are none. The full list is in coverage.skipped.
func hiddenSkippedNames(skipped []types.SkippedFile) string {
	const maxNamed = 5
	var names []string
	hidden := 0
	for _, s := range skipped {
		if !s.HidesContent() {
			continue
		}
		hidden++
		if len(names) == maxNamed {
			continue
		}
		why := strings.ReplaceAll(s.Kind, "_", " ")
		switch {
		case s.Kind == types.SkippedSymlink && s.Resolves == types.LinkDangling:
			why = "dangling symbolic link"
		case s.Kind == types.SkippedSymlink && s.Resolves == types.LinkExcluded:
			why = "symbolic link to content the scan skips"
		case s.Kind == types.SkippedSymlink:
			why = "symbolic link resolving outside the target"
		}
		names = append(names, output.TerminalText(s.Path)+" ("+why+")")
	}
	if hidden > maxNamed {
		names = append(names, fmt.Sprintf("and %d more listed in coverage.skipped", hidden-maxNamed))
	}
	return strings.Join(names, ", ")
}

// applyAuditCoverageTriage keeps an audit that evaluated nothing from
// clearing the target. Absence of findings only means something when
// files were scanned. handoff and action_plan derive from the decision,
// so a coverage review also withholds install and execution there.
func applyAuditCoverageTriage(t *AuditTriage, result *AuditResult) {
	if result.Scan.FilesScanned == 0 {
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "nothing_scanned",
			Severity: "warning",
			Message:  "No files were scanned under the target, so the audit evaluated nothing.",
		})
		if t.Decision == "proceed" {
			t.Decision = "review"
			t.Summary = "Nothing was scanned: the audit evaluated no files, so it cannot clear this target."
			t.RecommendedNextSteps = []string{
				"Check that the audit path points at the project you meant to audit.",
				"Do not treat this result as a clean audit.",
			}
		}
		return
	}

	// Any installable entry without one exact version (that no pin of
	// the same name covers) was matched only against advisories covering
	// every version: an install resolves a version this audit never saw.
	if counts, files := unpinnedEntries(result.Check.Ecosystems, result.Target); counts != "" {
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "unpinned_dependency_evidence",
			Severity: "warning",
			Message:  counts,
		})
		hint := ""
		pythonOnly := true
		for _, e := range result.Check.Ecosystems {
			if e.Unpinned > 0 && e.Ecosystem != intel.EcosystemPyPI {
				pythonOnly = false
			}
		}
		if pythonOnly {
			hint = " (for example with pip-compile or uv pip compile)"
		} else {
			hint = " (or commit a lock file such as packages.lock.json)"
		}
		escalateForCoverage(t,
			"Some dependency entries are not pinned to one version, so the audit cannot clear dependency installation.",
			"Pin exact versions in "+files+hint+" and audit again, or review those dependencies before installing them.")
	}

	cov := result.Check.Coverage
	if cov == nil || len(cov.UnsupportedEvidence) == 0 {
		// No dependency files at all keeps the package side as before.
		return
	}
	_, _, manifests := splitUnsupported(cov.UnsupportedEvidence)
	if len(manifests) > 0 {
		// A manifest that declares dependencies without an evaluated
		// lockfile: whatever an install resolves was never checked.
		names := unsupportedEvidenceNames(manifests, result.Target)
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "manifest_without_lockfile",
			Severity: "warning",
			Message:  "These manifests declare dependencies, but no lockfile for their ecosystem was evaluated, so an install would resolve versions this audit did not check: " + names + ".",
		})
		escalateForCoverage(t,
			"Dependency manifests have no evaluated lockfile, so the audit cannot clear dependency installation.",
			"Generate or commit a lockfile for "+names+", then run the audit again.")
	}
	var others []packagecheck.UnsupportedEvidence
	for _, u := range cov.UnsupportedEvidence {
		if !u.IsManifest() {
			others = append(others, u)
		}
	}
	if len(others) == 0 {
		return
	}
	files := unsupportedEvidenceNames(others, result.Target)
	step := "Review the dependencies pinned in " + files + " before installing them; this audit did not check them."
	summary := "Dependency files were found that Aguara cannot evaluate, so the audit cannot clear dependency installation."
	partial, _ := partlyRead(others)
	if cov.Evaluated() {
		// Some evidence was checked, but action_plan grants or withholds
		// installation for the whole repository: an install would also
		// pull the packages in these files, which nothing checked.
		message := "These dependency files could not be evaluated and their packages were not checked: " + files + "."
		if len(partial) > 0 {
			// A requirements file read except for some lines: what pip
			// does with those lines was not checked.
			message = "These dependency files could not be evaluated in full, and what Aguara could not read in them was not checked: " + files + "."
		}
		if len(partial) == len(others) {
			names := make([]string, 0, len(partial))
			for _, u := range partial {
				names = append(names, displayPath(result.Target, u.Path))
			}
			step = "Fix or review the lines listed in coverage.unsupported_evidence for " + strings.Join(names, ", ") + " before installing; this audit did not check what pip does with them."
		}
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "partial_dependency_coverage",
			Severity: "warning",
			Message:  message,
		})
		summary = "Some dependency files could not be evaluated, so the audit cannot clear dependency installation."
	} else {
		// Dependency evidence exists but none of it could be evaluated.
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     "dependency_evidence_not_evaluated",
			Severity: "warning",
			Message:  "Dependency files were found but none could be evaluated: " + files + ". No package in them was checked against malicious-package intelligence.",
		})
	}
	escalateForCoverage(t, summary, step)
}

// escalateForCoverage turns a proceed decision into review with the
// coverage summary and next steps; a decision already at review or stop
// keeps its summary and gains the step.
func escalateForCoverage(t *AuditTriage, summary, step string) {
	if t.Decision == "proceed" {
		t.Decision = "review"
		t.Summary = summary
		t.RecommendedNextSteps = []string{
			step,
			"Do not install dependencies on the strength of this audit.",
		}
		return
	}
	t.RecommendedNextSteps = append(t.RecommendedNextSteps, step)
}

// unpinnedEntries describes the read dependency files that have entries
// without one exact version: the reason message ("N of M entries in
// <file> are not pinned ...") and the file names for the next step.
// Both are "" when every entry is pinned. Constraints files are skipped:
// they install nothing. The runner already leaves out entries that a pin
// of the same name in the same file covers.
func unpinnedEntries(results []packagecheck.EcosystemResult, root string) (message, files string) {
	var counts []string
	var evidence []packagecheck.UnsupportedEvidence
	unpinned := 0
	for _, e := range results {
		if packagecheck.IsConstraintsFile(e.Source) || e.Unpinned == 0 {
			continue
		}
		unpinned += e.Unpinned
		counts = append(counts, fmt.Sprintf("%d of %d entries in %s", e.Unpinned, e.PackagesRead, displayPath(root, e.Path)))
		evidence = append(evidence, packagecheck.UnsupportedEvidence{Path: e.Path, Ecosystem: e.Ecosystem})
	}
	if len(counts) == 0 {
		return "", ""
	}
	const maxNamed = 5
	if len(counts) > maxNamed {
		counts = append(counts[:maxNamed], fmt.Sprintf("entries in %d more files", len(counts)-maxNamed))
	}
	verb, pronoun := "are", "them"
	if unpinned == 1 {
		verb, pronoun = "is", "it"
	}
	message = fmt.Sprintf("%s %s not pinned to one version, so only advisories covering every version were checked for %s.",
		strings.Join(counts, ", "), verb, pronoun)
	return message, unsupportedEvidenceNames(evidence, root)
}

// auditCoverageIncomplete reports whether triage raised a coverage reason:
// nothing was scanned, some dependency files could not be evaluated, some
// entries are not pinned to one version, or a manifest has no evaluated
// lockfile.
func auditCoverageIncomplete(t AuditTriage) bool {
	return hasTriageReason(t.Reasons, "scan_incomplete") ||
		hasTriageReason(t.Reasons, "entries_not_evaluated") ||
		hasTriageReason(t.Reasons, "nothing_scanned") ||
		hasTriageReason(t.Reasons, "dependency_evidence_not_evaluated") ||
		hasTriageReason(t.Reasons, "partial_dependency_coverage") ||
		hasTriageReason(t.Reasons, "unpinned_dependency_evidence") ||
		hasTriageReason(t.Reasons, "manifest_without_lockfile")
}

func hasTriageReason(reasons []AuditTriageReason, kind string) bool {
	for _, r := range reasons {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func auditScanGateFindings(result *AuditResult) []types.Finding {
	if result.scanGateSet {
		return result.scanGate
	}
	return result.Scan.Findings
}

func computeAuditAgentHandoff(triage AuditTriage) AuditAgentHandoff {
	switch triage.Decision {
	case "stop":
		return AuditAgentHandoff{
			Status:  "blocked",
			Summary: "Do not hand this repository to an agent for execution yet.",
			AllowedActions: []string{
				"Inspect files and lockfiles.",
				"Explain Aguara findings.",
				"Propose remediation patches.",
			},
			BlockedActions: []string{
				"Do not run package install scripts.",
				"Do not run build, test, CI, or project automation.",
				"Do not execute project-defined agent hooks or tools.",
			},
		}
	case "review":
		summary := "Limit agent work to inspection and remediation until findings are reviewed."
		if triage.ReviewFindings == 0 {
			// Coverage-driven review: nothing was found, but not
			// everything was evaluated (see triage.reasons).
			summary = "Limit agent work to inspection until what this audit could not evaluate is reviewed."
		}
		return AuditAgentHandoff{
			Status:  "review_only",
			Summary: summary,
			AllowedActions: []string{
				"Inspect source, lockfiles, configs, and findings.",
				"Explain risk and propose patches.",
				"Edit files only when a reviewer approves the trust decision.",
			},
			BlockedActions: []string{
				"Do not run install, build, test, or project automation until review is complete.",
				"Do not accept agent or MCP configuration from this repository as trusted yet.",
			},
		}
	default:
		return AuditAgentHandoff{
			Status:  "allowed",
			Summary: "No audit finding requires limiting agent handoff.",
			AllowedActions: []string{
				"Proceed with normal agent workflow under the repository owner's policy.",
			},
		}
	}
}

func computeAuditActionPlan(result *AuditResult) AuditActionPlan {
	plan := AuditActionPlan{
		TrustState:             "allowed",
		CanInstallDependencies: true,
		CanExecuteProjectCode:  true,
		CanRunCI:               true,
		CanUseRepoAgentConfig:  true,
		CanEditFiles:           true,
		CanExplainFindings:     true,
	}
	if result == nil {
		return plan
	}

	switch result.Handoff.Status {
	case "blocked":
		plan.TrustState = "blocked"
		plan.CanInstallDependencies = false
		plan.CanExecuteProjectCode = false
		plan.CanRunCI = false
		plan.CanUseRepoAgentConfig = false
	case "review_only":
		plan.TrustState = "review_only"
		plan.CanInstallDependencies = false
		plan.CanExecuteProjectCode = false
		plan.CanRunCI = false
		plan.CanUseRepoAgentConfig = false
	default:
		plan.TrustState = "allowed"
	}

	plan.Priority = auditActionPriority(result.Triage)
	plan.NextCommands = auditActionNextCommands(result)
	return plan
}

func auditActionPriority(triage AuditTriage) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range triage.Reasons {
		if seen[r.Kind] {
			continue
		}
		seen[r.Kind] = true
		out = append(out, r.Kind)
	}
	return out
}

func auditActionNextCommands(result *AuditResult) []string {
	if result == nil || result.Scan == nil {
		return nil
	}
	if rule := topScanRule(result.Scan.Findings); rule != "" {
		return []string{"aguara explain " + rule}
	}
	return nil
}

func writeAuditJSON(result *AuditResult) error {
	return writeReport(func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	})
}

// writeAuditTerminal renders the terminal report to stdout, or to the
// -o file when one is set (color is already off for a file).
func writeAuditTerminal(result *AuditResult) error {
	return writeReport(func(w io.Writer) error {
		return renderAuditTerminal(w, result)
	})
}

func renderAuditTerminal(w io.Writer, result *AuditResult) error {
	st := output.NewStyle(flagNoColor)
	width := output.DetectWidth(w)
	sep := st.Separator(width)

	fmt.Fprintf(w, "\n%s\n", sep)
	fmt.Fprintf(w, "  %s\n", st.Bold("AGUARA AUDIT"))
	fmt.Fprintf(w, "  Target: %s\n", output.TerminalText(result.Target))
	fmt.Fprintf(w, "%s\n", sep)

	fmt.Fprintf(w, "\n%s\n", st.SectionHeader("PACKAGE CHECK", width))
	if line := packageCoverageLine(result.Check.Coverage); line != "" {
		fmt.Fprintf(w, "\n  %s\n", st.Dim(line))
		for _, line := range unsupportedEvidenceLines(result.Check.Coverage, result.Target) {
			fmt.Fprintf(w, "  %s %s\n", st.SeverityIcon("MEDIUM"), st.Yellow(line))
		}
	}
	switch {
	case len(result.Check.Findings) > 0:
		for _, f := range result.Check.Findings {
			label := output.TerminalText(string(f.Severity))
			fmt.Fprintf(w, "\n  %s %s %s\n", st.SeverityIcon(label), st.SeverityLabel(fmt.Sprintf("%-8s", label)), output.TerminalText(f.Title))
			if f.Path != "" {
				fmt.Fprintf(w, "             %s\n", st.Dim(output.TerminalText(f.Location())))
			}
		}
	default:
		fmt.Fprintf(w, "\n  %s\n", noPackageFindingsLine(st, result.Check.Coverage))
	}
	if note := unpinnedNote(result.Check); note != "" {
		fmt.Fprintf(w, "\n  %s\n", st.Yellow(note))
	}

	fmt.Fprintf(w, "\n%s\n", st.SectionHeader("CONTENT SCAN", width))
	if result.Scan.Coverage != nil {
		fmt.Fprintf(w, "\n  %s\n", st.Dim(fmt.Sprintf("Coverage: %d files scanned", result.Scan.FilesScanned)))
	}
	if line := output.SkippedSummary(result.Scan.Skipped); line != "" {
		fmt.Fprintf(w, "  %s\n", st.Dim(line))
	}
	if summary := output.IncompleteSummary(result.Scan); summary != "" {
		fmt.Fprintf(w, "\n  %s %s\n", st.SeverityIcon("CRITICAL"), st.RedBold(summary))
		for _, line := range output.IncompleteDetails(result.Scan) {
			fmt.Fprintf(w, "    %s\n", st.Dim(line))
		}
	}
	switch {
	case len(result.Scan.Findings) == 0 && result.Scan.Incomplete:
		fmt.Fprintf(w, "\n  %s %s\n", st.SeverityIcon("MEDIUM"), st.Yellow("No content findings in what was evaluated; the scan is incomplete."))
	case len(result.Scan.Findings) == 0 && result.Scan.FilesScanned == 0:
		fmt.Fprintf(w, "\n  %s %s\n", st.SeverityIcon("MEDIUM"), st.Yellow(output.NothingScannedMessage(result.Scan)))
	case len(result.Scan.Findings) == 0:
		fmt.Fprintf(w, "\n  %s\n", st.OK("No content findings."))
	default:
		// Cap the listing unless --verbose -- a noisy repo can dump
		// hundreds of low-severity findings into the audit output,
		// and showing all of them buries the verdict.
		const maxList = 10
		shown := 0
		fmt.Fprintln(w)
		for _, f := range result.Scan.Findings {
			if !flagAuditVerbose && shown >= maxList {
				break
			}
			label := f.Severity.String()
			fmt.Fprintf(w, "  %s %s %s %s\n",
				st.SeverityIcon(label),
				st.Bold(st.Cell(output.TerminalText(f.RuleID), 24)),
				st.Cell(output.TerminalText(f.RuleName), 36),
				st.Cyan(fmt.Sprintf("%s:%d", output.TerminalText(f.FilePath), f.Line)))
			shown++
		}
		if !flagAuditVerbose && len(result.Scan.Findings) > maxList {
			fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("... +%d more (rerun with --verbose or use --format json)",
				len(result.Scan.Findings)-maxList)))
		}
	}

	// Provenance line, unified with `aguara check`. Suppressed under --ci
	// (stdout stays verdict + findings); a stale local cache still notes
	// to stderr inside printIntelFreshness.
	if !flagAuditCI {
		fmt.Fprintln(w)
	}
	fprintIntelFreshness(w, os.Stderr, result.Intel, flagAuditCI)

	// Green is reserved for a clean pass: FINDINGS exits 0 but still
	// means unresolved findings exist, so it renders yellow with the
	// medium-tier icon; FAIL is red with the critical icon. A PASS that
	// triage still sends to review (nothing scanned, dependency files
	// not evaluated) is not a clean pass either.
	verdict := fmt.Sprintf("Verdict: %s", output.TerminalText(strings.ToUpper(result.Verdict.Status)))
	counts := fmt.Sprintf("(check: %d critical / %d warning, scan: %d critical / %d high)",
		result.Verdict.CheckCriticals, result.Verdict.CheckWarnings,
		result.Verdict.ScanCriticals, result.Verdict.ScanHighs)
	var line string
	switch {
	case result.Verdict.ThresholdExceeded:
		line = st.SeverityIcon("CRITICAL") + " " + st.RedBold(verdict) + " " + counts
	case result.Verdict.Status == "incomplete":
		line = st.SeverityIcon("CRITICAL") + " " + st.RedBold(verdict) + " " + counts + " " + st.Yellow("(content scan incomplete, see scan.errors)")
	case result.Verdict.Status == "findings":
		line = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold(verdict)) + " " + counts
	case result.Triage.Decision != "" && result.Triage.Decision != "proceed":
		line = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold(verdict)) + " " + counts
		if auditCoverageIncomplete(result.Triage) {
			// PASS only means no finding; say why triage still asks for review.
			line += " " + st.Yellow("(coverage incomplete, see triage)")
		}
	default:
		line = st.Green(st.Bold("✔ "+verdict)) + " " + counts
	}

	fmt.Fprintf(w, "\n%s\n  %s\n%s\n", sep, line, sep)

	if result.Triage.Decision != "" {
		var triageLine string
		switch result.Triage.Decision {
		case "stop":
			triageLine = st.SeverityIcon("CRITICAL") + " " + st.RedBold("Triage: STOP")
		case "review":
			triageLine = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold("Triage: REVIEW"))
		default:
			triageLine = st.Green(st.Bold("✔ Triage: PROCEED"))
		}
		fmt.Fprintf(w, "  %s\n", triageLine)
		if result.Triage.Summary != "" {
			fmt.Fprintf(w, "  %s\n", st.Dim(output.TerminalText(result.Triage.Summary)))
		}
		if len(result.Triage.RecommendedNextSteps) > 0 {
			fmt.Fprintf(w, "  %s\n", st.Dim("Next: "+output.TerminalText(result.Triage.RecommendedNextSteps[0])))
		}
	}

	if result.Handoff.Status != "" {
		var handoffLine string
		switch result.Handoff.Status {
		case "blocked":
			handoffLine = st.SeverityIcon("CRITICAL") + " " + st.RedBold("Agent handoff: BLOCKED")
		case "review_only":
			handoffLine = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold("Agent handoff: REVIEW ONLY"))
		default:
			handoffLine = st.Green(st.Bold("✔ Agent handoff: ALLOWED"))
		}
		fmt.Fprintf(w, "  %s\n", handoffLine)
		if result.Handoff.Summary != "" {
			fmt.Fprintf(w, "  %s\n", st.Dim(output.TerminalText(result.Handoff.Summary)))
		}
		if len(result.Handoff.AllowedActions) > 0 {
			fmt.Fprintf(w, "  %s\n", st.Dim("Allowed: "+output.TerminalText(result.Handoff.AllowedActions[0])))
		}
		if len(result.Handoff.BlockedActions) > 0 {
			fmt.Fprintf(w, "  %s\n", st.Dim("Blocked: "+output.TerminalText(result.Handoff.BlockedActions[0])))
		}
	}

	if result.Plan.TrustState != "" {
		execStatus := "yes"
		installStatus := "yes"
		if !result.Plan.CanExecuteProjectCode {
			execStatus = "no"
		}
		if !result.Plan.CanInstallDependencies {
			installStatus = "no"
		}
		fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("Action plan: install=%s execute=%s trust_state=%s",
			installStatus, execStatus, output.TerminalText(result.Plan.TrustState))))
	}

	if rule := topScanRule(result.Scan.Findings); rule != "" {
		fmt.Fprintf(w, "  %s\n", st.Dim("Next: aguara explain "+output.TerminalText(rule)))
	}
	return nil
}

// topScanRule returns the rule behind the most severe content finding,
// for the Next hint after the verdict.
func topScanRule(findings []scanner.Finding) string {
	best := -1
	rule := ""
	for _, f := range findings {
		if int(f.Severity) > best {
			best = int(f.Severity)
			rule = f.RuleID
		}
	}
	return rule
}

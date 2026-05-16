package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/discover"
	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/update"
	"github.com/garagon/aguara/internal/engine/ci"
	"github.com/garagon/aguara/internal/engine/jsrisk"
	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/pkgmeta"
	"github.com/garagon/aguara/internal/engine/rugpull"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/state"
	"github.com/garagon/aguara/internal/types"
)

var (
	flagFailOn      string
	flagCI          bool
	flagVerbose     bool
	flagChanged     bool
	flagMonitor     bool
	flagStatePath   string
	flagAuto        bool
	flagMaxFileSize string
	flagToolName    string
	flagProfile     string
	flagNoRedact    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for security issues",
	Args: func(cmd *cobra.Command, args []string) error {
		if flagAuto {
			if len(args) > 0 {
				return fmt.Errorf("--auto does not accept path arguments")
			}
			return nil
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "", "Exit with code 1 if findings at or above this severity (critical, high, medium, low)")
	scanCmd.Flags().BoolVar(&flagCI, "ci", false, "CI mode: equivalent to --fail-on high --format terminal --no-color")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show rule descriptions for critical and high findings")
	scanCmd.Flags().BoolVar(&flagChanged, "changed", false, "Only scan git-changed files (staged, unstaged, untracked)")
	scanCmd.Flags().BoolVar(&flagMonitor, "monitor", false, "Enable rug-pull detection: track file hashes across runs")
	scanCmd.Flags().StringVar(&flagStatePath, "state-path", "", "Path to state file for --monitor (default: ~/.aguara/state.json)")
	scanCmd.Flags().BoolVar(&flagAuto, "auto", false, "Auto-discover and scan all MCP client configs")
	scanCmd.Flags().StringVar(&flagMaxFileSize, "max-file-size", "", "Maximum file size to scan (e.g. 50MB, 100MB; default 50MB, range 1MB-500MB)")
	scanCmd.Flags().StringVar(&flagToolName, "tool-name", "", "Tool context for false-positive reduction (e.g. Bash, Edit, WebFetch)")
	scanCmd.Flags().StringVar(&flagProfile, "profile", "", "Scan profile: strict (default), content-aware, minimal")
	scanCmd.Flags().BoolVar(&flagNoRedact, "no-redact", false, "Keep raw matched text in credential-leak findings (default: redact to [REDACTED])")
	// Runtime errors (ErrThresholdExceeded after a successful scan,
	// network failures on --auto) should not trigger Cobra's
	// flag-usage block: a CI log that already says
	// "Error: findings exceed severity threshold" then prints the
	// full --help reads as a command-misuse error to non-technical
	// readers. Flag-parse errors still surface with a clear error
	// message; we just stop printing the usage block on top.
	scanCmd.SilenceUsage = true
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if flagAuto {
		return runAutoScan(cmd)
	}

	// Background update check
	var updateMsg string
	if !flagNoUpdateCheck {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if r := update.CheckLatest(Version, "garagon/aguara"); r != nil && r.NeedsUpdate() {
				updateMsg = fmt.Sprintf("\nUpdate available: %s → %s\n", r.Latest, r.UpdateURL)
			}
		}()
		defer func() {
			<-done
			if updateMsg != "" {
				fmt.Fprint(os.Stderr, updateMsg)
			}
		}()
	}

	targetPath := args[0]

	cfg := loadScanConfig(cmd, targetPath)
	applyCIDefaults()

	minSev, err := parseSeverityFlag()
	if err != nil {
		return err
	}

	compiled, err := loadAndCompileRules(cfg)
	if err != nil {
		return err
	}

	s, store := buildScanner(compiled, cfg, minSev)

	sp := startSpinnerIfTerminal(s, "Discovering files...")

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	result, err := executeScan(ctx, s, targetPath)
	stopSpinner(sp)
	if err != nil {
		return err
	}
	result.RulesLoaded = len(compiled)
	result.Target = targetPath

	if store != nil {
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving state: %v\n", err)
		}
	}

	if !flagNoRedact {
		types.RedactSensitiveFindings(result.Findings)
	}

	if err := writeOutput(result); err != nil {
		return err
	}

	return checkFailOnThreshold(result)
}

func runAutoScan(cmd *cobra.Command) error {
	discovered, err := discover.Scan()
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	if discovered.TotalClients() == 0 {
		fmt.Println("No MCP configurations found — nothing to scan.")
		return nil
	}

	// Collect unique config file paths
	var paths []string
	seen := map[string]bool{}
	for _, cr := range discovered.Clients {
		if !seen[cr.Path] {
			seen[cr.Path] = true
			paths = append(paths, cr.Path)
		}
	}

	fmt.Fprintf(os.Stderr, "Discovered %d MCP configs across %d clients, scanning...\n\n",
		len(paths), discovered.TotalClients())

	applyCIDefaults()

	minSev, err := parseSeverityFlag()
	if err != nil {
		return err
	}

	// Use empty config for auto mode (no per-target .aguara.yml)
	cfg := config.Config{}

	compiled, err := loadAndCompileRules(cfg)
	if err != nil {
		return err
	}

	s, store := buildScanner(compiled, cfg, minSev)

	sp := startSpinnerIfTerminal(s, "Scanning configs...")

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	// Aggregate findings from all config files
	aggregate := &scanner.ScanResult{
		RulesLoaded: len(compiled),
		Target:      "(auto-discovered)",
	}

	for i, path := range paths {
		if sp != nil {
			sp.Update(fmt.Sprintf("Scanning config %d/%d...", i+1, len(paths)))
		}
		result, scanErr := s.Scan(ctx, path)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "warning: scanning %s: %v\n", path, scanErr)
			continue
		}
		aggregate.Findings = append(aggregate.Findings, result.Findings...)
		aggregate.FilesScanned += result.FilesScanned
	}
	stopSpinner(sp)

	if store != nil {
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving state: %v\n", err)
		}
	}

	if !flagNoRedact {
		types.RedactSensitiveFindings(aggregate.Findings)
	}

	if err := writeOutput(aggregate); err != nil {
		return err
	}

	return checkFailOnThreshold(aggregate)
}

func loadScanConfig(cmd *cobra.Command, targetPath string) config.Config {
	cfg, err := config.Load(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if !cmd.Flags().Changed("severity") && cfg.Severity != "" {
		flagSeverity = cfg.Severity
	}
	if !cmd.Flags().Changed("format") && cfg.Format != "" {
		flagFormat = cfg.Format
	}
	if !cmd.Flags().Changed("fail-on") && cfg.FailOn != "" {
		flagFailOn = cfg.FailOn
	}
	if !cmd.Flags().Changed("rules") && cfg.Rules != "" {
		flagRules = cfg.Rules
	}
	return cfg
}

func applyCIDefaults() {
	if flagCI {
		if flagFailOn == "" {
			flagFailOn = "high"
		}
		if flagFormat == "terminal" {
			flagNoColor = true
		}
	}
	if os.Getenv("NO_COLOR") != "" {
		flagNoColor = true
	}
}

func parseSeverityFlag() (scanner.Severity, error) {
	if flagSeverity == "" {
		return scanner.SeverityInfo, nil
	}
	sev, err := scanner.ParseSeverity(flagSeverity)
	if err != nil {
		return 0, fmt.Errorf("invalid --severity: %w", err)
	}
	return sev, nil
}

func loadAndCompileRules(cfg config.Config) ([]*rules.CompiledRule, error) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return nil, fmt.Errorf("loading built-in rules: %w", err)
	}

	if flagRules != "" {
		rulesDir, err := filepath.Abs(flagRules)
		if err != nil {
			return nil, fmt.Errorf("resolving rules path: %w", err)
		}
		info, err := os.Stat(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("rules directory: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("--rules path is not a directory: %s", rulesDir)
		}
		customRules, err := rules.LoadFromDir(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules from %s: %w", rulesDir, err)
		}
		rawRules = append(rawRules, customRules...)
	}

	compiled, errs := rules.CompileAll(rawRules)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}

	if len(cfg.RuleOverrides) > 0 {
		overrides := make(map[string]rules.RuleOverride, len(cfg.RuleOverrides))
		for id, ovr := range cfg.RuleOverrides {
			overrides[id] = rules.RuleOverride{
				Severity:     ovr.Severity,
				Disabled:     ovr.Disabled,
				ApplyToTools: ovr.ApplyToTools,
				ExemptTools:  ovr.ExemptTools,
			}
		}
		var ovrErrs []error
		compiled, ovrErrs = rules.ApplyOverrides(compiled, overrides)
		for _, e := range ovrErrs {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}
	}

	if disableList := collectDisabledRules(cfg); len(disableList) > 0 {
		disabled := make(map[string]bool)
		for _, id := range disableList {
			disabled[id] = true
		}
		compiled = rules.FilterByIDs(compiled, disabled)
	}

	return compiled, nil
}

// collectDisabledRules merges the config file's disable_rules with the
// --disable-rule flag, trims whitespace, and drops empties. Returned once so
// both the pattern-rule filter and the scanner-pipeline filter see the same
// canonical list — analyzer-emitted rule IDs (GHA_*, TOXIC_*, etc.) need the
// pipeline-level filter because they never appear in the compiled rule list.
func collectDisabledRules(cfg config.Config) []string {
	raw := append([]string{}, cfg.DisableRules...)
	raw = append(raw, flagDisableRules...)
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func buildScanner(compiled []*rules.CompiledRule, cfg config.Config, minSev scanner.Severity) (*scanner.Scanner, *state.Store) {
	s := scanner.New(flagWorkers)
	s.SetMinSeverity(minSev)
	if disableList := collectDisabledRules(cfg); len(disableList) > 0 {
		s.SetDisabledRules(disableList)
	}
	if len(cfg.Ignore) > 0 {
		s.SetIgnorePatterns(cfg.Ignore)
	}

	if maxSize, err := parseMaxFileSize(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	} else if maxSize > 0 {
		s.SetMaxFileSize(maxSize)
	}

	if flagToolName != "" {
		s.SetToolName(flagToolName)
	}

	if profile, err := parseProfileFlag(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	} else if profile != scanner.ProfileStrict {
		s.SetScanProfile(profile)
	}

	// Propagate tool-scoped rule overrides from config
	if len(cfg.RuleOverrides) > 0 {
		toolScoped := make(map[string]scanner.ToolScopedRule)
		for id, ovr := range cfg.RuleOverrides {
			if len(ovr.ApplyToTools) > 0 || len(ovr.ExemptTools) > 0 {
				toolScoped[id] = scanner.ToolScopedRule{
					ApplyToTools: ovr.ApplyToTools,
					ExemptTools:  ovr.ExemptTools,
				}
			}
		}
		if len(toolScoped) > 0 {
			s.SetToolScopedRules(toolScoped)
		}
	}

	s.RegisterAnalyzer(pattern.NewMatcher(compiled))
	s.RegisterAnalyzer(ci.New())
	s.RegisterAnalyzer(pkgmeta.New())
	s.RegisterAnalyzer(jsrisk.New())
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	s.RegisterAnalyzer(toxicflow.New())
	s.SetCrossFileAccumulator(toxicflow.NewCrossFileAnalyzer())

	var store *state.Store
	if flagMonitor {
		statePath := flagStatePath
		if statePath == "" {
			statePath = state.DefaultPath()
		}
		store = state.New(statePath)
		if err := store.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: loading state: %v\n", err)
		}
		s.RegisterAnalyzer(rugpull.New(store))
	}

	return s, store
}

func contextWithInterrupt() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()
	return ctx, cancel
}

func executeScan(ctx context.Context, s *scanner.Scanner, targetPath string) (*scanner.ScanResult, error) {
	if flagChanged {
		return scanChangedFiles(ctx, s, targetPath)
	}
	result, err := s.Scan(ctx, targetPath)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	return result, nil
}

func scanChangedFiles(ctx context.Context, s *scanner.Scanner, targetPath string) (*scanner.ScanResult, error) {
	changedFiles, err := scanner.GitChangedFiles(targetPath)
	if err != nil {
		return nil, fmt.Errorf("getting changed files: %w", err)
	}
	var targets []*scanner.Target
	for _, relPath := range changedFiles {
		absPath := filepath.Join(targetPath, relPath)
		// Lstat instead of Stat so a symlink doesn't resolve to its target.
		// The normal directory walk already skips symlinks (internal/scanner/target.go
		// in the walk callback); --changed gets file paths from git and must do the
		// same check, otherwise a malicious symlink committed to the repo would make
		// aguara read files outside the tree and surface their contents in findings.
		info, err := os.Lstat(absPath)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		targets = append(targets, &scanner.Target{
			Path:    absPath,
			RelPath: relPath,
		})
	}
	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	return result, nil
}

func writeOutput(result *scanner.ScanResult) error {
	output.ToolVersion = Version

	var formatter output.Formatter
	switch strings.ToLower(flagFormat) {
	case "json":
		formatter = &output.JSONFormatter{}
	case "sarif":
		formatter = &output.SARIFFormatter{}
	case "markdown", "md":
		formatter = &output.MarkdownFormatter{}
	default:
		formatter = &output.TerminalFormatter{NoColor: flagNoColor, Verbose: flagVerbose}
	}

	w := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	return formatter.Format(w, result)
}

func isTerminalFormat() bool {
	f := strings.ToLower(flagFormat)
	return f == "terminal" || f == ""
}

func startSpinnerIfTerminal(s *scanner.Scanner, message string) *output.Spinner {
	if !isTerminalFormat() {
		return nil
	}
	sp := output.NewSpinner(os.Stderr)
	sp.Start(message)
	s.SetProgressFunc(func(current, total int) {
		sp.Update(fmt.Sprintf("Scanning %d/%d files...", current, total))
	})
	return sp
}

func stopSpinner(sp *output.Spinner) {
	if sp != nil {
		sp.Stop()
	}
}

// parseMaxFileSize resolves the max-file-size from flag or config.
// Returns 0 if neither is set (use default).
func parseMaxFileSize(cfg config.Config) (int64, error) {
	if flagMaxFileSize != "" {
		v, err := parseByteSize(flagMaxFileSize)
		if err != nil {
			return 0, fmt.Errorf("invalid --max-file-size: %w", err)
		}
		return config.ValidateMaxFileSize(v)
	}
	if cfg.MaxFileSize > 0 {
		return config.ValidateMaxFileSize(cfg.MaxFileSize)
	}
	return 0, nil
}

// parseByteSize parses human-readable byte sizes like "50MB", "100mb", "1GB".
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size value")
	}

	// Find where the numeric part ends
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	numStr := s[:i]
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("cannot parse %q as byte size", s)
	}

	switch unit {
	case "", "B":
		return int64(num), nil
	case "KB", "K":
		return int64(num * 1024), nil
	case "MB", "M":
		return int64(num * 1024 * 1024), nil
	case "GB", "G":
		return int64(num * 1024 * 1024 * 1024), nil
	default:
		return 0, fmt.Errorf("unknown size unit %q in %q", unit, s)
	}
}

func parseProfileFlag() (scanner.ScanProfile, error) {
	switch strings.ToLower(strings.TrimSpace(flagProfile)) {
	case "", "strict":
		return scanner.ProfileStrict, nil
	case "content-aware":
		return scanner.ProfileContentAware, nil
	case "minimal":
		return scanner.ProfileMinimal, nil
	default:
		return scanner.ProfileStrict, fmt.Errorf("invalid --profile %q: use strict, content-aware, or minimal", flagProfile)
	}
}

// ErrThresholdExceeded is returned when findings meet or exceed the --fail-on severity.
var ErrThresholdExceeded = fmt.Errorf("findings exceed severity threshold")

func checkFailOnThreshold(result *scanner.ScanResult) error {
	if flagFailOn == "" {
		return nil
	}
	threshold, err := scanner.ParseSeverity(flagFailOn)
	if err != nil {
		return fmt.Errorf("invalid --fail-on: %w", err)
	}
	for _, f := range result.Findings {
		if f.Severity >= threshold {
			return ErrThresholdExceeded
		}
	}
	return nil
}

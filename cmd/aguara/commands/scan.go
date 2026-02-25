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
	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/rugpull"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/state"
)

var (
	flagFailOn    string
	flagCI        bool
	flagVerbose   bool
	flagChanged   bool
	flagMonitor   bool
	flagStatePath string
	flagAuto      bool
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
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if flagAuto {
		return runAutoScan(cmd)
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

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	result, err := executeScan(ctx, s, targetPath)
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

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	// Aggregate findings from all config files
	aggregate := &scanner.ScanResult{
		RulesLoaded: len(compiled),
		Target:      "(auto-discovered)",
	}

	for _, path := range paths {
		result, scanErr := s.Scan(ctx, path)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "warning: scanning %s: %v\n", path, scanErr)
			continue
		}
		aggregate.Findings = append(aggregate.Findings, result.Findings...)
		aggregate.FilesScanned += result.FilesScanned
	}

	if store != nil {
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving state: %v\n", err)
		}
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
		customRules, err := rules.LoadFromDir(flagRules)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules from %s: %w", flagRules, err)
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
			overrides[id] = rules.RuleOverride{Severity: ovr.Severity, Disabled: ovr.Disabled}
		}
		var ovrErrs []error
		compiled, ovrErrs = rules.ApplyOverrides(compiled, overrides)
		for _, e := range ovrErrs {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}
	}

	if len(flagDisableRules) > 0 {
		disabled := make(map[string]bool)
		for _, id := range flagDisableRules {
			disabled[strings.TrimSpace(id)] = true
		}
		compiled = rules.FilterByIDs(compiled, disabled)
	}

	return compiled, nil
}

func buildScanner(compiled []*rules.CompiledRule, cfg config.Config, minSev scanner.Severity) (*scanner.Scanner, *state.Store) {
	s := scanner.New(flagWorkers)
	s.SetMinSeverity(minSev)
	if len(cfg.Ignore) > 0 {
		s.SetIgnorePatterns(cfg.Ignore)
	}

	s.RegisterAnalyzer(pattern.NewMatcher(compiled))
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	s.RegisterAnalyzer(toxicflow.New())

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
		if _, err := os.Stat(absPath); err != nil {
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
			os.Exit(1)
		}
	}
	return nil
}

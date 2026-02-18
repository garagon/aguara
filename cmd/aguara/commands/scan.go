package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
)

var (
	flagFailOn  string
	flagCI      bool
	flagVerbose bool
	flagChanged bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan a directory for security issues",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "", "Exit with code 1 if findings at or above this severity (critical, high, medium, low)")
	scanCmd.Flags().BoolVar(&flagCI, "ci", false, "CI mode: equivalent to --fail-on high --format terminal --no-color")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show rule descriptions for critical and high findings")
	scanCmd.Flags().BoolVar(&flagChanged, "changed", false, "Only scan git-changed files (staged, unstaged, untracked)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	// Load config file
	cfg, err := config.Load(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	// Apply config defaults (CLI flags take precedence)
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

	// CI mode defaults
	if flagCI {
		if flagFailOn == "" {
			flagFailOn = "high"
		}
		if flagFormat == "terminal" {
			flagNoColor = true
		}
	}

	// Check NO_COLOR env var
	if os.Getenv("NO_COLOR") != "" {
		flagNoColor = true
	}

	// Parse minimum severity
	minSev := scanner.SeverityInfo
	if flagSeverity != "" {
		sev, err := scanner.ParseSeverity(flagSeverity)
		if err != nil {
			return fmt.Errorf("invalid --severity: %w", err)
		}
		minSev = sev
	}

	// Load built-in rules
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return fmt.Errorf("loading built-in rules: %w", err)
	}

	// Load custom rules if specified
	if flagRules != "" {
		customRules, err := rules.LoadFromDir(flagRules)
		if err != nil {
			return fmt.Errorf("loading custom rules from %s: %w", flagRules, err)
		}
		rawRules = append(rawRules, customRules...)
	}

	// Compile rules
	compiled, errs := rules.CompileAll(rawRules)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}
	}

	// Apply config rule overrides
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

	// Apply --disable-rule flag
	if len(flagDisableRules) > 0 {
		disabled := make(map[string]bool)
		for _, id := range flagDisableRules {
			disabled[strings.TrimSpace(id)] = true
		}
		compiled = rules.FilterByIDs(compiled, disabled)
	}

	// Create scanner
	s := scanner.New(flagWorkers)
	s.SetMinSeverity(minSev)
	if len(cfg.Ignore) > 0 {
		s.SetIgnorePatterns(cfg.Ignore)
	}

	// Register analyzers
	s.RegisterAnalyzer(pattern.NewMatcher(compiled))
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())

	// Create context with cancellation (Ctrl+C)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	// Run scan
	var result *scanner.ScanResult
	if flagChanged {
		changedFiles, err := scanner.GitChangedFiles(targetPath)
		if err != nil {
			return fmt.Errorf("getting changed files: %w", err)
		}
		var targets []*scanner.Target
		for _, relPath := range changedFiles {
			absPath := filepath.Join(targetPath, relPath)
			if _, err := os.Stat(absPath); err != nil {
				continue // skip deleted files
			}
			targets = append(targets, &scanner.Target{
				Path:    absPath,
				RelPath: relPath,
			})
		}
		result, err = s.ScanTargets(ctx, targets)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
	} else {
		result, err = s.Scan(ctx, targetPath)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
	}
	result.RulesLoaded = len(compiled)
	result.Target = targetPath

	// Set tool version for SARIF output
	output.ToolVersion = Version

	// Select formatter
	var formatter output.Formatter
	switch strings.ToLower(flagFormat) {
	case "json":
		formatter = &output.JSONFormatter{}
	case "sarif":
		formatter = &output.SARIFFormatter{}
	default:
		formatter = &output.TerminalFormatter{NoColor: flagNoColor, Verbose: flagVerbose}
	}

	// Select output writer
	w := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	if err := formatter.Format(w, result); err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}

	// Check --fail-on threshold
	if flagFailOn != "" {
		threshold, err := scanner.ParseSeverity(flagFailOn)
		if err != nil {
			return fmt.Errorf("invalid --fail-on: %w", err)
		}
		for _, f := range result.Findings {
			if f.Severity >= threshold {
				os.Exit(1)
			}
		}
	}

	return nil
}

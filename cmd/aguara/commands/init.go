package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	flagHook   bool
	flagCIOnly bool
)

var initCmd = &cobra.Command{
	Use:   "init [path]",
	Short: "Initialize Aguara configuration files",
	Long:  `Scaffolds .aguara.yml, .aguaraignore, and a GitHub Actions workflow for Aguara scanning.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&flagHook, "hook", false, "Create a git pre-commit hook that runs Aguara")
	initCmd.Flags().BoolVar(&flagCIOnly, "ci", false, "Only generate GitHub Actions workflow (skip config files)")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	if flagHook {
		return initHook(dir)
	}

	if flagCIOnly {
		return initCIOnly(dir)
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	files := []struct {
		path    string
		content string
	}{
		{
			path:    filepath.Join(dir, ".aguara.yml"),
			content: configTemplate,
		},
		{
			path:    filepath.Join(dir, ".aguaraignore"),
			content: ignoreTemplate,
		},
		{
			path:    filepath.Join(dir, ".github", "workflows", "aguara.yml"),
			content: workflowTemplateV2,
		},
	}

	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			fmt.Printf("  skip %s (already exists)\n", f.path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.path), 0755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", f.path, err)
		}
		if err := os.WriteFile(f.path, []byte(f.content), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
		fmt.Printf("  create %s\n", f.path)
	}

	return nil
}

func initHook(dir string) error {
	gitDir := filepath.Join(dir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("no .git directory found in %s (is this a git repository?)", dir)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err == nil {
		fmt.Printf("  skip %s (already exists)\n", hookPath)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
		return fmt.Errorf("creating hooks directory: %w", err)
	}
	if err := os.WriteFile(hookPath, []byte(preCommitTemplate), 0755); err != nil {
		return fmt.Errorf("writing pre-commit hook: %w", err)
	}
	fmt.Printf("  create %s\n", hookPath)
	return nil
}

func initCIOnly(dir string) error {
	wfPath := filepath.Join(dir, ".github", "workflows", "aguara.yml")
	if _, err := os.Stat(wfPath); err == nil {
		fmt.Printf("  skip %s (already exists)\n", wfPath)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(wfPath), 0755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", wfPath, err)
	}
	if err := os.WriteFile(wfPath, []byte(workflowTemplateV2), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", wfPath, err)
	}
	fmt.Printf("  create %s\n", wfPath)
	return nil
}

const configTemplate = `# Aguara security scanner configuration
# https://github.com/garagon/aguara

# Paths to scan (default: current directory)
# paths:
#   - .

# File patterns to ignore
ignore:
  - "*.log"
  - "vendor/"
  - "node_modules/"
  - ".git/"

# Minimum severity to report: critical, high, medium, low, info
severity: info

# Exit with code 1 if findings at or above this severity
# fail_on: high

# Output format: terminal, json, sarif
format: terminal

# Additional rules directory
# rules: custom-rules/

# Per-rule overrides
# rule_overrides:
#   PROMPT_INJECTION_001:
#     severity: medium
#   EXFIL_005:
#     disabled: true
`

const ignoreTemplate = `# Aguara ignore patterns
# Files matching these patterns will be skipped during scanning

# Dependencies
vendor/
node_modules/
.venv/
__pycache__/

# Build artifacts
dist/
build/
bin/
*.exe
*.dll
*.so

# IDE and editor
.idea/
.vscode/
*.swp
*.swo

# Logs and temp
*.log
tmp/
temp/

# Test coverage
coverage/
*.cover
`

const preCommitTemplate = `#!/bin/sh
# Aguara pre-commit hook
echo "Running Aguara security scan..."
aguara scan . --fail-on high --no-color
exit $?
`

const workflowTemplateV2 = `name: Aguara Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read
  pull-requests: write

jobs:
  aguara:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Cache Aguara binary
        uses: actions/cache@v4
        with:
          path: ./aguara
          key: aguara-linux-amd64

      - name: Install Aguara
        run: |
          if [ ! -f ./aguara ]; then
            curl -sSL https://github.com/garagon/aguara/releases/latest/download/aguara-linux-amd64 -o aguara
            chmod +x aguara
          fi

      - name: Run Aguara scan
        id: scan
        continue-on-error: true
        run: ./aguara scan . --format sarif --output results.sarif --fail-on high

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Comment on PR
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const sarif = JSON.parse(fs.readFileSync('results.sarif', 'utf8'));
            const results = sarif.runs[0].results || [];
            const counts = {};
            results.forEach(r => { counts[r.level] = (counts[r.level] || 0) + 1; });
            const lines = ['## Aguara Security Scan', ''];
            if (results.length === 0) {
              lines.push('No security issues found.');
            } else {
              lines.push('| Level | Count |', '|-------|-------|');
              for (const [level, count] of Object.entries(counts)) {
                lines.push('| ' + level + ' | ' + count + ' |');
              }
            }
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: lines.join('\n')
            });

      - name: Fail on findings
        if: steps.scan.outcome == 'failure'
        run: exit 1
`

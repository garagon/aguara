package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/garagon/aguara/internal/output"
	"github.com/spf13/cobra"
)

var (
	flagHook   bool
	flagCIOnly bool
)

var initCmd = &cobra.Command{
	Use:     "init [path]",
	GroupID: groupSetup,
	Short:   "Initialize Aguara configuration files",
	Long:    "Scaffolds .aguara.yml, .aguaraignore, and a GitHub Actions workflow for Aguara scanning.",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runInit,
}

func init() {
	initCmd.Flags().BoolVar(&flagHook, "hook", false, "Create a git pre-commit hook that runs Aguara")
	initCmd.Flags().BoolVar(&flagCIOnly, "ci", false, "Only generate GitHub Actions workflow (skip config files)")
	rootCmd.AddCommand(initCmd)
}

type scaffoldFile struct {
	path    string
	content string
	mode    os.FileMode
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
	return initFiles(dir, false, []scaffoldFile{
		{".aguara.yml", configTemplate, 0o644},
		{".aguaraignore", ignoreTemplate, 0o644},
		{filepath.Join(".github", "workflows", "aguara.yml"), workflowTemplateV2, 0o644},
	})
}

func initHook(dir string) error {
	return initFiles(dir, true, []scaffoldFile{
		{filepath.Join(".git", "hooks", "pre-commit"), preCommitTemplate, 0o755},
	})
}

func initCIOnly(dir string) error {
	return initFiles(dir, false, []scaffoldFile{
		{filepath.Join(".github", "workflows", "aguara.yml"), workflowTemplateV2, 0o644},
	})
}

func initFiles(dir string, requireGit bool, files []scaffoldFile) error {
	if !requireGit {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if requireGit {
		info, err := root.Stat(".git")
		if err != nil {
			return fmt.Errorf("no .git directory found in %s: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf(".git is not a directory in %s", dir)
		}
	}
	for _, file := range files {
		created, err := createScaffoldFile(root, file.path, file.content, file.mode)
		if err != nil {
			return fmt.Errorf("writing %s: %w", file.path, err)
		}
		path := output.TerminalText(filepath.Join(dir, file.path))
		if created {
			fmt.Printf("  create %s\n", path)
		} else {
			fmt.Printf("  skip %s (already exists)\n", path)
		}
	}
	return nil
}

// The selected root is caller-owned. Rooted operations confine descendant paths
// on native CLI platforms; exclusive creation never truncates an existing leaf.
func createScaffoldFile(root *os.Root, name, content string, perm os.FileMode) (bool, error) {
	info, err := root.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() && !info.IsDir() {
			return false, fmt.Errorf("output %s is not a regular file or directory", name)
		}
		return false, nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return false, err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	if writeErr != nil {
		return false, writeErr
	}
	return closeErr == nil, closeErr
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

// workflowTemplateV2 is the GitHub Actions workflow scaffolded by
// `aguara init`. It uses the official `garagon/aguara` action so
// the workflow gets:
//
//   - install.sh-backed binary install with mandatory checksum
//     verification (no manual curl + 404 risk),
//   - SARIF upload to Code Scanning out of the box,
//   - automatic version pinning matching whatever tag the user
//     pins the `uses:` ref to.
//
// The action ref is pinned to the v0.28.0 tag rather than `@v1`
// (which exists but lags significantly behind point releases). New
// projects get a reproducible, dependabot-friendly pin; users who
// want floating-major can edit the ref themselves.
//
// The 'Comment on PR' step is kept so the workflow feels complete
// out of the box; it reads from the action's default SARIF output
// path (aguara-results.sarif).
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

      - name: Run Aguara security scan
        id: scan
        uses: garagon/aguara@v0.28.0
        with:
          path: .
          fail-on: high
          # Pin the actual Aguara BINARY version too. Without this,
          # the action's install step calls install.sh with no
          # version override and fetches whatever release is
          # "latest" at run time -- so the scanner code can drift
          # away from the action ref above without notice.
          version: v0.28.0
          # SARIF results land at aguara-results.sarif and are
          # uploaded to GitHub Code Scanning automatically. Set
          # upload-sarif: 'false' to disable that upload.

      - name: Comment summary on PR
        if: github.event_name == 'pull_request' && always() && hashFiles('aguara-results.sarif') != ''
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const sarif = JSON.parse(fs.readFileSync('aguara-results.sarif', 'utf8'));
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
`

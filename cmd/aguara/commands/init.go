package commands

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	Long: `Scaffolds .aguara.yml, .aguaraignore and a GitHub Actions workflow that
runs aguara audit. Existing files are never overwritten.

.aguara.yml and .aguaraignore apply to local aguara scan runs. aguara audit,
aguara scan --ci, the GitHub Action and the scaffolded workflow do not apply
them, and aguara scan in a detected CI environment applies only fail_on, so
a change under review cannot hide its own findings.

With --hook, writes a git pre-commit hook instead: it scans the staged
version of added and modified files and blocks the commit on HIGH or
CRITICAL findings. With --ci, writes only the workflow.`,
	Example: `  aguara init                Scaffold config, ignore file and workflow here
  aguara init --ci           Only the GitHub Actions workflow
  aguara init --hook         Install a pre-commit hook in this git checkout`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
	// Errors such as "not inside a git work tree" explain themselves; the
	// usage block would only bury them.
	SilenceUsage: true,
}

func init() {
	initCmd.Flags().BoolVar(&flagHook, "hook", false, "Create a git pre-commit hook that scans staged files with Aguara")
	initCmd.Flags().BoolVar(&flagCIOnly, "ci", false, "Only generate the GitHub Actions workflow (skip config files)")
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
	created, err := initFiles(dir, []scaffoldFile{
		{".aguara.yml", configTemplate, 0o644},
		{".aguaraignore", ignoreTemplate, 0o644},
		{workflowPath, workflowTemplateV2, 0o644},
	})
	if err != nil {
		return err
	}
	printNextSteps(nextStepsInit(created[workflowPath]))
	return nil
}

var workflowPath = filepath.Join(".github", "workflows", "aguara.yml")

// initHook writes the pre-commit hook where git runs it: the hooks
// directory git reports for dir, which also covers linked worktrees and
// core.hooksPath.
func initHook(dir string) error {
	hooksDir, err := gitHooksDir(dir)
	if err != nil {
		return err
	}
	base, name := dir, filepath.Join(hooksDir, "pre-commit")
	if rel, ok := insideDir(dir, name); ok {
		// Keep the rooted, link-safe creation relative to the checkout.
		name = rel
	} else {
		if err := os.MkdirAll(hooksDir, 0o755); err != nil {
			return err
		}
		base, name = hooksDir, "pre-commit"
	}
	created, err := initFiles(base, []scaffoldFile{{name, preCommitTemplate, 0o755}})
	if err != nil {
		return err
	}
	printNextSteps(nextStepsHook(created[name]))
	return nil
}

func initCIOnly(dir string) error {
	created, err := initFiles(dir, []scaffoldFile{
		{workflowPath, workflowTemplateV2, 0o644},
	})
	if err != nil {
		return err
	}
	printNextSteps(nextStepsWorkflow(created[workflowPath]))
	return nil
}

// gitHooksDir returns the hooks directory git uses for the work tree that
// contains dir, or an error that says what to do when dir is not in one.
func gitHooksDir(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("init --hook: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("init --hook: %s is not a directory", dir)
	}
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("init --hook needs git on PATH: %w", err)
	}
	notRepo := fmt.Errorf("init --hook: %s is not inside a git work tree; run it from a git checkout (git init creates one), or use aguara init without --hook", dir)
	out, err := gitIn(dir, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		return "", notRepo
	}
	out, err = gitIn(dir, "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", fmt.Errorf("init --hook: cannot locate the git hooks directory: %w", err)
	}
	hooks := strings.TrimRight(out, "\r\n")
	if hooks == "" {
		return "", errors.New("init --hook: git reported no hooks directory")
	}
	if !filepath.IsAbs(hooks) {
		hooks = filepath.Join(dir, hooks)
	}
	return hooks, nil
}

// gitIn runs git in dir and returns stdout; a failure carries git's stderr.
func gitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
				return "", fmt.Errorf("git %s: %s", args[0], msg)
			}
		}
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return string(out), nil
}

// insideDir returns path relative to dir when it lies inside dir.
func insideDir(dir, path string) (string, bool) {
	absDir, err1 := filepath.Abs(dir)
	absPath, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return "", false
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// initFiles creates each file under dir unless it already exists, and
// reports which ones it created.
func initFiles(dir string, files []scaffoldFile) (map[string]bool, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	created := make(map[string]bool, len(files))
	for _, file := range files {
		ok, err := createScaffoldFile(root, file.path, file.content, file.mode)
		if err != nil {
			return nil, fmt.Errorf("writing %s: %w", file.path, err)
		}
		created[file.path] = ok
		path := output.TerminalText(filepath.Join(dir, file.path))
		if ok {
			fmt.Printf("  create %s\n", path)
		} else {
			fmt.Printf("  skip %s (already exists)\n", path)
		}
	}
	return created, nil
}

func printNextSteps(lines []string) {
	fmt.Println()
	fmt.Println("Next steps:")
	for _, line := range lines {
		fmt.Println("  " + line)
	}
}

func nextStepsInit(workflowCreated bool) []string {
	workflow := "3. Commit .github/workflows/aguara.yml to run the audit on pushes and pull requests."
	if !workflowCreated {
		workflow = "3. Your existing .github/workflows/aguara.yml was left unchanged."
	}
	return []string{
		"1. Review .aguara.yml and .aguaraignore. They apply to local `aguara scan` runs only.",
		"2. Run `aguara audit .` to check dependencies and content before installing or running anything.",
		workflow,
		"4. Optional: `aguara init --hook` scans staged files before each commit.",
	}
}

func nextStepsWorkflow(created bool) []string {
	if !created {
		return []string{"The existing workflow was left unchanged; remove it and run `aguara init --ci` again to get the current one."}
	}
	return []string{
		"Commit .github/workflows/aguara.yml. It runs `aguara audit . --ci` on pushes to main and on pull requests,",
		"uploads content findings to code scanning where available, and writes a summary on the job page.",
	}
}

func nextStepsHook(created bool) []string {
	if !created {
		return []string{
			"An existing pre-commit hook was left unchanged. Remove it and run `aguara init --hook` again,",
			"or call Aguara from it (see the hook `aguara init --hook` writes in a new repository).",
		}
	}
	return []string{
		"Commit as usual. The hook scans the staged version of added and modified files and blocks the",
		"commit on HIGH or CRITICAL findings. It needs aguara on PATH, or AGUARA_BIN set to the binary.",
		"Skip it once with `git commit --no-verify`.",
	}
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

const configTemplate = `# Aguara configuration for local scans.
# https://github.com/garagon/aguara
#
# Local aguara scan runs apply this file. aguara audit, aguara scan --ci and
# the GitHub Action ignore it, and a scan in a detected CI environment applies
# only fail_on, so a change under review cannot hide its own findings.

# Minimum severity to report: critical, high, medium, low, info
severity: info

# Exit with code 1 if findings reach this severity
# fail_on: high

# Output format: terminal, json, sarif, markdown
format: terminal

# More patterns to skip, in the .aguaraignore syntax
# ignore:
#   - "generated/"

# Additional rules directory
# rules: custom-rules/

# Per-rule overrides
# rule_overrides:
#   PROMPT_INJECTION_001:
#     severity: medium
#   EXFIL_005:
#     disabled: true
`

const ignoreTemplate = `# Aguara ignore patterns for local scans.
#
# Local aguara scan runs skip what this file lists. aguara audit, aguara
# scan --ci, the GitHub Action and scans in a detected CI environment ignore
# this file, so a change under review cannot hide files from them.
#
# "name/" skips every directory with that name and everything in it,
# "/name" only the one at the project root, "*.log" matches file names
# anywhere and "dir/**" everything under dir. A name without a slash matches
# files only. Negation (!) is not supported. node_modules/ and .git/ are
# always skipped.

# Dependencies and virtual environments
vendor/
.venv/
__pycache__/

# Build output
dist/
build/

# Logs, temporary files and coverage
*.log
tmp/
temp/
coverage/
*.cover
*.swp
*.swo
`

// preCommitTemplate is the hook `aguara init --hook` writes. It scans the
// index, not the work tree: `scan --changed` reads the work tree copy of
// files that differ from HEAD plus untracked files, so a hook built on it
// could pass a commit whose staged content differs from what it read.
const preCommitTemplate = `#!/bin/sh
# Aguara pre-commit hook, written by aguara init --hook.
#
# Scans the staged version of every added, copied, modified, renamed or
# type-changed file, which is what the commit will contain, and blocks the
# commit on HIGH or CRITICAL findings. Skip it once with
# git commit --no-verify. Set AGUARA_BIN to run another aguara binary.
set -eu

aguara=${AGUARA_BIN:-aguara}
if ! command -v "$aguara" >/dev/null 2>&1; then
	echo "aguara pre-commit hook: $aguara not found; install Aguara or set AGUARA_BIN" >&2
	exit 1
fi

# Nothing staged with content to scan.
if git diff --cached --quiet --diff-filter=ACMRT; then
	exit 0
fi

tmpdir=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmpdir%/}/aguara-pre-commit.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$tmp/staged"

# Copy the staged blobs out of the index. NUL-separated names keep paths
# with spaces or newlines intact. The staged .aguara.yml and .aguaraignore
# come along so local exclusions apply as they do for aguara scan.
git diff --cached --name-only -z --diff-filter=ACMRT >"$tmp/list"
for f in .aguara.yml .aguara.yaml .aguaraignore; do
	if git cat-file -e ":$f" 2>/dev/null; then
		printf '%s\0' "$f" >>"$tmp/list"
	fi
done
git checkout-index -f -z --stdin --prefix="$tmp/staged/" <"$tmp/list"

set +e
"$aguara" scan "$tmp/staged" --fail-on high --no-update-check
status=$?
set -e
if [ "$status" -ne 0 ]; then
	echo "aguara pre-commit hook: commit blocked (exit $status); paths are relative to the repository root" >&2
fi
exit "$status"
`

// workflowTemplateV2 is the GitHub Actions workflow scaffolded by
// `aguara init`. It runs `aguara audit . --ci`, the command the README
// recommends for CI, with the binary the official action installs (pinned
// release, checksum-verified install.sh). The action step also uploads its
// SARIF to code scanning; that upload is skipped for fork pull requests
// and when the AGUARA_UPLOAD_SARIF repository variable is "false", and a
// failed upload does not fail the job. A job summary replaces the PR
// comment earlier scaffolds posted on every push, which needed write
// permission fork pull requests do not get.
//
// Third-party actions are pinned to a full commit SHA, the Aguara action
// to its release tag (checked by .github/scripts/check-version-pins.sh).
// The project-policy flag is explicit so the result does not depend on
// CI detection.
const workflowTemplateV2 = `# Aguara security checks, scaffolded by aguara init.
#
# Runs aguara audit (known-malicious packages plus a content scan) and fails
# on CRITICAL findings. Content findings go to GitHub code scanning where it
# is available, and the audit report is written to the job summary.
# Policy files in this repository (.aguara.yml, .aguaraignore, inline
# aguara-ignore directives) are not applied, so a pull request cannot hide
# its own findings. Change main below if your default branch differs.
name: Aguara

on:
  push:
    branches: [main]
  pull_request:

permissions: {}

jobs:
  aguara:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      # Upload of content findings to code scanning. Private repositories
      # also need actions: read for that upload.
      security-events: write
      actions: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Install Aguara and upload content findings
        uses: garagon/aguara@v0.29.0
        with:
          path: .
          # Pin the Aguara binary as well as the action.
          version: v0.29.0
          # Fork pull requests cannot write to code scanning. Set the
          # repository variable AGUARA_UPLOAD_SARIF to false where code
          # scanning is not available. A failed upload never fails the job.
          upload-sarif: ${{ vars.AGUARA_UPLOAD_SARIF != 'false' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}

      - name: Audit dependencies and content
        shell: bash
        run: |
          set +e
          aguara audit . --ci --project-policy ignore --no-color --no-update-check >aguara-audit.txt 2>&1
          status=$?
          cat aguara-audit.txt
          exit "$status"

      - name: Write job summary
        if: always()
        shell: bash
        run: |
          {
            echo "## Aguara audit"
            echo
            if [ -s aguara-audit.txt ]; then
              echo "<pre>"
              head -c 900000 aguara-audit.txt | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
              echo "</pre>"
            else
              echo "The audit did not run or wrote no report; see the job log."
            fi
          } >>"$GITHUB_STEP_SUMMARY"
`

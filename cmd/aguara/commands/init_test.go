package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/garagon/aguara/internal/config"
)

// gitRepo creates an empty git repository and returns its path. Global
// and system git configuration are ignored so a developer's hooksPath or
// templates cannot change the result.
func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	return dir
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := c.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return string(out)
}

func TestInitCreatesFiles(t *testing.T) {
	dir := t.TempDir()

	var err error
	captureStdoutBytes(t, func() { err = runInit(nil, []string{dir}) })
	require.NoError(t, err)

	// Check all files were created
	for _, name := range []string{
		".aguara.yml",
		".aguaraignore",
		filepath.Join(".github", "workflows", "aguara.yml"),
	} {
		path := filepath.Join(dir, name)
		_, err := os.Stat(path)
		require.NoError(t, err, "expected %s to exist", name)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotEmpty(t, data, "expected %s to have content", name)
	}
}

func TestInitWorkflowUsesActionNotBrokenAsset(t *testing.T) {
	// QA regression on v0.16.0: the scaffolded workflow downloaded
	// `aguara-linux-amd64` from /releases/latest/download/, an asset
	// shape that does not exist (release assets are tar.gz archives
	// like `aguara_0.16.0_linux_amd64.tar.gz`). The curl 404'd and
	// every new-user CI job broke at install.
	//
	// The workflow must now:
	//   1. NOT reference the broken `aguara-linux-amd64` asset,
	//   2. NOT manually curl install.sh in the workflow itself
	//      (the action does that with checksum verification),
	//   3. USE the official `garagon/aguara` action so version pin
	//      + checksum verify happen via the action's contract.
	body := workflowTemplateV2

	require.NotContains(t, body, "aguara-linux-amd64",
		"workflow must not reference the non-existent aguara-linux-amd64 asset (release assets are tar.gz archives)")
	require.NotContains(t, body, "/releases/latest/download/aguara",
		"workflow must not curl release assets directly; the action handles install + checksum")
	require.NotContains(t, body, "curl")
	require.True(t, strings.Contains(body, "uses: garagon/aguara@"),
		"workflow must invoke the official garagon/aguara action so version pin + checksum verify are guaranteed")

	// The action ref alone does NOT pin the binary version (the
	// action's `version` input defaults to empty -> install.sh fetches
	// whatever is latest at run time). The scaffold MUST also set the
	// `version:` input so the installed CLI is reproducible across runs.
	require.True(t, strings.Contains(body, "version: v"),
		"workflow must pin the Aguara binary version (action ref alone does not pin the install)")
}

type workflowDoc struct {
	On          map[string]any `yaml:"on"`
	Permissions map[string]any `yaml:"permissions"`
	Jobs        map[string]struct {
		RunsOn      string            `yaml:"runs-on"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Name  string            `yaml:"name"`
			Uses  string            `yaml:"uses"`
			Run   string            `yaml:"run"`
			If    string            `yaml:"if"`
			Shell string            `yaml:"shell"`
			With  map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// The scaffolded workflow runs the command the README recommends for CI,
// requests only the permissions it uses, pins actions, never comments on
// pull requests and does not depend on CI detection for project policy.
func TestInitWorkflowStructure(t *testing.T) {
	var wf workflowDoc
	require.NoError(t, yaml.Unmarshal([]byte(workflowTemplateV2), &wf))
	require.Contains(t, wf.On, "push")
	require.Contains(t, wf.On, "pull_request")
	require.NotContains(t, wf.On, "pull_request_target")
	require.Empty(t, wf.Permissions, "no default token permissions at the workflow level")

	job, ok := wf.Jobs["aguara"]
	require.True(t, ok)
	require.Equal(t, map[string]string{"contents": "read", "security-events": "write", "actions": "read"}, job.Permissions)

	sha := regexp.MustCompile(`^[\w.-]+/[\w.-]+@[0-9a-f]{40}$`)
	var run, summary string
	for _, step := range job.Steps {
		switch {
		case step.Uses == "garagon/aguara@v0.29.0":
			require.Equal(t, "v0.29.0", step.With["version"])
			require.Contains(t, step.With["upload-sarif"], "github.event.pull_request.head.repo.full_name == github.repository",
				"fork pull requests cannot write to code scanning")
			require.Contains(t, step.With["upload-sarif"], "vars.AGUARA_UPLOAD_SARIF")
			// The SARIF must not land in the checkout, where the audit
			// step would scan it as a JSON file.
			require.Equal(t, "${{ runner.temp }}/aguara-results.sarif", step.With["output"])
		case step.Uses != "":
			require.Regexp(t, sha, step.Uses, "third-party actions are pinned to a commit SHA")
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				require.Equal(t, "false", step.With["persist-credentials"])
			}
		case strings.Contains(step.Run, "aguara audit"):
			run = step.Run
		case strings.Contains(step.Run, "GITHUB_STEP_SUMMARY"):
			summary = step.Run
			require.Equal(t, "always()", step.If)
		}
	}
	require.Contains(t, run, "aguara audit . --ci --project-policy ignore")
	require.Contains(t, run, `>"$RUNNER_TEMP/aguara-audit.txt"`, "the audit report is written outside the checkout it scans")
	require.Contains(t, summary, "&lt;", "the report is HTML-escaped inside <pre>")
	require.Contains(t, summary, `head -c 200000 "$RUNNER_TEMP/aguara-audit.txt" | sed`,
		"escaping can grow the text five times; the summary must stay under 1 MiB")
	require.NotContains(t, workflowTemplateV2, "pull-requests:")
	require.NotContains(t, workflowTemplateV2, "github-script")
	require.NotContains(t, workflowTemplateV2, "createComment")
}

// The job summary step must render a report whose findings contain markup
// as text, not as HTML or Markdown.
func TestInitWorkflowSummaryEscapesReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs bash and sed")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	var wf workflowDoc
	require.NoError(t, yaml.Unmarshal([]byte(workflowTemplateV2), &wf))
	var script string
	for _, step := range wf.Jobs["aguara"].Steps {
		if strings.Contains(step.Run, "GITHUB_STEP_SUMMARY") {
			script = step.Run
		}
	}
	require.NotEmpty(t, script)
	checkout, runnerTemp := t.TempDir(), t.TempDir()
	report := "  ✖ PROMPT_INJECTION_001  x.md:1 </pre><img src=x onerror=alert(1)> & `code`\n"
	require.NoError(t, os.WriteFile(filepath.Join(runnerTemp, "aguara-audit.txt"), []byte(report), 0o644))
	summary := filepath.Join(runnerTemp, "summary.md")
	runSummary := func() {
		t.Helper()
		c := exec.Command(bash, "-e", "-o", "pipefail", "-c", script)
		c.Dir = checkout
		c.Env = append(os.Environ(), "GITHUB_STEP_SUMMARY="+summary, "RUNNER_TEMP="+runnerTemp)
		out, err := c.CombinedOutput()
		require.NoError(t, err, "%s", out)
	}
	runSummary()
	got, err := os.ReadFile(summary)
	require.NoError(t, err)
	require.Contains(t, string(got), "&lt;/pre&gt;&lt;img src=x onerror=alert(1)&gt; &amp; `code`")
	require.Equal(t, 1, strings.Count(string(got), "</pre>"))

	// A report of any size, even one made only of characters that grow
	// five times when escaped, stays under the 1 MiB summary limit.
	require.NoError(t, os.WriteFile(filepath.Join(runnerTemp, "aguara-audit.txt"), bytes.Repeat([]byte("&"), 2<<20), 0o644))
	require.NoError(t, os.WriteFile(summary, nil, 0o644))
	runSummary()
	info, err := os.Stat(summary)
	require.NoError(t, err)
	require.Less(t, info.Size(), int64(1<<20))
}

// The audit and summary steps write nothing into the checkout they scan,
// so a scan later in the job never reads the job's own reports.
func TestInitWorkflowWritesNothingIntoTheCheckout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	var wf workflowDoc
	require.NoError(t, yaml.Unmarshal([]byte(workflowTemplateV2), &wf))
	bin := t.TempDir()
	stub := "#!/bin/sh\necho \"stub report for $*\"\nexit 0\n"
	require.NoError(t, os.WriteFile(filepath.Join(bin, "aguara"), []byte(stub), 0o755))
	checkout, runnerTemp := t.TempDir(), t.TempDir()
	summary := filepath.Join(runnerTemp, "summary.md")
	ran := 0
	for _, step := range wf.Jobs["aguara"].Steps {
		if step.Run == "" {
			continue
		}
		ran++
		c := exec.Command(bash, "-e", "-o", "pipefail", "-c", step.Run)
		c.Dir = checkout
		c.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GITHUB_STEP_SUMMARY="+summary, "RUNNER_TEMP="+runnerTemp)
		out, err := c.CombinedOutput()
		require.NoError(t, err, "%s: %s", step.Name, out)
	}
	require.Equal(t, 2, ran)
	entries, err := os.ReadDir(checkout)
	require.NoError(t, err)
	require.Empty(t, entries, "no report is written into the scanned checkout")
	got, err := os.ReadFile(summary)
	require.NoError(t, err)
	require.Contains(t, string(got), "stub report for audit . --ci --project-policy ignore")
}

// The scaffold must not advertise settings nothing reads, and every
// setting it does write must load without warnings or notices.
func TestInitConfigTemplate(t *testing.T) {
	require.NotContains(t, configTemplate, "paths")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), []byte(configTemplate), 0o644))
	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Empty(t, cfg.Warnings)
	require.Empty(t, cfg.Notices)
	require.Empty(t, cfg.Ignore, "ignore patterns live in .aguaraignore")
	for _, tmpl := range []string{configTemplate, ignoreTemplate} {
		require.Contains(t, tmpl, "aguara audit")
		require.Contains(t, tmpl, "--ci")
		require.Contains(t, tmpl, "GitHub Action")
		require.Contains(t, tmpl, "detected CI environment")
	}
	// Agent and editor configuration is what Aguara inspects; the
	// scaffold must not hide it.
	for _, hidden := range []string{".vscode/", ".idea/", "bin/"} {
		require.NotContains(t, ignoreTemplate, "\n"+hidden+"\n")
	}
}

// A project scaffolded by init, scanned locally, skips the directories its
// .aguaraignore lists and nothing else. The scaffolded files themselves
// produce no findings.
func TestInitScaffoldExcludesListedDirectories(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	captureStdoutBytes(t, func() { require.NoError(t, runCLI(t, "init", dir)) })
	data, err := runScanJSONWithError(t, dir)
	require.NoError(t, err)
	var clean changedScanResult
	require.NoError(t, json.Unmarshal(data, &clean))
	require.Equal(t, 3, clean.FilesScanned)
	require.Empty(t, clean.Findings, "the scaffolded files are clean")

	for _, p := range []string{"dist/app.md", "packages/web/dist/b.md", ".venv/lib/c.md", "vendor/x/d.md", "build/e.md", "src/keep.md"} {
		path := filepath.Join(dir, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(injectionPayload), 0o644))
	}
	data, err = runScanJSONWithError(t, dir)
	require.NoError(t, err)
	var res changedScanResult
	require.NoError(t, json.Unmarshal(data, &res))
	var files []string
	for _, f := range res.Findings {
		files = append(files, filepath.ToSlash(f.FilePath))
	}
	require.Equal(t, []string{"src/keep.md"}, files)
}

func TestInitPrintsNextSteps(t *testing.T) {
	dir := t.TempDir()
	out := captureStdoutBytes(t, func() { require.NoError(t, runInit(nil, []string{dir})) })
	require.Contains(t, string(out), "Next steps:")
	require.Contains(t, string(out), "aguara audit .")
	require.Contains(t, string(out), "aguara init --hook")

	out = captureStdoutBytes(t, func() { require.NoError(t, runInit(nil, []string{dir})) })
	require.Contains(t, string(out), "left unchanged")
}

func TestInitSkipsExisting(t *testing.T) {
	dir := t.TempDir()

	// Pre-create .aguara.yml with custom content
	existing := filepath.Join(dir, ".aguara.yml")
	require.NoError(t, os.WriteFile(existing, []byte("custom: true\n"), 0644))

	var err error
	captureStdoutBytes(t, func() { err = runInit(nil, []string{dir}) })
	require.NoError(t, err)

	// Existing file should not be overwritten
	data, err := os.ReadFile(existing)
	require.NoError(t, err)
	require.Equal(t, "custom: true\n", string(data))

	// Other files should still be created
	_, err = os.Stat(filepath.Join(dir, ".aguaraignore"))
	require.NoError(t, err)
}

func TestInitCreatesSubdirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "project")

	var err error
	captureStdoutBytes(t, func() { err = runInit(nil, []string{dir}) })
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".github", "workflows", "aguara.yml"))
	require.NoError(t, err)
}

func TestInitHookCreatesPreCommit(t *testing.T) {
	dir := gitRepo(t)

	flagHook = true
	defer func() { flagHook = false }()

	var err error
	out := captureStdoutBytes(t, func() { err = runInit(nil, []string{dir}) })
	require.NoError(t, err)
	require.Contains(t, string(out), "git commit --no-verify")

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	info, err := os.Stat(hookPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.True(t, info.Mode()&0111 != 0, "hook should be executable")
	}

	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "aguara")
	require.Contains(t, string(data), "git checkout-index -f -z --stdin")
	require.NotContains(t, string(data), "scan . ", "the hook scans the staged files, not the whole work tree")
}

// Outside a git work tree the error says what to do, without a raw stat
// error or the usage block.
func TestInitHookNoGitDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", os.TempDir())
	dir := t.TempDir()
	resetFlags()
	stderr := new(bytes.Buffer)
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs([]string{"init", "--hook", dir, "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		flagHook = false
		resetFlags()
	})
	err := rootCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not inside a git work tree")
	require.NotContains(t, err.Error(), "statat")
	require.NotContains(t, stderr.String(), "Usage:")
	_, statErr := os.Stat(filepath.Join(dir, ".git"))
	require.True(t, os.IsNotExist(statErr), "nothing is created outside a repository")
}

func TestInitHookSkipsExisting(t *testing.T) {
	dir := gitRepo(t)
	hooksDir := filepath.Join(dir, ".git", "hooks")
	require.NoError(t, os.MkdirAll(hooksDir, 0755))

	hookPath := filepath.Join(hooksDir, "pre-commit")
	require.NoError(t, os.WriteFile(hookPath, []byte("#!/bin/sh\necho custom\n"), 0755))

	flagHook = true
	defer func() { flagHook = false }()

	var err error
	out := captureStdoutBytes(t, func() { err = runInit(nil, []string{dir}) })
	require.NoError(t, err)
	require.Contains(t, string(out), "left unchanged")

	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "echo custom", "existing hook should not be overwritten")
}

// From a subdirectory or a linked worktree the hook goes where git runs
// hooks, not into a .git directory that does not exist there.
func TestInitHookFollowsGitHooksDirectory(t *testing.T) {
	repo := gitRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(repo, "README.md"), []byte("# x\n"), 0o644))
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-q", "-m", "init")
	sub := filepath.Join(repo, "docs")
	require.NoError(t, os.Mkdir(sub, 0o755))

	flagHook = true
	defer func() { flagHook = false }()

	captureStdoutBytes(t, func() { require.NoError(t, runInit(nil, []string{sub})) })
	_, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(repo, ".git", "hooks", "pre-commit")))

	worktree := filepath.Join(t.TempDir(), "wt")
	runGit(t, repo, "worktree", "add", "-q", worktree)
	captureStdoutBytes(t, func() { require.NoError(t, runInit(nil, []string{worktree})) })
	common := strings.TrimSpace(runGit(t, worktree, "rev-parse", "--git-common-dir"))
	if !filepath.IsAbs(common) {
		common = filepath.Join(worktree, common)
	}
	_, err = os.Stat(filepath.Join(common, "hooks", "pre-commit"))
	require.NoError(t, err, "a linked worktree runs the common directory's hooks")
}

func TestInitCIOnly(t *testing.T) {
	dir := t.TempDir()

	flagCIOnly = true
	defer func() { flagCIOnly = false }()

	var err error
	captureStdoutBytes(t, func() { err = runInit(nil, []string{dir}) })
	require.NoError(t, err)

	// Workflow file should exist
	wfPath := filepath.Join(dir, ".github", "workflows", "aguara.yml")
	_, err = os.Stat(wfPath)
	require.NoError(t, err)

	// Config files should NOT exist
	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.True(t, os.IsNotExist(err), ".aguara.yml should not be created with --ci")

	_, err = os.Stat(filepath.Join(dir, ".aguaraignore"))
	require.True(t, os.IsNotExist(err), ".aguaraignore should not be created with --ci")
}

func TestInitDefaultDir(t *testing.T) {
	// Save and restore working directory
	orig, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(orig) }()

	dir := t.TempDir()
	require.NoError(t, os.Chdir(dir))

	captureStdoutBytes(t, func() { err = runInit(nil, []string{}) })
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.NoError(t, err)
}

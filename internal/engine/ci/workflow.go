// Package ci analyzes GitHub Actions workflow YAML for trust-boundary
// chain violations: pull_request_target executing PR-controlled code,
// cache poisoning across fork/base boundaries, OIDC token surface
// exposed to install/build/test, and persisted credentials on untrusted
// checkouts.
//
// The analyzer is fully offline and deterministic. It does not emulate
// the workflow runtime; it parses each workflow file once with yaml.v3,
// classifies each step against a curated set of trust-chain fingerprints
// derived from real-world supply-chain incidents (Mini Shai-Hulud and
// related GitHub Security Lab pwn-request patterns), and emits a small
// number of high-confidence findings.
//
// Only files under a .github/workflows/ directory with extension .yml or
// .yaml are inspected; everything else returns nil quickly. The analyzer
// is intentionally chain-first: single weak signals (pull_request_target
// alone, id-token: write alone, actions/cache alone) never fire.
package ci

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// AnalyzerName is the value reported in Finding.Analyzer for this engine.
const AnalyzerName = "ci-trust"

// Rule IDs emitted by this analyzer.
const (
	RulePwnRequest = "GHA_PWN_REQUEST_001"
	RuleCache      = "GHA_CACHE_001"
	RuleOIDC       = "GHA_OIDC_001"
	RuleCheckout   = "GHA_CHECKOUT_001"
)

// Analyzer implements scanner.Analyzer for GitHub Actions trust analysis.
type Analyzer struct{}

// New returns a fresh CI trust analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

// Analyze parses the target if it is a GitHub Actions workflow and returns
// trust-chain findings. Non-workflow files and malformed YAML return nil.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isWorkflowTarget(target) {
		return nil, nil
	}
	if len(target.Content) == 0 {
		return nil, nil
	}
	wf, err := parseWorkflow(target.Content)
	if err != nil || wf == nil {
		// Malformed YAML: leave pattern rules to flag what they can; ci-trust
		// only reports on shapes it can confidently reason about.
		return nil, nil
	}
	wf.Path = target.RelPath
	return detect(wf), nil
}

// --- target gating ---

// isWorkflowTarget returns true if the target is a YAML file located under
// any .github/workflows/ directory. Checks both Path (when scanning a real
// repo) and RelPath (when scanning in-memory content with a hinted name).
func isWorkflowTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.Path, t.RelPath} {
		if p == "" {
			continue
		}
		slash := filepath.ToSlash(p)
		if !strings.Contains(slash, ".github/workflows/") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(slash))
		if ext == ".yml" || ext == ".yaml" {
			return true
		}
	}
	return false
}

// --- model ---

type workflow struct {
	Path        string
	Events      eventSet
	Permissions perms // top-level permissions
	Jobs        []job
}

type eventSet struct {
	PullRequest       bool
	PullRequestTarget bool
	WorkflowRun       bool
	Push              bool
	Release           bool
	WorkflowDispatch  bool
}

// perms captures the GitHub Actions permissions surface. Specified records
// whether any permission key was present (needed to distinguish job-level
// override from inheritance).
type perms struct {
	Contents     string
	Actions      string
	IDToken      string
	Packages     string
	Attestations string
	WriteAll     bool
	ReadAll      bool
	Specified    bool
}

type job struct {
	ID                      string
	Line                    int
	JobPermissionsSpecified bool
	JobPermissions          perms
	Steps                   []step
}

type step struct {
	Line int
	Name string
	Uses string
	Run  string
	With map[string]string

	Checkout                bool
	CheckoutUntrustedPR     bool
	Cache                   bool
	PackageInstall          bool
	PackageBuildOrTest      bool
	Publish                 bool
	ExecutesCode            bool
	PersistCredentialsFalse bool
}

// --- yaml parsing ---

func parseWorkflow(content []byte) (*workflow, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("empty yaml document")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow root is not a mapping")
	}

	wf := &workflow{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		k := top.Content[i]
		v := top.Content[i+1]
		// GitHub uses `on:` as a key. yaml.v3 in 1.2 mode keeps the literal
		// text in Value; some encoders may emit it as the boolean `true`.
		key := strings.ToLower(strings.TrimSpace(k.Value))
		if k.Tag == "!!bool" && key == "true" {
			key = "on"
		}
		switch key {
		case "on":
			wf.Events = parseEvents(v)
		case "permissions":
			wf.Permissions = parsePermissions(v)
		case "jobs":
			wf.Jobs = parseJobs(v)
		}
	}
	return wf, nil
}

func parseEvents(n *yaml.Node) eventSet {
	var es eventSet
	if n == nil {
		return es
	}
	switch n.Kind {
	case yaml.ScalarNode:
		setEvent(&es, n.Value)
	case yaml.SequenceNode:
		for _, item := range n.Content {
			setEvent(&es, item.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			setEvent(&es, n.Content[i].Value)
		}
	}
	return es
}

func setEvent(es *eventSet, name string) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "pull_request":
		es.PullRequest = true
	case "pull_request_target":
		es.PullRequestTarget = true
	case "workflow_run":
		es.WorkflowRun = true
	case "push":
		es.Push = true
	case "release":
		es.Release = true
	case "workflow_dispatch":
		es.WorkflowDispatch = true
	}
}

func parsePermissions(n *yaml.Node) perms {
	var p perms
	if n == nil {
		return p
	}
	p.Specified = true
	switch n.Kind {
	case yaml.ScalarNode:
		switch strings.ToLower(strings.TrimSpace(n.Value)) {
		case "write-all":
			p.WriteAll = true
		case "read-all":
			p.ReadAll = true
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := strings.ToLower(strings.TrimSpace(n.Content[i].Value))
			v := strings.ToLower(strings.TrimSpace(n.Content[i+1].Value))
			switch k {
			case "contents":
				p.Contents = v
			case "actions":
				p.Actions = v
			case "id-token":
				p.IDToken = v
			case "packages":
				p.Packages = v
			case "attestations":
				p.Attestations = v
			}
		}
	}
	return p
}

func parseJobs(n *yaml.Node) []job {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var jobs []job
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		v := n.Content[i+1]
		if v.Kind != yaml.MappingNode {
			continue
		}
		j := job{ID: k.Value, Line: k.Line}
		for jj := 0; jj+1 < len(v.Content); jj += 2 {
			jk := strings.ToLower(strings.TrimSpace(v.Content[jj].Value))
			jv := v.Content[jj+1]
			switch jk {
			case "permissions":
				j.JobPermissions = parsePermissions(jv)
				j.JobPermissionsSpecified = j.JobPermissions.Specified
			case "steps":
				j.Steps = parseSteps(jv)
			}
		}
		jobs = append(jobs, j)
	}
	return jobs
}

func parseSteps(n *yaml.Node) []step {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	steps := make([]step, 0, len(n.Content))
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		s := step{Line: item.Line}
		for i := 0; i+1 < len(item.Content); i += 2 {
			k := strings.ToLower(strings.TrimSpace(item.Content[i].Value))
			v := item.Content[i+1]
			switch k {
			case "name":
				s.Name = v.Value
			case "uses":
				s.Uses = strings.TrimSpace(v.Value)
			case "run":
				s.Run = v.Value
			case "with":
				s.With = parseWith(v)
			}
		}
		classifyStep(&s)
		steps = append(steps, s)
	}
	return steps
}

func parseWith(n *yaml.Node) map[string]string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]string, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := strings.ToLower(strings.TrimSpace(n.Content[i].Value))
		v := n.Content[i+1]
		// Use Value verbatim; expressions like "${{ github.head_ref }}" are
		// preserved as strings, which is what classifyStep matches against.
		out[k] = strings.TrimSpace(v.Value)
	}
	return out
}

// --- step classification ---

// classifyStep populates the boolean flags on step based on uses/run/with.
// Classification is intentionally narrow: each flag should map to a concrete
// behavioral primitive (e.g. "installs a package manager dependency tree"),
// not to a generic shape ("has a run command").
func classifyStep(s *step) {
	usesBase := stripActionRef(s.Uses)
	usesLower := strings.ToLower(usesBase)

	// checkout
	if usesLower == "actions/checkout" || strings.HasPrefix(usesLower, "actions/checkout/") {
		s.Checkout = true
		if ref := s.With["ref"]; ref != "" && isUntrustedRef(ref) {
			s.CheckoutUntrustedPR = true
		}
		if pc, ok := s.With["persist-credentials"]; ok {
			v := strings.Trim(strings.ToLower(strings.TrimSpace(pc)), "'\"")
			if v == "false" {
				s.PersistCredentialsFalse = true
			}
		}
	}

	// cache
	if usesLower == "actions/cache" ||
		strings.HasPrefix(usesLower, "actions/cache/") {
		s.Cache = true
	}
	// Setup actions with cache: <something> non-empty enable cache writes
	// for the package manager. setup-node, setup-python, setup-go all
	// expose this pattern.
	if strings.HasPrefix(usesLower, "actions/setup-") {
		if c, ok := s.With["cache"]; ok {
			c = strings.Trim(strings.ToLower(strings.TrimSpace(c)), "'\"")
			if c != "" && c != "false" {
				s.Cache = true
			}
		}
	}

	// Local actions (./...) execute action code from the checkout; for
	// pwn-request analysis that means PR-controlled code.
	if strings.HasPrefix(usesBase, "./") {
		s.ExecutesCode = true
	}

	if s.Run != "" {
		run := s.Run
		lower := strings.ToLower(run)
		if matchesPackageInstall(lower) {
			s.PackageInstall = true
		}
		if matchesPackageBuildOrTest(lower) {
			s.PackageBuildOrTest = true
		}
		if matchesPublish(lower) {
			s.Publish = true
		}
		if matchesInterpreter(lower) {
			s.ExecutesCode = true
		}
	}
}

// stripActionRef returns the action name without any @ref suffix.
func stripActionRef(uses string) string {
	uses = strings.TrimSpace(uses)
	if idx := strings.Index(uses, "@"); idx > 0 {
		return uses[:idx]
	}
	return uses
}

// isUntrustedRef returns true for `with.ref` values that point at PR head /
// merge refs, which is the precondition for executing PR-controlled code.
func isUntrustedRef(ref string) bool {
	lower := strings.ToLower(ref)
	needles := []string{
		"github.event.pull_request.head",
		"github.event.pull_request.merge",
		"github.head_ref",
		"refs/pull/",
		"pull_request.number",
		"/merge",
	}
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func matchesPackageInstall(run string) bool {
	needles := []string{
		"npm install", "npm i ", "npm ci",
		"pnpm install", "pnpm i ", "pnpm i\n",
		"yarn install", "yarn --frozen-lockfile",
		"bun install", "bun i ",
		"pip install", "uv pip install", "poetry install",
	}
	for _, n := range needles {
		if strings.Contains(run, n) {
			return true
		}
	}
	// Bare `pnpm i` / `npm i` / `yarn` / `bun i` at end-of-line.
	for _, line := range strings.Split(run, "\n") {
		l := strings.TrimSpace(line)
		switch l {
		case "npm i", "pnpm i", "yarn", "bun i", "bun install":
			return true
		}
	}
	return false
}

func matchesPackageBuildOrTest(run string) bool {
	needles := []string{
		"npm run ", "npm test", "npm exec",
		"pnpm run ", "pnpm test", "pnpm exec",
		"yarn run ", "yarn test",
		"bun run ", "bun test",
		"nx run", "nx build", "nx test",
		"turbo run",
		"make ", "make\t",
	}
	for _, n := range needles {
		if strings.Contains(run, n) {
			return true
		}
	}
	return false
}

func matchesPublish(run string) bool {
	needles := []string{
		"npm publish", "pnpm publish", "yarn publish", "yarn npm publish",
		"bun publish",
		"twine upload", "uv publish", "poetry publish",
		"cargo publish", "goreleaser release",
	}
	for _, n := range needles {
		if strings.Contains(run, n) {
			return true
		}
	}
	return false
}

// matchesInterpreter returns true for run: commands that explicitly invoke
// an interpreter or execute a script file. This is intentionally narrower
// than matchesPackageBuildOrTest to avoid flagging passive grep/diff steps.
func matchesInterpreter(run string) bool {
	indicators := []string{
		"node -e", "node -p", "node ./", "node ../",
		"python -c", "python3 -c", "python ./", "python3 ./",
		"ruby -e", "ruby ./",
		"php -r", "php ./",
		"go run ", "cargo run", "dotnet run",
		"bash ./", "sh ./",
	}
	for _, n := range indicators {
		if strings.Contains(run, n) {
			return true
		}
	}
	return false
}

// --- detection ---

// effectivePermissions resolves the permissions that apply to a job. Per
// GitHub Actions semantics, job-level permissions fully replace top-level
// permissions; if a job specifies none, the top-level set is inherited.
func effectivePermissions(top perms, j *job) perms {
	if j.JobPermissionsSpecified {
		return j.JobPermissions
	}
	return top
}

func detect(wf *workflow) []types.Finding {
	var out []types.Finding
	for i := range wf.Jobs {
		j := &wf.Jobs[i]
		eff := effectivePermissions(wf.Permissions, j)
		if f := detectPwnRequest(wf, j); f != nil {
			out = append(out, *f)
		}
		if f := detectCache(wf, j); f != nil {
			out = append(out, *f)
		}
		if f := detectOIDC(wf, j, eff); f != nil {
			out = append(out, *f)
		}
		if f := detectCheckout(wf, j); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// dangerousWrite returns true if the effective permissions expose a
// write-shaped surface (id-token write, contents write, packages write, or
// blanket write-all) that should escalate pwn-request findings to CRITICAL.
func dangerousWrite(p perms) bool {
	if p.WriteAll {
		return true
	}
	if p.IDToken == "write" {
		return true
	}
	if p.Contents == "write" {
		return true
	}
	if p.Packages == "write" {
		return true
	}
	if p.Attestations == "write" {
		return true
	}
	return false
}

// findUntrustedCheckoutStep returns the first step in a job that checks out
// a PR-controlled ref. The step's line is used as the anchor for findings.
func findUntrustedCheckoutStep(j *job) *step {
	for i := range j.Steps {
		if j.Steps[i].CheckoutUntrustedPR {
			return &j.Steps[i]
		}
	}
	return nil
}

func jobExecutesPRCode(j *job) bool {
	for _, s := range j.Steps {
		if s.PackageInstall || s.PackageBuildOrTest || s.ExecutesCode {
			return true
		}
	}
	return false
}

func jobHasCacheStep(j *job) *step {
	for i := range j.Steps {
		if j.Steps[i].Cache {
			return &j.Steps[i]
		}
	}
	return nil
}

func detectPwnRequest(wf *workflow, j *job) *types.Finding {
	if !wf.Events.PullRequestTarget {
		return nil
	}
	ck := findUntrustedCheckoutStep(j)
	if ck == nil {
		return nil
	}
	if !jobExecutesPRCode(j) {
		return nil
	}
	sev := types.SeverityHigh
	eff := effectivePermissions(wf.Permissions, j)
	if dangerousWrite(eff) {
		sev = types.SeverityCritical
	}
	return &types.Finding{
		RuleID:   RulePwnRequest,
		RuleName: "pull_request_target executes untrusted PR code",
		Severity: sev,
		Category: "supply-chain",
		Description: "Workflow runs on pull_request_target (privileged) and checks out " +
			"the PR head ref while the same job installs, builds, tests, or runs " +
			"PR-controlled code. This is the classic pwn-request chain that turns " +
			"untrusted contributor code into privileged CI execution.",
		FilePath:    wf.Path,
		Line:        ck.Line,
		MatchedText: "pull_request_target + untrusted checkout + code execution in job " + j.ID,
		Analyzer:    AnalyzerName,
		Confidence:  0.95,
		Remediation: "Use pull_request for untrusted build/test. Reserve pull_request_target for " +
			"passive, read-only operations (labeling, commenting). Move privileged work into a " +
			"separate workflow_run job that consumes only verified artifacts.",
	}
}

func detectCache(wf *workflow, j *job) *types.Finding {
	if !wf.Events.PullRequestTarget {
		return nil
	}
	if findUntrustedCheckoutStep(j) == nil {
		return nil
	}
	cache := jobHasCacheStep(j)
	if cache == nil {
		return nil
	}
	sev := types.SeverityHigh
	if jobExecutesPRCode(j) {
		sev = types.SeverityCritical
	}
	return &types.Finding{
		RuleID:   RuleCache,
		RuleName: "Untrusted PR workflow can write cache consumed by privileged workflows",
		Severity: sev,
		Category: "supply-chain",
		Description: "pull_request_target jobs that check out PR code AND populate the " +
			"GitHub Actions cache can poison cache entries consumed later by privileged " +
			"workflows. Cache writes are not constrained by the workflow's GITHUB_TOKEN " +
			"permissions, so trust on the cache key cannot be assumed.",
		FilePath:    wf.Path,
		Line:        cache.Line,
		MatchedText: "pull_request_target + untrusted checkout + cache write in job " + j.ID,
		Analyzer:    AnalyzerName,
		Confidence:  0.9,
		Remediation: "Avoid writing the cache from untrusted PR contexts. Either disable cache " +
			"writes in pull_request_target jobs, or use a separate cache key namespace for " +
			"untrusted runs. Prefer pull_request for any job that needs to install dependencies.",
	}
}

func detectOIDC(wf *workflow, j *job, eff perms) *types.Finding {
	if eff.IDToken != "write" && !eff.WriteAll {
		return nil
	}
	// FP control: a job that only publishes (no install/build/test) is the
	// intended use of OIDC and should not be flagged.
	hasInstallOrBuild := false
	hasPublish := false
	for _, s := range j.Steps {
		if s.PackageInstall || s.PackageBuildOrTest || s.ExecutesCode {
			hasInstallOrBuild = true
		}
		if s.Publish {
			hasPublish = true
		}
	}
	if !hasInstallOrBuild {
		return nil
	}
	sev := types.SeverityHigh
	if hasPublish {
		sev = types.SeverityCritical
	}
	return &types.Finding{
		RuleID:   RuleOIDC,
		RuleName: "OIDC token available in a job that executes install/build/test code",
		Severity: sev,
		Category: "supply-chain",
		Description: "id-token: write (or write-all) is granted on a job that also installs, " +
			"builds, tests, or runs scripts. The OIDC token is exposed for the lifetime of " +
			"the job, so any compromised dependency lifecycle script can mint a trusted " +
			"publishing token before the publish step.",
		FilePath:    wf.Path,
		Line:        j.Line,
		MatchedText: "id-token: write + install/build/test in job " + j.ID,
		Analyzer:    AnalyzerName,
		Confidence:  0.85,
		Remediation: "Split publishing into its own job that only consumes pre-built, verified " +
			"artifacts. Grant id-token: write only on that publish-only job and use " +
			"id-token: none everywhere else.",
	}
}

func detectCheckout(wf *workflow, j *job) *types.Finding {
	if !wf.Events.PullRequestTarget {
		return nil
	}
	ck := findUntrustedCheckoutStep(j)
	if ck == nil {
		return nil
	}
	if ck.PersistCredentialsFalse {
		return nil
	}
	return &types.Finding{
		RuleID:   RuleCheckout,
		RuleName: "Privileged workflow checks out PR code with persisted credentials",
		Severity: types.SeverityHigh,
		Category: "supply-chain",
		Description: "actions/checkout in a pull_request_target job is fetching the PR head " +
			"ref while leaving persist-credentials at its default (true). That leaves the " +
			"job's GITHUB_TOKEN in .git/config, where any subsequent step executing PR code " +
			"can read it.",
		FilePath:    wf.Path,
		Line:        ck.Line,
		MatchedText: "pull_request_target checkout of PR ref without persist-credentials: false",
		Analyzer:    AnalyzerName,
		Confidence:  0.9,
		Remediation: "Prefer not checking out untrusted PR code in privileged workflows. If a " +
			"checkout is required, set with.persist-credentials: false so the GITHUB_TOKEN is " +
			"not written to .git/config.",
	}
}

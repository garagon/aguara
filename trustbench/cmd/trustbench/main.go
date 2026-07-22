// Command trustbench evaluates Aguara against a versioned, synthetic corpus.
// It executes the public CLI so the benchmark covers discovery, parsing,
// analyzers, output serialization, and embedded threat intel together.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var manifestSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type manifest struct {
	SchemaVersion int         `yaml:"schema_version"`
	Name          string      `yaml:"name"`
	License       string      `yaml:"license"`
	Cases         []benchCase `yaml:"cases"`
}

type benchCase struct {
	ID              string            `yaml:"id"`
	Surface         string            `yaml:"surface"`
	Command         string            `yaml:"command"`
	Files           map[string]string `yaml:"files"`
	Expected        []expectation     `yaml:"expected"`
	KnownUnexpected []expectation     `yaml:"known_unexpected"`
}

type expectation struct {
	Kind  string `yaml:"kind"`
	Value string `yaml:"value"`
}

type observation struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type caseResult struct {
	ID                       string        `json:"id"`
	Surface                  string        `json:"surface"`
	Expected                 []expectation `json:"expected"`
	Observed                 []observation `json:"observed"`
	Missing                  []expectation `json:"missing"`
	Unexpected               []observation `json:"unexpected"`
	KnownUnexpected          []observation `json:"known_unexpected"`
	UnacknowledgedUnexpected []observation `json:"unacknowledged_unexpected"`
	StaleKnownUnexpected     []expectation `json:"stale_known_unexpected"`
}

type metrics struct {
	Cases                   int     `json:"cases"`
	PositiveCases           int     `json:"positive_cases"`
	BenignCases             int     `json:"benign_cases"`
	TruePositives           int     `json:"true_positives"`
	FalsePositives          int     `json:"false_positives"`
	FalseNegatives          int     `json:"false_negatives"`
	KnownFalsePositives     int     `json:"known_false_positives"`
	GateFalsePositives      int     `json:"gate_false_positives"`
	StaleKnownExceptions    int     `json:"stale_known_exceptions"`
	BenignCasesWithFindings int     `json:"benign_cases_with_findings"`
	Precision               float64 `json:"precision"`
	Recall                  float64 `json:"recall"`
	BenignCaseFPR           float64 `json:"benign_case_fpr"`
}

type report struct {
	SchemaVersion  int                `json:"schema_version"`
	Benchmark      string             `json:"benchmark"`
	License        string             `json:"license"`
	ManifestSHA256 string             `json:"manifest_sha256"`
	AguaraVersion  string             `json:"aguara_version"`
	Metrics        metrics            `json:"metrics"`
	BySurface      map[string]metrics `json:"by_surface"`
	Cases          []caseResult       `json:"cases"`
}

func main() {
	binary := flag.String("binary", "./aguara", "path to the Aguara binary under test")
	manifestPath := flag.String("manifest", "trustbench/manifest.yaml", "path to the benchmark manifest")
	format := flag.String("format", "text", "output format: text or json")
	output := flag.String("output", "", "write the report to this path instead of stdout")
	flag.Parse()

	if err := run(*binary, *manifestPath, *format, *output); err != nil {
		fmt.Fprintln(os.Stderr, "trustbench:", err)
		os.Exit(1)
	}
}

func run(binary, manifestPath, format, output string) error {
	m, manifestDigest, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return fmt.Errorf("resolve binary: %w", err)
	}
	if _, err := os.Stat(binary); err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	versionOut, err := exec.Command(binary, "--no-update-check", "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("read Aguara version: %w\n%s", err, versionOut)
	}

	tmp, err := os.MkdirTemp("", "aguara-trustbench-")
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			fmt.Fprintf(os.Stderr, "warning: remove benchmark workspace: %v\n", err)
		}
	}()

	r := report{
		SchemaVersion:  1,
		Benchmark:      m.Name,
		License:        m.License,
		ManifestSHA256: manifestDigest,
		AguaraVersion:  strings.TrimSpace(string(versionOut)),
		BySurface:      make(map[string]metrics),
	}
	for _, c := range m.Cases {
		cr, err := runCase(binary, tmp, c)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		r.Cases = append(r.Cases, cr)
	}
	r.Metrics = calculateMetrics(r.Cases)
	for _, cr := range r.Cases {
		bySurface := append([]caseResult(nil), filterSurface(r.Cases, cr.Surface)...)
		r.BySurface[cr.Surface] = calculateMetrics(bySurface)
	}

	var data []byte
	switch format {
	case "text":
		data = []byte(formatText(r))
	case "json":
		data, err = json.MarshalIndent(r, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if output == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(output, data, 0o644)
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if r.Metrics.GateFalsePositives > 0 || r.Metrics.FalseNegatives > 0 || r.Metrics.StaleKnownExceptions > 0 {
		return fmt.Errorf("quality gate failed: %d false positive(s), %d false negative(s), %d stale known exception(s)",
			r.Metrics.GateFalsePositives, r.Metrics.FalseNegatives, r.Metrics.StaleKnownExceptions)
	}
	return nil
}

func loadManifest(path string) (manifest, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, "", fmt.Errorf("read manifest: %w", err)
	}
	var m manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return manifest{}, "", fmt.Errorf("parse manifest: %w", err)
	}
	if err := validateManifest(m); err != nil {
		return manifest{}, "", err
	}
	digest := sha256.Sum256(data)
	return m, fmt.Sprintf("%x", digest), nil
}

func validateManifest(m manifest) error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported manifest schema_version %d", m.SchemaVersion)
	}
	if strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.License) == "" {
		return errors.New("manifest name and license are required")
	}
	if len(m.Cases) == 0 {
		return errors.New("manifest has no cases")
	}
	seen := make(map[string]bool)
	for _, c := range m.Cases {
		if !manifestSlugRe.MatchString(c.ID) || !manifestSlugRe.MatchString(c.Surface) {
			return fmt.Errorf("case id and surface must be lowercase slugs: id=%q surface=%q", c.ID, c.Surface)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Command != "scan" && c.Command != "check" && c.Command != "audit" {
			return fmt.Errorf("case %s: unsupported command %q", c.ID, c.Command)
		}
		if len(c.Files) == 0 {
			return fmt.Errorf("case %s: no files", c.ID)
		}
		for name := range c.Files {
			clean := filepath.Clean(name)
			if filepath.IsAbs(name) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return fmt.Errorf("case %s: unsafe file path %q", c.ID, name)
			}
		}
		if err := validateExpectations(c.ID, "expected", c.Expected); err != nil {
			return err
		}
		if err := validateExpectations(c.ID, "known_unexpected", c.KnownUnexpected); err != nil {
			return err
		}
	}
	return nil
}

func validateExpectations(caseID, field string, entries []expectation) error {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if (e.Kind != "rule_id" && e.Kind != "title_contains") || strings.TrimSpace(e.Value) == "" {
			return fmt.Errorf("case %s: invalid %s entry %+v", caseID, field, e)
		}
		key := e.Kind + "\x00" + e.Value
		if seen[key] {
			return fmt.Errorf("case %s: duplicate %s entry %+v", caseID, field, e)
		}
		seen[key] = true
	}
	return nil
}

func runCase(binary, tmp string, c benchCase) (caseResult, error) {
	root := filepath.Join(tmp, c.ID)
	for name, content := range c.Files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return caseResult{}, err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return caseResult{}, err
		}
	}
	home := filepath.Join(tmp, "home", c.ID)
	if err := os.MkdirAll(home, 0o755); err != nil {
		return caseResult{}, err
	}
	cmd := exec.Command(binary, "--no-update-check", "--format", "json", c.Command, root)
	cmd.Env = isolatedEnv(home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return caseResult{}, fmt.Errorf("aguara %s failed: %w\n%s", c.Command, err, out)
	}
	var doc any
	if err := json.Unmarshal(out, &doc); err != nil {
		return caseResult{}, fmt.Errorf("decode Aguara JSON: %w\n%s", err, out)
	}
	observed := collectObservations(doc)
	missing, unexpected := compare(c.Expected, observed)
	known, unacknowledged, staleKnown := partitionKnownUnexpected(c.KnownUnexpected, unexpected)
	return caseResult{
		ID:                       c.ID,
		Surface:                  c.Surface,
		Expected:                 nonNilExpected(c.Expected),
		Observed:                 nonNilObserved(observed),
		Missing:                  nonNilExpected(missing),
		Unexpected:               nonNilObserved(unexpected),
		KnownUnexpected:          nonNilObserved(known),
		UnacknowledgedUnexpected: nonNilObserved(unacknowledged),
		StaleKnownUnexpected:     nonNilExpected(staleKnown),
	}, nil
}

func collectObservations(v any) []observation {
	unique := make(map[string]observation)
	var walk func(any)
	walk = func(value any) {
		switch x := value.(type) {
		case map[string]any:
			if id, ok := x["rule_id"].(string); ok && id != "" {
				o := observation{Kind: "rule_id", Value: id}
				unique[o.Kind+"\x00"+o.Value] = o
			} else if title, ok := x["title"].(string); ok && title != "" {
				if _, finding := x["severity"]; finding {
					o := observation{Kind: "title", Value: title}
					unique[o.Kind+"\x00"+o.Value] = o
				}
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	result := make([]observation, 0, len(unique))
	for _, o := range unique {
		result = append(result, o)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Value < result[j].Value
	})
	return result
}

func compare(expected []expectation, observed []observation) ([]expectation, []observation) {
	used := make([]bool, len(observed))
	var missing []expectation
	for _, e := range expected {
		found := false
		for i, o := range observed {
			if !used[i] && matches(e, o) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, e)
		}
	}
	var unexpected []observation
	for i, o := range observed {
		if !used[i] {
			unexpected = append(unexpected, o)
		}
	}
	return missing, unexpected
}

func matches(e expectation, o observation) bool {
	switch e.Kind {
	case "rule_id":
		return o.Kind == "rule_id" && o.Value == e.Value
	case "title_contains":
		return o.Kind == "title" && strings.Contains(strings.ToLower(o.Value), strings.ToLower(e.Value))
	default:
		return false
	}
}

func partitionKnownUnexpected(known []expectation, unexpected []observation) ([]observation, []observation, []expectation) {
	used := make([]bool, len(unexpected))
	var matched []observation
	var stale []expectation
	for _, e := range known {
		found := false
		for i, o := range unexpected {
			if !used[i] && matches(e, o) {
				used[i] = true
				matched = append(matched, o)
				found = true
				break
			}
		}
		if !found {
			stale = append(stale, e)
		}
	}
	var unacknowledged []observation
	for i, o := range unexpected {
		if !used[i] {
			unacknowledged = append(unacknowledged, o)
		}
	}
	return matched, unacknowledged, stale
}

func calculateMetrics(cases []caseResult) metrics {
	m := metrics{Cases: len(cases)}
	for _, c := range cases {
		if len(c.Expected) == 0 {
			m.BenignCases++
			if len(c.Unexpected) > 0 {
				m.BenignCasesWithFindings++
			}
		} else {
			m.PositiveCases++
		}
		m.TruePositives += len(c.Expected) - len(c.Missing)
		m.FalseNegatives += len(c.Missing)
		m.FalsePositives += len(c.Unexpected)
		m.KnownFalsePositives += len(c.KnownUnexpected)
		m.GateFalsePositives += len(c.UnacknowledgedUnexpected)
		m.StaleKnownExceptions += len(c.StaleKnownUnexpected)
	}
	m.Precision = ratio(m.TruePositives, m.TruePositives+m.FalsePositives)
	m.Recall = ratio(m.TruePositives, m.TruePositives+m.FalseNegatives)
	m.BenignCaseFPR = ratio(m.BenignCasesWithFindings, m.BenignCases)
	return m
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 1
	}
	return float64(n) / float64(d)
}

func isolatedEnv(home string) []string {
	drop := map[string]bool{
		"HOME":                   true,
		"XDG_CONFIG_HOME":        true,
		"AGUARA_NO_UPDATE_CHECK": true,
		"AGUARA_INSECURE_INTEL":  true,
		"NO_COLOR":               true,
	}
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !drop[key] {
			env = append(env, entry)
		}
	}
	return append(env,
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"AGUARA_NO_UPDATE_CHECK=1",
		"NO_COLOR=1",
	)
}

func filterSurface(cases []caseResult, surface string) []caseResult {
	var result []caseResult
	for _, c := range cases {
		if c.Surface == surface {
			result = append(result, c)
		}
	}
	return result
}

func formatText(r report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.Benchmark)
	fmt.Fprintf(&b, "aguara: %s\n", r.AguaraVersion)
	fmt.Fprintf(&b, "manifest_sha256: %s\n", r.ManifestSHA256)
	fmt.Fprintf(&b, "cases: %d (%d positive, %d benign)\n", r.Metrics.Cases, r.Metrics.PositiveCases, r.Metrics.BenignCases)
	fmt.Fprintf(&b, "precision: %.4f\nrecall: %.4f\nbenign_case_fpr: %.4f\n", r.Metrics.Precision, r.Metrics.Recall, r.Metrics.BenignCaseFPR)
	fmt.Fprintf(&b, "tp: %d\nfp: %d (known: %d, gate: %d)\nfn: %d\n",
		r.Metrics.TruePositives, r.Metrics.FalsePositives, r.Metrics.KnownFalsePositives,
		r.Metrics.GateFalsePositives, r.Metrics.FalseNegatives)
	fmt.Fprintf(&b, "stale_known_exceptions: %d\n", r.Metrics.StaleKnownExceptions)

	var surfaces []string
	for surface := range r.BySurface {
		surfaces = append(surfaces, surface)
	}
	sort.Strings(surfaces)
	b.WriteString("\nsurfaces:\n")
	for _, surface := range surfaces {
		m := r.BySurface[surface]
		fmt.Fprintf(&b, "  %s: cases=%d precision=%.4f recall=%.4f benign_case_fpr=%.4f\n", surface, m.Cases, m.Precision, m.Recall, m.BenignCaseFPR)
	}
	for _, c := range r.Cases {
		if len(c.Missing) == 0 && len(c.Unexpected) == 0 && len(c.StaleKnownUnexpected) == 0 {
			continue
		}
		label := "FAIL"
		if len(c.Missing) == 0 && len(c.UnacknowledgedUnexpected) == 0 && len(c.StaleKnownUnexpected) == 0 {
			label = "KNOWN GAP"
		}
		fmt.Fprintf(&b, "\n%s %s (%s)\n", label, c.ID, c.Surface)
		for _, e := range c.Missing {
			fmt.Fprintf(&b, "  missing: %s=%s\n", e.Kind, e.Value)
		}
		for _, o := range c.Unexpected {
			fmt.Fprintf(&b, "  unexpected: %s=%s\n", o.Kind, o.Value)
		}
		for _, e := range c.StaleKnownUnexpected {
			fmt.Fprintf(&b, "  stale known exception: %s=%s\n", e.Kind, e.Value)
		}
	}
	return b.String()
}

func nonNilExpected(v []expectation) []expectation {
	if v == nil {
		return []expectation{}
	}
	return v
}

func nonNilObserved(v []observation) []observation {
	if v == nil {
		return []observation{}
	}
	return v
}

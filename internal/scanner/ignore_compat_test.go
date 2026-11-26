package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// compatFixture is a project tree with the shapes the patterns below are
// meant for, plus near misses: nested directories with the same name, files
// and directories sharing a name, and names that only share a prefix.
var compatFixture = []string{
	"aguara", "cmd/aguara/main.go", "cmd/aguara/aguara", "cmd/aguara/commands/scan.go",
	"x.test", "pkg/y.test",
	"internal/rules/builtin/a.yaml", "internal/rules/builtin/sub/b.yaml", "internal/rules/compiler.go",
	"testdata/malicious/x.md", "sandbox/s.md", "scripts/run.sh", ".github/scripts/check.sh",
	"DOCS/a.md", "CHANGELOG.md", "docs/CHANGELOG.md", "README.md", "sub/README.md", "RULES.md",
	"vendor/lib/x.go", "src/vendor/y.go", "tools/vendor",
	".venv/lib/site.py", "__pycache__/m.pyc", "pkg/__pycache__/n.pyc",
	"dist/app.js", "web/dist/b.js", "distribution.md",
	"build/out.md", "src/build/c.md", "builder/x.md",
	"bin/run", "tools/bin/x",
	"a.exe", "lib.dll", "x.so",
	".idea/ws.xml", ".vscode/mcp.json",
	"f.swp", "g.swo", "debug.log", "logs/app.log",
	"tmp/t.md", "temp/u.md", "coverage/index.html", "c.cover",
	"payload.md", "skills/payload.md",
	"generated/api/client.ts", "docs/guide.md", "docs/internal/notes.md",
	"web/app.min.js", "fixtures/a.json", "pkg/fixtures/b.json",
	"node_modules/pkg/index.js", ".git/config",
}

// The patterns of the repository's own .aguara.yml, of the files `aguara
// init` scaffolded before and after this change, of the README examples
// and of the action test fixture.
var compatPatterns = []struct {
	source  string
	pattern string
}{
	{"repo .aguara.yml", "internal/rules/builtin/**"},
	{"repo .aguara.yml", "testdata/**"},
	{"repo .aguara.yml", "sandbox/**"},
	{"repo .aguara.yml", "scripts/**"},
	{"repo .aguara.yml", "DOCS/**"},
	{"repo .aguara.yml", "CHANGELOG.md"},
	{"repo .aguara.yml", "RULES.md"},
	{"repo .aguara.yml", "README.md"},
	{"repo .aguara.yml", "aguara"},
	{"repo .aguara.yml", "*.test"},
	{"old init .aguara.yml", "*.log"},
	{"old init .aguara.yml", "vendor/"},
	{"old init .aguara.yml", "node_modules/"},
	{"old init .aguara.yml", ".git/"},
	{"old init .aguaraignore", ".venv/"},
	{"old init .aguaraignore", "__pycache__/"},
	{"old init .aguaraignore", "dist/"},
	{"old init .aguaraignore", "build/"},
	{"old init .aguaraignore", "bin/"},
	{"old init .aguaraignore", "*.exe"},
	{"old init .aguaraignore", "*.dll"},
	{"old init .aguaraignore", "*.so"},
	{"old init .aguaraignore", ".idea/"},
	{"old init .aguaraignore", ".vscode/"},
	{"old init .aguaraignore", "*.swp"},
	{"old init .aguaraignore", "*.swo"},
	{"old init .aguaraignore", "tmp/"},
	{"old init .aguaraignore", "temp/"},
	{"old init .aguaraignore", "coverage/"},
	{"old init .aguaraignore", "*.cover"},
	{"README", "dist/"},
	{"README", "/build/"},
	{"README", "/build"},
	{"README", "**/fixtures/"},
	{"README", "generated/**"},
	{"README", "docs/*.md"},
	{"README", "*.min.js"},
	{"README", "docs/internal"},
	{"action fixture .aguaraignore", "payload.md"},
}

// changedByDesign lists the patterns that matched nothing before because
// they end with a slash, start with one, or name a directory by its path.
var changedByDesign = map[string]bool{
	"vendor/": true, "node_modules/": true, ".git/": true, ".venv/": true, "__pycache__/": true,
	"dist/": true, "build/": true, "bin/": true, ".idea/": true, ".vscode/": true,
	"tmp/": true, "temp/": true, "coverage/": true,
	"/build/": true, "/build": true, "**/fixtures/": true, "docs/internal": true,
}

func legacyMatches(pattern string, files []string) []string {
	var out []string
	for _, f := range files {
		if matchGlob(pattern, filepath.FromSlash(f)) {
			out = append(out, f)
		}
	}
	return out
}

func newMatches(pattern string, files []string) []string {
	r := compileIgnoreRule(pattern)
	var out []string
	for _, f := range files {
		if r.matchFile(filepath.FromSlash(f), true) {
			out = append(out, f)
		}
	}
	return out
}

func describe(files []string) string {
	if len(files) == 0 {
		return "(none)"
	}
	return strings.Join(files, ", ")
}

// Patterns that matched files before match exactly the same files now;
// the only patterns whose result changes are the directory forms, which
// matched nothing before. A real directory walk agrees with the matcher.
func TestIgnorePatternCompatibilityTable(t *testing.T) {
	var table strings.Builder
	table.WriteString("| Source | Pattern | Matched before | Matched after |\n|---|---|---|---|\n")
	for _, tc := range compatPatterns {
		before := legacyMatches(tc.pattern, compatFixture)
		after := newMatches(tc.pattern, compatFixture)
		fmt.Fprintf(&table, "| %s | `%s` | %s | %s |\n", tc.source, tc.pattern, describe(before), describe(after))
		if changedByDesign[tc.pattern] {
			if len(before) != 0 {
				t.Errorf("%q: expected no match before, got %v", tc.pattern, before)
			}
			if len(after) == 0 {
				t.Errorf("%q: directory form should now match", tc.pattern)
			}
			continue
		}
		if !slices.Equal(before, after) {
			t.Errorf("%q changed: before %v, after %v", tc.pattern, before, after)
		}
	}
	t.Log("\n" + table.String())
}

func TestIgnorePatternWalkAgreesWithMatcher(t *testing.T) {
	dir := t.TempDir()
	fixture := compatFixture
	if caseInsensitive(t, dir) {
		// DOCS/ and docs/ would be one directory.
		fixture = slices.DeleteFunc(slices.Clone(fixture), func(f string) bool { return strings.HasPrefix(f, "DOCS/") })
	}
	for _, f := range fixture {
		path := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range compatPatterns {
		td := &TargetDiscovery{IgnorePatterns: []string{tc.pattern}}
		targets, err := td.Discover(dir)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		var got []string
		for _, target := range targets {
			got = append(got, filepath.ToSlash(target.RelPath))
		}
		sort.Strings(got)
		excluded := newMatches(tc.pattern, fixture)
		var want []string
		for _, f := range fixture {
			// A walk always skips .git and node_modules.
			alwaysSkipped := strings.HasPrefix(f, ".git/") || strings.HasPrefix(f, "node_modules/")
			if !slices.Contains(excluded, f) && !isBinaryExt(f) && !alwaysSkipped {
				want = append(want, f)
			}
		}
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("%q: walk kept %v, matcher keeps %v", tc.pattern, got, want)
		}
	}
}

func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(probe) }()
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

func TestMatchSegments(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},
		{"**/b", "b", true},
		{"**/b", "x/b", true},
		{"a/**", "a", false},
		{"a/**", "a/x", true},
		{"a/**", "a/x/y", true},
		{"*/dist", "web/dist", true},
		{"*/dist", "a/web/dist", false},
		{"docs/*.md", "docs/a.md", true},
		{"docs/*.md", "docs/x/a.md", false},
		{"[!a]*", "b", true},
		{"[^a]*", "a", false},
		{strings.Repeat("**/", 40) + "z", strings.Repeat("d/", 60) + "z", true},
	} {
		if got := matchSegments(translateNegatedClasses(tc.pattern), tc.name); got != tc.want {
			t.Errorf("matchSegments(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestTranslateNegatedClasses(t *testing.T) {
	for in, want := range map[string]string{
		"[!a]":      "[^a]",
		"x[!ab]y":   "x[^ab]y",
		"[a!]":      "[a!]",
		"!x":        "!x",
		"[!a][!b]":  "[^a][^b]",
		"plain.md":  "plain.md",
		"[[!]":      "[[!]",
		"[a]![!b]c": "[a]![^b]c",
	} {
		if got := translateNegatedClasses(in); got != want {
			t.Errorf("translateNegatedClasses(%q) = %q, want %q", in, got, want)
		}
	}
	if filepath.Separator == '/' {
		if got := translateNegatedClasses(`\[!a]`); got != `\[!a]` {
			t.Errorf("escaped bracket rewritten: %q", got)
		}
	}
}

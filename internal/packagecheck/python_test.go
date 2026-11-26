package packagecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// refSummary renders refs as "name version [group]" lines for compact
// assertions; unpinned refs render as "name (constraint)".
func refSummary(refs []PackageRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		s := r.Name + " " + r.Version
		if r.Unpinned {
			s = r.Name + " (" + r.Constraint + ")"
		}
		if r.Group != "" {
			s += " [" + r.Group + "]"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func fixtureTarget(dir, source string) Target {
	return Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join("testdata", dir, source), Source: source}
}

func TestParseUVLockRegistryOnly(t *testing.T) {
	refs, err := ParseUVLock(fixtureTarget("python-uv", "uv.lock"))
	require.NoError(t, err)
	require.Equal(t, []string{"evil-pkg 1.0", "iniconfig 2.3.1", "mirror-pkg 6.0.0", "six 1.16.0"}, refSummary(refs),
		"virtual, editable, git, url, path and directory entries have no PyPI identity")
	for _, r := range refs {
		require.Equal(t, intel.EcosystemPyPI, r.Ecosystem)
		require.Equal(t, "uv.lock", r.Source)
		require.NotZero(t, r.Line)
	}
	require.Equal(t, 42, findRef(t, refs, "evil-pkg").Line, "line of the [[package]] header")
}

func TestParsePoetryLockCurrentAndLegacy(t *testing.T) {
	refs, err := ParsePoetryLock(fixtureTarget("python-poetry", "poetry.lock"))
	require.NoError(t, err)
	require.Equal(t, []string{"evil-pkg 1.0.0 [dev]", "private-pkg 2.0.0", "requests 2.31.0"}, refSummary(refs),
		"git, directory and url sources are skipped; a legacy index source is a registry; main+dev is a main dependency")

	refs, err = ParsePoetryLock(fixtureTarget("python-poetry-legacy", "poetry.lock"))
	require.NoError(t, err)
	require.Equal(t, []string{"Evil_Pkg 1.0.0 [dev]", "six 1.16.0"}, refSummary(refs),
		"lock-version 1.1 records category and keeps files under [metadata.files]")
}

func TestParsePipfileLockCategories(t *testing.T) {
	refs, err := ParsePipfileLock(fixtureTarget("python-pipfile", "Pipfile.lock"))
	require.NoError(t, err)
	require.Equal(t, []string{"Evil_Pkg 1.0 [develop]", "loose (*) [develop]", "requests 2.31.0", "sphinx 7.2.6 [docs]"}, refSummary(refs),
		"VCS, editable path and file entries are skipped; custom categories are read")
}

func TestParsePDMLock(t *testing.T) {
	refs, err := ParsePDMLock(fixtureTarget("python-pdm", "pdm.lock"))
	require.NoError(t, err)
	require.Equal(t, []string{"evil-pkg 1.0.0 [dev]", "requests 2.31.0"}, refSummary(refs))
}

func TestParsePylock(t *testing.T) {
	refs, err := ParsePylock(fixtureTarget("python-pylock", "pylock.toml"))
	require.NoError(t, err)
	require.Equal(t, []string{"evil-pkg 1.0", "no-version ()", "six 1.16.0"}, refSummary(refs),
		"directory, vcs and archive packages are direct references; a package without a version is unpinned")
	require.True(t, isPylockName("pylock.toml"))
	require.True(t, isPylockName("pylock.dev.toml"))
	require.False(t, isPylockName("pylock.a.b.toml"))
	require.False(t, isPylockName("pylock..toml"))
	require.False(t, isPylockName("mypylock.toml"))
}

func TestParseRequirementsIncludesAndPins(t *testing.T) {
	target := fixtureTarget("python-requirements", "requirements.txt")
	target.Root = filepath.Join("testdata", "python-requirements")
	parsed, err := parseRequirementsTarget(target, newRequirementsCache())
	require.NoError(t, err)
	require.Equal(t, []string{
		"Evil_Pkg 1.0",
		"bare-name ()",
		"loose (>=1.0,<2)",
		"requests 2.31.0",
		"six 1.16.0",
		"urllib3 2.0.7 [constraint]",
		"wild (==1.*)",
	}, refSummary(parsed.refs), "editable, path, archive, VCS and URL requirements are skipped")
	require.Equal(t, []string{UnresolvedIncludeURL, UnresolvedIncludeOutside, UnresolvedIncludeMissing}, unresolvedReasons(parsed.unresolved),
		"URL include, include outside the project and missing include")
	require.Equal(t, "../outside.txt", parsed.unresolved[1].Argument)
	require.Equal(t, 20, parsed.unresolved[1].Line)
	require.Equal(t, target.Path, parsed.unresolved[1].Path)
	evil := findRef(t, parsed.refs, "Evil_Pkg")
	require.Equal(t, 10, evil.Line)
	require.Equal(t, filepath.Join("testdata", "python-requirements", "requirements.txt"), evil.Path)
	six := findRef(t, parsed.refs, "six")
	require.Equal(t, filepath.Join("testdata", "python-requirements", "requirements", "base.txt"), six.Path)
	require.Equal(t, 1, six.Line)
	require.Equal(t, 6, findRef(t, parsed.refs, "requests").Line, "a continued line reports its first physical line")
}

func unresolvedReasons(list []UnresolvedInclude) []string {
	out := make([]string, 0, len(list))
	for _, u := range list {
		out = append(out, u.Reason)
	}
	return out
}

func findRef(t *testing.T, refs []PackageRef, name string) PackageRef {
	t.Helper()
	for _, r := range refs {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("ref %q not found in %v", name, refSummary(refs))
	return PackageRef{}
}

func TestParseRequirementsLineGrammar(t *testing.T) {
	for _, tc := range []struct {
		line string
		want string // "" = skipped
	}{
		{"pkg==1.0", "pkg 1.0"},
		{"pkg ==  1.0", "pkg 1.0"},
		{"pkg===1.0-custom", "pkg 1.0-custom"},
		{"pkg (==1.0)", "pkg 1.0"},
		{"pkg[a, b]==1.0;python_version<'3.9'", "pkg 1.0"},
		{"pkg==1.0 --hash=sha256:00 --hash sha256:11", "pkg 1.0"},
		{"pkg==1.0 --config-settings=key=value", "pkg 1.0"},
		{"pkg==1.0,>=0.9", "pkg 1.0"},
		{"pkg==1.0,==2.0", "pkg (==1.0,==2.0)"},
		{"pkg==1.0,==1.0", "pkg 1.0"},
		{"pkg==1.0, == 1.0.0", "pkg 1.0"},
		{"pkg===1.0,===1.0", "pkg 1.0"},
		{"pkg===1.0,==1.0.0", "pkg (===1.0,==1.0.0)"},
		{"pkg~=1.0", "pkg (~=1.0)"},
		{"pkg!=1.0", "pkg (!=1.0)"},
		{"pkg==${VERSION}", "pkg (==${VERSION})"},
		{"pkg", "pkg ()"},
		{"pkg @ https://example.com/pkg-1.0.tar.gz", ""},
		{"pkg[x] @ file:///tmp/pkg", ""},
		{"./local", ""},
		{"../sibling", ""},
		{"/abs/path", ""},
		{"~/home/path", ""},
		{"pkg-1.0-py3-none-any.whl", ""},
		{"pkg-1.0.tar.gz", ""},
		{"git+https://example.com/repo.git#egg=pkg", ""},
		{"https://example.com/pkg.zip", ""},
		{"-e .", ""},
		{"--editable=git+https://example.com/repo.git#egg=pkg", ""},
		{"-i https://pypi.org/simple", ""},
		{"--trusted-host example.com --pre", ""},
		{"--only-binary :all:", ""},
	} {
		items, err := parseRequirementsLine(tc.line, 1)
		require.NoErrorf(t, err, "line %q", tc.line)
		var got []string
		for _, it := range items {
			if it.ref != nil {
				got = refSummary([]PackageRef{*it.ref})
			}
		}
		if tc.want == "" {
			require.Emptyf(t, got, "line %q must not yield a package", tc.line)
			continue
		}
		require.Equalf(t, []string{tc.want}, got, "line %q", tc.line)
	}
}

func TestParseRequirementsMalformedIsAnError(t *testing.T) {
	for _, line := range []string{
		"pkg==",
		"pkg==not a version",
		"pkg==1.0abc!",
		"pkg>>1.0",
		"pkg[unterminated==1.0",
		"pkg==1.0;",
		"-pkg",
		"--unknown-option value",
		"pkg==1.0 --unknown-per-req",
		"-r",
		"pkg==1.0 --hash",
		"-r 'unterminated",
		"$weird==1.0",
	} {
		_, err := parseRequirementsLine(line, 1)
		require.Errorf(t, err, "line %q must be rejected", line)
	}
}

func TestParseRequirementsContinuationAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	content := utf8BOM + "# comment ending in a backslash is not a continuation \\\n" +
		"alpha==1.0 \\\n" +
		"    --hash=sha256:00\n" +
		"beta==2.0 # trailing comment\r\n" +
		"gamma==3.0 \\\n" +
		"# a comment line ends the continuation\n" +
		"url-with-fragment @ https://example.com/x.zip#sha256=00\n"
	writeFile(t, path, content)
	refs, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: path, Source: "requirements.txt"})
	require.NoError(t, err)
	require.Equal(t, []string{"alpha 1.0", "beta 2.0", "gamma 3.0"}, refSummary(refs))
	require.Equal(t, 2, findRef(t, refs, "alpha").Line)
	require.Equal(t, 5, findRef(t, refs, "gamma").Line)
}

func TestParseRequirementsIncludeBoundaries(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside-pkg==1.0\n")
	writeFile(t, filepath.Join(root, "sub", "inner.txt"), "inner-pkg==1.0\n")
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape")))
	writeFile(t, filepath.Join(root, "requirements.txt"), strings.Join([]string{
		"-r sub/inner.txt",
		"-r " + filepath.Join(outside, "secret.txt"),
		"-r escape/secret.txt",
		"-r ../" + filepath.Base(outside) + "/secret.txt",
		"--requirement=${HOME}/x.txt",
		"-rfile:///etc/hosts",
		"",
	}, "\n"))
	parsed, err := parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements.txt"), Source: "requirements.txt", Root: root}, newRequirementsCache())
	require.NoError(t, err)
	require.Equal(t, []string{"inner-pkg 1.0"}, refSummary(parsed.refs), "nothing outside the project root is read")
	require.Equal(t, []string{UnresolvedIncludeOutside, UnresolvedIncludeOutside, UnresolvedIncludeOutside, UnresolvedIncludeVariable, UnresolvedIncludeURL},
		unresolvedReasons(parsed.unresolved))

	// A linked include file is unsafe input, reported as an error.
	writeFile(t, filepath.Join(root, "real.txt"), "linked-pkg==1.0\n")
	require.NoError(t, os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "linked.txt")))
	writeFile(t, filepath.Join(root, "requirements-linked.txt"), "-r linked.txt\n")
	_, err = parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements-linked.txt"), Source: "requirements-linked.txt", Root: root}, newRequirementsCache())
	require.Error(t, err)

	// A malformed line in an included file is skipped and reported; the
	// rest of the target is still read.
	writeFile(t, filepath.Join(root, "bad.txt"), "pkg==\n")
	writeFile(t, filepath.Join(root, "requirements-bad.txt"), "good==1.0\n-r bad.txt\n")
	refs, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements-bad.txt"), Source: "requirements-bad.txt", Root: root})
	var syntax *RequirementsSyntaxError
	require.ErrorAs(t, err, &syntax)
	require.Equal(t, []string{"good 1.0"}, refSummary(refs))
}

func TestParseRequirementsIncludeDepthLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i <= maxRequirementsIncludeDepth+1; i++ {
		writeFile(t, filepath.Join(root, fmt.Sprintf("r%d.txt", i)), fmt.Sprintf("pkg%d==1.0\n-r r%d.txt\n", i, i+1))
	}
	writeFile(t, filepath.Join(root, fmt.Sprintf("r%d.txt", maxRequirementsIncludeDepth+2)), "last==1.0\n")
	_, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "r0.txt"), Root: root})
	require.ErrorContains(t, err, "deeper")

	shallow := t.TempDir()
	writeFile(t, filepath.Join(shallow, "requirements.txt"), "-r a.txt\n")
	writeFile(t, filepath.Join(shallow, "a.txt"), "a==1.0\n-r b.txt\n")
	writeFile(t, filepath.Join(shallow, "b.txt"), "b==1.0\n")
	refs, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(shallow, "requirements.txt"), Root: shallow})
	require.NoError(t, err)
	require.Equal(t, []string{"a 1.0", "b 1.0"}, refSummary(refs))
}

func TestPythonTOMLLockfilesRejectMalformedInput(t *testing.T) {
	uvPkg := "version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	for _, tc := range []struct {
		source, content string
	}{
		{"uv.lock", "[[package]]\nname = \"pkg\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"}, // no version
		{"uv.lock", "version = 2\n" + strings.TrimPrefix(uvPkg, "version = 1\n")},
		{"uv.lock", "version = \"1\"\n"},
		{"uv.lock", "version = 1\n[[package]]\nversion = \"1.0\"\nsource = { registry = \"x\" }\n"},
		{"uv.lock", "version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n"},
		{"uv.lock", "version = 1\n[[package]]\nname = \"pkg\"\nsource = { registry = \"https://pypi.org/simple\" }\n"},
		{"uv.lock", "version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\nsource = { registry = \"a\", git = \"b\" }\n"},
		{"uv.lock", "version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\nsource = { mystery = \"a\" }\n"},
		{"uv.lock", "version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\nsource = \"registry\"\n"},
		{"uv.lock", uvPkg + "name = \"other\"\n"},
		{"uv.lock", uvPkg + "[package.version]\nx = 1\n"},
		{"uv.lock", "version = 1\n[package]\nname = \"pkg\"\n"},
		{"uv.lock", "version = 1\npackage = [{ name = \"pkg\" }]\n"},
		{"uv.lock", "version = 1\n[package.metadata]\nx = 1\n"},
		{"uv.lock", "version = 1\n[[package]]\nname = 7\n"},
		{"uv.lock", uvPkg + "garbage = \"unterminated"},
		{"poetry.lock", "[[package]]\nname = \"pkg\"\n"},
		{"poetry.lock", "[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n[package.source]\ntype = \"svn\"\nurl = \"x\"\n"},
		{"poetry.lock", "[[package]]\nname = \"pkg\"\nversion = \"1.0\"\ngroups = \"dev\"\n"},
		{"poetry.lock", "[metadata]\nlock-version = \"3.0\"\n"},
		{"poetry.lock", "[metadata]\nlock-version = 2\n"},
		{"pdm.lock", "[metadata]\nlock_version = \"5.0\"\n"},
		{"pdm.lock", "[[package]]\nname = \"pkg\"\ngroups = [\"default\"]\n"},
		{"pdm.lock", "[[package]]\nname = \"pkg\"\nversion = \"1.0\"\neditable = \"yes\"\n"},
		{"pylock.toml", "[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n"},
		{"pylock.toml", "lock-version = \"2.0\"\n"},
		{"pylock.toml", "lock-version = \"1.0\"\n[[packages]]\nversion = \"1.0\"\n"},
	} {
		path := filepath.Join(t.TempDir(), tc.source)
		writeFile(t, path, tc.content)
		refs, err := parseTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: path, Source: tc.source})
		require.Errorf(t, err, "%s must reject:\n%s", tc.source, tc.content)
		require.Nil(t, refs)
	}
}

func TestPythonTOMLLockfilesAcceptEquivalentSyntax(t *testing.T) {
	for _, content := range []string{
		"version = 1 # comment\n[[ package ]]\n'name' = 'pkg'\n\"version\" = \"1.0\"\nsource.registry = \"https://pypi.org/simple\"\n",
		"version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n[package.source]\nregistry = \"https://pypi.org/simple\"\n",
		"version = 1\nnotes = '''\n[[package]]\nname = \"phantom\"\n'''\n[[package]]\nname = \"pk\\u0067\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
	} {
		path := filepath.Join(t.TempDir(), "uv.lock")
		writeFile(t, path, content)
		refs, err := ParseUVLock(Target{Path: path})
		require.NoErrorf(t, err, "content:\n%s", content)
		require.Equal(t, []string{"pkg 1.0"}, refSummary(refs))
	}
}

func TestPipfileLockRejectsMalformedInput(t *testing.T) {
	for _, content := range []string{
		`[]`,
		`{"default": []}`,
		`{"default": {"pkg": "==1.0"}}`,
		`{"default": {"pkg": {"version": 1}}}`,
		`{"default": {"pkg": {"version": "==1.0", "editable": "yes"}}}`,
		`{"_meta": {"pipfile-spec": 7}}`,
		`{"_meta": {"pipfile-spec": "6"}}`,
		`{"default": {"": {"version": "==1.0"}}}`,
		`{"default": {"pkg": null}}`,
		`{"default": {`,
	} {
		refs, err := parsePipfileLockBytes([]byte(content), "Pipfile.lock")
		require.Errorf(t, err, "must reject %s", content)
		require.Nil(t, refs)
	}
	refs, err := parsePipfileLockBytes([]byte(`{"default":{"pkg":{"version":"==1.0","Version":"==9.9"},"pkg":{"version":"==2.0"}},"Develop":{"x":{"version":"==1"}}}`), "Pipfile.lock")
	require.NoError(t, err)
	require.Equal(t, []string{"Develop:x", "pkg:2.0"}, func() []string {
		var out []string
		for _, r := range refs {
			if r.Group != "" {
				out = append(out, r.Group+":"+r.Name)
			} else {
				out = append(out, r.Name+":"+r.Version)
			}
		}
		sort.Strings(out)
		return out
	}(), "exact keys, last duplicate wins, unknown categories are categories")
}

func TestTOMLNodeBudgetRejectsHugeExpressions(t *testing.T) {
	var b strings.Builder
	b.WriteString("version = 1\nx = [")
	for i := 0; i <= maxTOMLExpressionNodes; i++ {
		b.WriteString("1,")
	}
	b.WriteString("1]\n")
	_, err := parseTOMLLock([]byte(b.String()), "uv.lock", uvLockFormat)
	require.ErrorContains(t, err, "node limit")

	// The same number of values spread across expressions is fine:
	// the arena is reused between expressions.
	b.Reset()
	b.WriteString("version = 1\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "k%d = [%s1]\n", i, strings.Repeat("1,", maxTOMLExpressionNodes/1000))
	}
	_, err = parseTOMLLock([]byte(b.String()), "uv.lock", uvLockFormat)
	require.NoError(t, err)

	// Strings and comments do not count, and cannot hide structure.
	require.NoError(t, checkTOMLNodeBudget([]byte("a = \"[[[,,,\" # ,,,,\nb = '''\n,,,\n'''\n"), "x"))
	hidden := "a = \"\"\"x\"\"\"\"\nb = [" + strings.Repeat("1,", maxTOMLExpressionNodes+1) + "1]\n"
	require.Error(t, checkTOMLNodeBudget([]byte(hidden), "x"))
}

func TestPythonLockfileEntryLimit(t *testing.T) {
	c := newPythonRefCollector("uv.lock")
	for i := 0; i < maxPythonLockEntries; i++ {
		require.NoError(t, c.add(PackageRef{Name: fmt.Sprintf("p%d", i), Version: "1"}))
	}
	require.NoError(t, c.add(PackageRef{Name: "P0", Version: "1"}), "a duplicate does not count")
	require.ErrorContains(t, c.add(PackageRef{Name: "extra", Version: "1"}), "more than")
}

func TestDiscoverPythonTargetsAndSkipsEnvironments(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "pylock.toml", "pylock.dev.toml",
		"requirements.txt", "requirements-dev.txt", "constraints.txt", "requirements.in", "Pipfile", "pyproject.toml", "pylock.a.b.toml"} {
		writeFile(t, filepath.Join(root, f), "")
	}
	writeFile(t, filepath.Join(root, "services", "api", "requirements.txt"), "")
	// Installed trees and .venv are not projects. A pyvenv.cfg marker
	// does not hide the directory that carries it.
	writeFile(t, filepath.Join(root, ".venv", "requirements.txt"), "")
	writeFile(t, filepath.Join(root, "env", "pyvenv.cfg"), "home = /usr/bin\n")
	writeFile(t, filepath.Join(root, "env", "lib", "python3.12", "site-packages", "pkg", "uv.lock"), "")
	writeFile(t, filepath.Join(root, "env", "Cargo.lock"), "")
	writeFile(t, filepath.Join(root, "vendored", "site-packages", "dep", "requirements.txt"), "")
	writeFile(t, filepath.Join(root, "node_modules", "x", "requirements.txt"), "")
	targets, err := Discover(root, nil)
	require.NoError(t, err)
	var got []string
	for _, tg := range targets {
		rel, err := filepath.Rel(root, tg.Path)
		require.NoError(t, err)
		require.Equal(t, root, tg.Root)
		got = append(got, tg.Ecosystem+":"+filepath.ToSlash(rel))
	}
	sort.Strings(got)
	require.Equal(t, []string{
		"PyPI:Pipfile.lock", "PyPI:constraints.txt", "PyPI:pdm.lock", "PyPI:poetry.lock", "PyPI:pylock.dev.toml", "PyPI:pylock.toml",
		"PyPI:requirements-dev.txt", "PyPI:requirements.txt", "PyPI:services/api/requirements.txt", "PyPI:uv.lock",
		"crates.io:env/Cargo.lock",
	}, got)

	// The scan root is what the user asked for, even inside an
	// installed tree; only the root's own name marks it as one.
	inside := filepath.Join(root, "env", "lib", "python3.12", "site-packages", "pkg")
	targets, err = Discover(inside, []string{intel.EcosystemPyPI})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	targets, err = Discover(filepath.Dir(inside), []string{intel.EcosystemPyPI})
	require.NoError(t, err)
	require.Empty(t, targets)
}

func TestRunnerPythonMatchingNormalisesNamesAndVersions(t *testing.T) {
	matcher := intel.NewMatcher(intel.Snapshot{
		Records: []intel.Record{
			{ID: "MAL-EVIL-1", Ecosystem: intel.EcosystemPyPI, Name: "Evil.Pkg", Kind: intel.KindMalicious, Versions: []string{"1.0.0"}},
			{ID: "GHSA-evil-alias", Ecosystem: intel.EcosystemPyPI, Name: "evil_pkg", Kind: intel.KindMalicious, Versions: []string{"1.0"}},
			// Non-registry entries with these names must never match.
			{ID: "MAL-GIT", Ecosystem: intel.EcosystemPyPI, Name: "from-git", Kind: intel.KindMalicious, Versions: []string{"1.2.3", "2.0.0"}},
			{ID: "MAL-LOCAL", Ecosystem: intel.EcosystemPyPI, Name: "local-lib", Kind: intel.KindMalicious, Versions: []string{"0.1.0"}},
		},
		AllVersions: []intel.AllVersionsEntry{{ID: "MAL-LOOSE", Ecosystem: intel.EcosystemPyPI, Name: "loose"}},
	})
	runner := &Runner{Matcher: matcher}
	for _, dir := range []string{"python-uv", "python-poetry", "python-poetry-legacy", "python-pipfile", "python-pdm", "python-pylock", "python-requirements"} {
		t.Run(dir, func(t *testing.T) {
			targets, err := Discover(filepath.Join("testdata", dir), []string{intel.EcosystemPyPI})
			require.NoError(t, err)
			require.NotEmpty(t, targets)
			res, err := runner.Run(targets)
			require.NoError(t, err)
			var evil *Hit
			for i := range res.Hits {
				h := &res.Hits[i]
				require.NotContains(t, []string{"from-git", "local-lib"}, h.Ref.Name)
				if intel.PEP503Normalize(h.Ref.Name) == "evil-pkg" {
					evil = h
				}
			}
			require.NotNil(t, evil, "Evil_Pkg / evil-pkg / Evil.Pkg at 1.0 or 1.0.0 must match")
			require.Equal(t, []string{"MAL-EVIL-1", "GHSA-evil-alias"}, evil.AdvisoryIDs, "every matching advisory is kept")
			total := 0
			for _, e := range res.Ecosystems {
				total += e.FindingsCount
			}
			require.Equal(t, len(res.Hits), total)
		})
	}
}

func TestRunnerRequirementsUnpinnedAndSharedIncludes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "requirements", "base.txt"), "evil-pkg==1.0\nloose>=2\n")
	writeFile(t, filepath.Join(root, "requirements.txt"), "-r requirements/base.txt\n")
	writeFile(t, filepath.Join(root, "requirements-dev.txt"), "-r requirements/base.txt\nother==1\n-r https://example.com/x.txt\n")
	matcher := intel.NewMatcher(intel.Snapshot{
		Records:     []intel.Record{{ID: "MAL-EVIL-1", Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg", Kind: intel.KindMalicious, Versions: []string{"1.0"}}},
		AllVersions: []intel.AllVersionsEntry{{ID: "MAL-LOOSE", Ecosystem: intel.EcosystemPyPI, Name: "loose"}},
	})
	targets, err := Discover(root, []string{intel.EcosystemPyPI})
	require.NoError(t, err)
	require.Len(t, targets, 2)
	res, err := (&Runner{Matcher: matcher}).Run(targets)
	require.NoError(t, err)
	require.Len(t, res.Hits, 2, "a shared include is reported once, not once per including file")
	var ids []string
	for _, h := range res.Hits {
		ids = append(ids, h.Record.ID)
		require.Equal(t, filepath.Join(root, "requirements", "base.txt"), h.Ref.Path)
	}
	require.ElementsMatch(t, []string{"MAL-EVIL-1", "MAL-LOOSE"}, ids, "an unpinned requirement matches only an every-version advisory")
	byPath := map[string]EcosystemResult{}
	for _, e := range res.Ecosystems {
		byPath[filepath.Base(e.Path)] = e
	}
	require.Equal(t, 1, byPath["requirements-dev.txt"].Unpinned)
	require.Equal(t, 1, byPath["requirements-dev.txt"].UnresolvedIncludes)
	require.Equal(t, 3, byPath["requirements-dev.txt"].PackagesRead)
	require.Equal(t, 2, byPath["requirements-dev.txt"].FindingsCount+byPath["requirements.txt"].FindingsCount)
}

func TestPythonLockfileInputRejectsLinkedFiles(t *testing.T) {
	for _, tc := range []struct{ source, content string }{
		{"uv.lock", "version = 1\n[[package]]\nname = \"example\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"},
		{"poetry.lock", "[[package]]\nname = \"example\"\nversion = \"1.0\"\n"},
		{"Pipfile.lock", `{"default":{"example":{"version":"==1.0"}}}`},
		{"pdm.lock", "[[package]]\nname = \"example\"\nversion = \"1.0\"\n"},
		{"pylock.toml", "lock-version = \"1.0\"\n[[packages]]\nname = \"example\"\nversion = \"1.0\"\n"},
		{"requirements.txt", "example==1.0\n"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.source)
			writeFile(t, path, tc.content)
			refs, err := parseTarget(Target{Ecosystem: intel.EcosystemPyPI, Source: tc.source, Path: path})
			require.NoError(t, err)
			require.Len(t, refs, 1, "regular-file control")
			dir := t.TempDir()
			link := filepath.Join(dir, tc.source)
			if err := os.Symlink(path, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			targets, err := Discover(dir, []string{intel.EcosystemPyPI})
			require.NoError(t, err)
			require.Len(t, targets, 1, "unsafe candidates must not disappear")
			result, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}

// A file named like a requirements or constraints file whose lines are not
// in the pip grammar the parser reads is not evaluated: the run lists it
// instead of failing. Input the parser refuses because pip could still
// read it and install something unseen stays an error.
func TestRunnerListsRequirementsSyntaxItCannotRead(t *testing.T) {
	m := intel.NewMatcher(intel.Snapshot{})
	run := func(t *testing.T, files map[string]string, target string) (*RunResult, error) {
		t.Helper()
		dir := t.TempDir()
		for name, content := range files {
			writeFile(t, filepath.Join(dir, name), content)
		}
		return (&Runner{Matcher: m}).Run([]Target{{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(dir, target), Source: target, Root: dir}})
	}
	for name, tc := range map[string]struct {
		files  map[string]string
		target string
		detail string
	}{
		// Line 1 reads as a requirement named "Constraints"; line 2 does not.
		"documentation named constraints.txt": {map[string]string{"constraints.txt": "Constraints\n===========\n\n.. class:: CheckConstraint(*, check, name)\n"}, "constraints.txt", "line 2 is not"},
		"unknown option":                      {map[string]string{"requirements.txt": "--frobnicate\nflask==3.0.0\n"}, "requirements.txt", "line 1 is not"},
		"malformed specifier":                 {map[string]string{"requirements.txt": "flask==3.0.0\npkg==\n"}, "requirements.txt", "line 2 is not"},
		"unterminated quote":                  {map[string]string{"requirements.txt": "-r 'base.txt\n"}, "requirements.txt", "line 1 is not"},
		"malformed include":                   {map[string]string{"requirements.txt": "good==1.0\n-r bad.txt\n", "bad.txt": "pkg==\n"}, "requirements.txt", "line 1 of bad.txt, which it includes, is not"},
		"several lines":                       {map[string]string{"requirements.txt": "--frobnicate\nflask==3.0.0\npkg==\n"}, "requirements.txt", "line 1 and 1 more line are not pip requirements or options Aguara reads"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := run(t, tc.files, tc.target)
			require.NoError(t, err)
			require.Len(t, res.Ecosystems, 1, "the lines that parsed were evaluated")
			require.Len(t, res.Unparsed, 1)
			require.Equal(t, ReasonFormatNotParsed, res.Unparsed[0].Reason)
			require.Contains(t, res.Unparsed[0].Detail, tc.detail)
			require.Contains(t, res.Unparsed[0].Detail, "the other lines were checked")
			require.True(t, res.Unparsed[0].PartlyRead())
			require.Empty(t, res.Requirements, "a file with a skipped line never stands for a manifest")
		})
	}

	// The entries that parsed are matched as usual.
	matcher := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{
		{ID: "MAL-TEST", Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg", Kind: intel.KindMalicious, Versions: []string{"1.0"}},
		{ID: "MAL-TEST-2", Ecosystem: intel.EcosystemPyPI, Name: "other-evil", Kind: intel.KindMalicious, Versions: []string{"2.0"}},
	}})
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "--frobnicate\nevil-pkg==1.0\n-r base.txt\n")
	writeFile(t, filepath.Join(dir, "base.txt"), "pkg==\nother-evil==2.0 ; python_version >= '3'\n")
	res, err := (&Runner{Matcher: matcher}).Run([]Target{{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(dir, "requirements.txt"), Source: "requirements.txt", Root: dir}})
	require.NoError(t, err)
	require.Len(t, res.Hits, 2, "the pin in the file and the one in its include")
	require.Len(t, res.Unparsed, 1)
	require.Equal(t, 2, res.Ecosystems[0].FindingsCount)

	deep := map[string]string{}
	for i := 0; i <= maxRequirementsIncludeDepth+2; i++ {
		deep[fmt.Sprintf("r%d.txt", i)] = fmt.Sprintf("pkg%d==1.0\n-r r%d.txt\n", i, i+1)
	}
	deep["requirements.txt"] = "-r r0.txt\n"
	for name, tc := range map[string]struct {
		files  map[string]string
		target string
	}{
		"declared encoding":   {map[string]string{"requirements.txt": "# -*- coding: latin-1 -*-\nflask==3.0.0\n"}, "requirements.txt"},
		"not UTF-8":           {map[string]string{"requirements.txt": "flask==3.0.0\n\xff\xfe\n"}, "requirements.txt"},
		"overlong line":       {map[string]string{"requirements.txt": strings.Repeat("a", maxRequirementsLineBytes+1) + "\n"}, "requirements.txt"},
		"includes too deep":   {deep, "requirements.txt"},
		"missing target file": {map[string]string{}, "requirements.txt"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, tc.files, tc.target)
			require.Error(t, err)
		})
	}

	dir = t.TempDir()
	writeFile(t, filepath.Join(dir, "real.txt"), "flask==3.0.0\n")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "requirements.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err = (&Runner{Matcher: m}).Run([]Target{{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(dir, "requirements.txt"), Source: "requirements.txt", Root: dir}})
	require.Error(t, err, "a symlinked requirements file is unsafe input")
}

// A `===` pin is compared the way pip compares it, as a string against
// the release's normalized version, while `==` keeps PEP 440 equality.
func TestRequirementsArbitraryEqualityMatchesLikePip(t *testing.T) {
	matcher := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{{
		ID: "MAL-ARB", Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg", Kind: intel.KindMalicious, Versions: []string{"0.0.1"},
	}}})
	for _, tc := range []struct {
		line string
		hit  bool
	}{
		{"evil-pkg===0.0.1\n", true},
		{"Evil_Pkg===0.0.1\n", true},
		{"evil-pkg===0.0.1.0\n", false}, // pip would not select 0.0.1
		{"evil-pkg===v0.0.1\n", false},
		{"evil-pkg==0.0.1.0\n", true}, // PEP 440 equality pads zeros
		{"evil-pkg==v0.0.1\n", true},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "requirements.txt")
		writeFile(t, path, tc.line)
		res, err := (&Runner{Matcher: matcher}).Run([]Target{{Ecosystem: intel.EcosystemPyPI, Path: path, Source: "requirements.txt", Root: dir}})
		require.NoError(t, err)
		require.Equal(t, tc.hit, len(res.Hits) == 1, "line %q", tc.line)
	}
}

func TestPythonParsersDoNotEchoInputInErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uv.lock")
	writeFile(t, path, "version = 1\n[[package]]\nname = secretFixtureTOKEN\n")
	_, err := ParseUVLock(Target{Path: path})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secretFixtureTOKEN")
}

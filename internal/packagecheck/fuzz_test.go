package packagecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

// The lockfile parsers are the largest untrusted-input surface in
// aguara: `aguara check` runs them against attacker-controlled files
// in cloned repos. Each fuzz target asserts the parser never panics
// and that every returned ref keeps the basic shape downstream
// matching relies on (a non-empty name).
//
// Parsers read from disk via Target.Path, so each iteration writes
// the fuzzed bytes to a per-iteration temp file.

func fuzzLockfile(f *testing.F, ecosystem, source string, parse func(Target) ([]PackageRef, error), seeds ...string) {
	f.Helper()
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	addTestdataSeeds(f, source)

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), source)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		refs, err := parse(Target{Ecosystem: ecosystem, Path: path, Source: source})
		if err != nil {
			return
		}
		for _, r := range refs {
			if r.Name == "" {
				t.Errorf("parser returned a PackageRef with empty Name (version %q)", r.Version)
			}
		}
	})
}

// addTestdataSeeds feeds every committed fixture with a matching
// basename into the corpus, so the fuzzer starts from real lockfile
// grammar instead of random bytes.
func addTestdataSeeds(f *testing.F, source string) {
	f.Helper()
	matches, err := filepath.Glob(filepath.Join("testdata", "*", source))
	if err != nil {
		return
	}
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		f.Add(data)
	}
}

func FuzzParsePNPMLock(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemNPM, "pnpm-lock.yaml", ParsePNPMLock,
		"lockfileVersion: '9.0'\npackages:\n  node-ipc@9.2.3:\n    resolution: {integrity: sha512-x}\n",
		"packages:\n  safe-ipc@npm:node-ipc@9.2.3:\n    resolution: {integrity: sha512-x}\n",
		"a: &a\n  b: *a\n",
	)
}

func FuzzParsePackageLock(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemNPM, "package-lock.json", ParsePackageLock,
		`{"lockfileVersion":3,"packages":{"node_modules/node-ipc":{"version":"9.2.3"}}}`,
		`{"lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.0.0"}}}`,
		`{"packages":{"node_modules/safe":{"name":"node-ipc","version":"9.2.3"}}}`,
	)
}

func FuzzParseYarnLock(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemNPM, "yarn.lock", ParseYarnLock,
		"# yarn lockfile v1\n\nnode-ipc@^9.2.0:\n  version \"9.2.3\"\n",
		"__metadata:\n  version: 8\n\n\"node-ipc@npm:^9.2.0\":\n  version: 9.2.3\n",
	)
}

func FuzzParseBunLock(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemNPM, "bun.lock", ParseBunLock,
		`{"lockfileVersion":1,"packages":{"node-ipc":["node-ipc@9.2.3","",{},"sha512-x"]}}`,
		`{"lockfileVersion":0,"packages":{"alias":["node-ipc@9.2.3"]}}`,
	)
}

// FuzzParseGo writes the input as both go.sum and the go.mod beside it,
// so the go.sum reader and the go.mod reader it consults (require,
// replace and exclude directives, blocks) run on the same bytes.
func FuzzParseGo(f *testing.F) {
	for _, s := range []string{
		"github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.2.3/go.mod h1:def=\n",
		"module m\n\nrequire\tgithub.com/foo/bar v1.2.3\nrequire(\n\tgithub.com/x/y v0.1.0 // indirect\n)\nexclude(\n\t\"github.com/foo/bar\" v1.2.3\n)\nreplace github.com/x/y => ../y\n",
	} {
		f.Add([]byte(s))
	}
	addTestdataSeeds(f, "go.sum")
	addTestdataSeeds(f, "go.mod")
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if os.WriteFile(filepath.Join(dir, "go.sum"), data, 0o600) != nil || os.WriteFile(filepath.Join(dir, "go.mod"), data, 0o600) != nil {
			t.Skip()
		}
		for _, source := range []string{"go.sum", "go.mod"} {
			refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: filepath.Join(dir, source), Source: source})
			if err != nil {
				if refs != nil {
					t.Errorf("%s: refs returned alongside an error", source)
				}
				continue
			}
			for _, r := range refs {
				if r.Name == "" || r.Version == "" {
					t.Errorf("%s: PackageRef without a name or version: %+v", source, r)
				}
				if r.GraphOnly && r.Source != "go.sum" {
					t.Errorf("%s: graph-only ref from %s", source, r.Source)
				}
			}
		}
	})
}

func FuzzParseCargo(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemCargo, "Cargo.lock", ParseCargo,
		"[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n",
	)
}

func FuzzParseComposer(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemPackagist, "composer.lock", ParseComposer,
		`{"packages":[{"name":"symfony/console","version":"v6.0.0"}]}`,
	)
}

func FuzzParseRuby(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemRubyGems, "Gemfile.lock", ParseRuby,
		"GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nDEPENDENCIES\n  rake\n",
	)
}

func FuzzParseMaven(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemMaven, "pom.xml", ParseMaven,
		`<project><dependencies><dependency><groupId>org.x</groupId><artifactId>y</artifactId><version>1.0</version></dependency></dependencies></project>`,
	)
}

// FuzzParsePythonLockfiles drives every structured Python lockfile
// parser (uv.lock, poetry.lock, pdm.lock, pylock.toml, Pipfile.lock)
// with the same input. One target instead of five keeps the nightly
// fuzz budget flat; the four TOML formats share the streaming walker
// and node budget, and each parser rejects the others' shapes cheaply.
// It calls the byte-level entry points: the bounded file read in front
// of them is shared with every other lockfile parser and tested there,
// and skipping five temporary files per input multiplies throughput.
func FuzzParsePythonLockfiles(f *testing.F) {
	for _, s := range []string{
		"version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
		"version = 1\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n[package.source]\ngit = \"https://example.com/x\"\n",
		"[[package]]\nname = \"pkg\"\nversion = \"1.0\"\ngroups = [\"dev\"]\n[package.source]\ntype = \"legacy\"\nurl = \"x\"\n[metadata]\nlock-version = \"2.1\"\n",
		"[metadata]\nlock_version = \"4.5.0\"\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\ngroups = [\"default\"]\neditable = false\n",
		"lock-version = \"1.0\"\ncreated-by = \"x\"\n[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n[packages.vcs]\ntype = \"git\"\n",
		`{"_meta":{"pipfile-spec":6},"default":{"pkg":{"version":"==1.0"}},"develop":{"x":{"git":"y"}}}`,
		"a = \"\"\"x\"\"\"\"\nb = [1,2,[3,{c=4}]]\n",
	} {
		f.Add([]byte(s))
	}
	for _, source := range []string{"uv.lock", "poetry.lock", "pdm.lock", "pylock.toml", "Pipfile.lock"} {
		addTestdataSeeds(f, source)
	}
	toml := func(format tomlLockFormat) func([]byte) ([]PackageRef, error) {
		return func(data []byte) ([]PackageRef, error) { return parseTOMLLock(data, format.label, format) }
	}
	parsers := []struct {
		source string
		parse  func([]byte) ([]PackageRef, error)
	}{
		{"uv.lock", toml(uvLockFormat)}, {"poetry.lock", toml(poetryLockFormat)}, {"pdm.lock", toml(pdmLockFormat)},
		{"pylock.toml", toml(pylockFormat)},
		{"Pipfile.lock", func(data []byte) ([]PackageRef, error) { return parsePipfileLockBytes(data, "Pipfile.lock") }},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if int64(len(data)) > maxManifestBytes {
			t.Skip()
		}
		for _, p := range parsers {
			refs, err := p.parse(data)
			if err != nil {
				if refs != nil {
					t.Errorf("%s: refs returned alongside an error", p.source)
				}
				continue
			}
			checkPythonRefs(t, p.source, refs)
		}
	})
}

// FuzzParseRequirements fuzzes the pip requirements grammar together
// with include resolution: the input is both the discovered file and a
// sibling it may include, so -r / -c handling is exercised on fuzzed
// content without ever leaving the temporary project root.
func FuzzParseRequirements(f *testing.F) {
	for _, s := range []string{
		"pkg==1.0\n",
		"-r other.txt\n-c other.txt\npkg[a,b]==1.0 ; python_version < \"3.9\" \\\n    --hash=sha256:00\n",
		"# c \\\nx>=1,<2\n-e .\ngit+https://x/y.git#egg=z\nname @ https://x/y.zip\n--index-url https://x\n",
		"-r ../escape.txt\n-r ${HOME}/x\n-rfile:///etc/hosts\n",
		"# coding: utf-7\nsix==1.16.0 # +AAo-x+AD0APQ-1\n",
		"--constr other.txt\n--extra-index https://x\n--req a\n-- -r other.txt\nx==1 -r other.txt --g y\n-e ./x -r other.txt\n--pre=1\n",
		utf8BOM + "# coding: utf-7\nx==1\r\n",
	} {
		f.Add([]byte(s))
	}
	// Every separator Python's str.splitlines() honours, after a comment,
	// an option value, a hash and a continuation backslash.
	for _, sep := range []string{"\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\u0085", " ", " "} {
		f.Add([]byte("# c" + sep + "x==1" + sep + "--index-url https://x" + sep + "y==2 --hash=sha256:00" + sep + "z==\\" + sep + "3" + sep + "-r other.txt"))
	}
	addTestdataSeeds(f, "requirements.txt")
	addTestdataSeeds(f, "constraints.txt")
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		path := filepath.Join(root, "requirements.txt")
		if os.WriteFile(path, data, 0o600) != nil || os.WriteFile(filepath.Join(root, "other.txt"), data, 0o600) != nil {
			t.Skip()
		}
		parsed, err := parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: path, Source: "requirements.txt", Root: root}, newRequirementsCache())
		if err != nil {
			if parsed.refs != nil {
				t.Errorf("refs returned alongside an error")
			}
			return
		}
		checkPythonRefs(t, "requirements.txt", parsed.refs)
		if (parsed.syntax == nil) != (parsed.syntaxLines == 0) || (parsed.syntax != nil && parsed.syntax.Line < 1) {
			t.Errorf("skipped lines %d recorded inconsistently (%v)", parsed.syntaxLines, parsed.syntax)
		}
		rootReal, err := realDir(root)
		if err != nil {
			t.Skip()
		}
		for _, r := range parsed.refs {
			dir, err := realDir(filepath.Dir(r.Path))
			if err != nil || !withinDir(rootReal, dir) || strings.Contains(r.Path, "\x00") {
				t.Errorf("ref read from outside the project root: %s", r.Path)
			}
		}
	})
}

func checkPythonRefs(t *testing.T, source string, refs []PackageRef) {
	t.Helper()
	for _, r := range refs {
		if r.Name == "" {
			t.Errorf("%s: PackageRef with empty Name", source)
		}
		if r.Ecosystem != intel.EcosystemPyPI {
			t.Errorf("%s: ecosystem %q", source, r.Ecosystem)
		}
		if r.Unpinned == (r.Version != "") {
			t.Errorf("%s: %q must be either pinned with a version or unpinned without one", source, r.Name)
		}
	}
}

// FuzzParseDependencyManifests runs every dependency-manifest reader on
// the same input: they only decide whether a manifest declares
// dependencies and which exact pins it has, so one target covers them
// all within the nightly budget. Each must not panic, and every pin must
// carry an ecosystem, a name and a version.
func FuzzParseDependencyManifests(f *testing.F) {
	for _, s := range []string{
		`{"dependencies":{"left-pad":"1.3.0","a":"npm:b@2.0.0"},"workspaces":["p/*"]}`,
		`{"require":{"php":">=8","vendor/pkg":"v1.2.3"},"require-dev":{"x/y":"1.0.0@beta"}}`,
		"[project]\ndependencies = [\"flask==3.0.0\"]\n[tool.poetry.dependencies]\na = \"1.0\"\n[tool.uv.workspace]\nmembers = [\"x\"]\n",
		"[packages]\nflask = \"==3.0.0\"\nb = { version = \"===1.0\" }\n",
		"[workspace]\n[dependencies]\nserde = \"=1.0.0\"\n[dependencies.x]\nversion = \"=2.0.0\"\n",
		"setup(install_requires=['a'])\n",
		"[options]\ninstall_requires =\n    flask==3.0.0\n",
		"gem \"rails\", \"7.1.3\"\ngemspec\n",
		"dependencies:\n  - numpy\n  - pip:\n    - flask==3.0.0\n",
		"a: &a [*a]\n",
	} {
		f.Add([]byte(s))
	}
	readers := []struct {
		name  string
		parse func([]byte) (manifestInfo, error)
	}{
		{"package.json", parsePackageJSONManifest},
		{"composer.json", parseComposerManifest},
		{"pyproject.toml", parsePyprojectManifest},
		{"Pipfile", parsePipfileManifest},
		{"Cargo.toml", parseCargoManifest},
		{"setup.py", parseSetupPyManifest},
		{"setup.cfg", parseSetupCfgManifest},
		{"Gemfile", parseGemfileManifest},
		{"environment.yml", func(data []byte) (manifestInfo, error) {
			info, _, err := parseCondaEnvironment(data)
			return info, err
		}},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, r := range readers {
			info, err := r.parse(data)
			if err != nil {
				continue
			}
			if len(info.pins) > info.deps {
				t.Errorf("%s: %d pins for %d dependencies", r.name, len(info.pins), info.deps)
			}
			for _, p := range info.pins {
				if p.Ecosystem == "" || p.Name == "" || p.Version == "" {
					t.Errorf("%s: incomplete pin %+v", r.name, p)
				}
			}
		}
	})
}

func FuzzParseNuGet(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemNuGet, "packages.lock.json", ParseNuGet,
		`{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}`,
	)
}

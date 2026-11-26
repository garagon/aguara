package packagecheck

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func pinSummary(pins []PackageRef) []string {
	out := make([]string, 0, len(pins))
	for _, p := range pins {
		s := p.Name + " " + p.Version
		if p.ArbitraryEquality {
			s += " (===)"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestParsePackageJSONManifest(t *testing.T) {
	info, err := parsePackageJSONManifest([]byte(`{
		"name": "app",
		"dependencies": {
			"left-pad": "1.3.0",
			"exact-eq": "=2.0.0",
			"exact-v": "v3.0.0-rc.1",
			"with-build": "1.0.0+build.5",
			"ranged": "^4.18.0",
			"tagged": "latest",
			"star": "*",
			"aliased": "npm:@scope/real@5.0.0",
			"local": "file:../local",
			"linked": "link:../linked",
			"ws": "workspace:*",
			"gh": "owner/repo#v1",
			"git": "git+https://example.com/x.git",
			"url": "https://example.com/x.tgz",
			"catalog-dep": "catalog:"
		},
		"devDependencies": {"jest": "29.7.0"},
		"optionalDependencies": {"fsevents": "~2.3.0"},
		"peerDependencies": {"react": "18.2.0"},
		"workspaces": ["packages/*"]
	}`))
	require.NoError(t, err)
	require.True(t, info.workspace)
	require.Equal(t, 12, info.deps, "registry dependencies, peers included")
	require.Equal(t, []string{"@scope/real 5.0.0", "exact-eq 2.0.0", "exact-v 3.0.0-rc.1", "jest 29.7.0", "left-pad 1.3.0", "react 18.2.0", "with-build 1.0.0"}, pinSummary(info.pins))

	info, err = parsePackageJSONManifest([]byte(`{"name":"x","version":"1.0.0","peerDependencies":{"react":"18.2.0"},"dependencies":{}}`))
	require.NoError(t, err)
	require.True(t, info.declares(), "npm 7+ and pnpm install peer dependencies")

	info, err = parsePackageJSONManifest([]byte(`{"name":"x","version":"1.0.0","dependencies":{},"scripts":{"t":"x"}}`))
	require.NoError(t, err)
	require.False(t, info.declares(), "no installed dependency")

	// npm reads property names case-sensitively.
	info, err = parsePackageJSONManifest([]byte(`{"Dependencies":{"left-pad":"1.3.0"}}`))
	require.NoError(t, err)
	require.False(t, info.declares())

	info, err = parsePackageJSONManifest([]byte("\xef\xbb\xbf{\"dependencies\":{\"a\":\"1.0.0\"}}"))
	require.NoError(t, err, "npm accepts a UTF-8 byte-order mark")
	require.True(t, info.declares())

	_, err = parsePackageJSONManifest([]byte(`{"dependencies":`))
	require.Error(t, err)
}

func TestParseComposerManifest(t *testing.T) {
	info, err := parseComposerManifest([]byte(`{
		"require": {"php": ">=8.1", "ext-json": "*", "composer-plugin-api": "^2.0",
			"vendor/exact": "1.2.3", "vendor/v-exact": "v2.0.0", "vendor/eq": "==3.0.0",
			"vendor/flag": "4.0.0@beta", "vendor/range": "^5.0", "vendor/or": "1.0|2.0",
			"vendor/wild": "6.*", "vendor/branch": "dev-main"},
		"require-dev": {"vendor/dev": "7.1.0-RC1"}
	}`))
	require.NoError(t, err)
	require.Equal(t, 9, info.deps, "platform requirements are not packages")
	require.Equal(t, []string{"vendor/dev 7.1.0-RC1", "vendor/eq 3.0.0", "vendor/exact 1.2.3", "vendor/flag 4.0.0", "vendor/v-exact v2.0.0"}, pinSummary(info.pins))

	info, err = parseComposerManifest([]byte(`{"require": {"php": "^8.2", "ext-mbstring": "*"}}`))
	require.NoError(t, err)
	require.False(t, info.declares(), "platform requirements alone install nothing")
}

func TestParsePyprojectManifest(t *testing.T) {
	info, err := parsePyprojectManifest([]byte(`
[project]
name = "app"
dependencies = [
  "requests>=2",
  "flask==3.0.0",
  "local @ file:///tmp/local",
]

[project.optional-dependencies]
docs = ["sphinx===7.2.6"]

[dependency-groups]
test = ["pytest==8.2.0", {include-group = "docs"}]

[tool.uv]
dev-dependencies = ["ruff==0.4.4"]

[tool.pdm.dev-dependencies]
lint = ["black==24.4.2"]

[tool.poetry.dependencies]
python = "^3.11"
django = "5.0.1"
pinned-eq = "==1.1.0"
caret = "^2.0"
tabled = { version = "3.3.3", extras = ["x"] }
pathdep = { path = "../pathdep", develop = true }
gitdep = { git = "https://example.com/g.git" }
multi = [{ version = "1.0", python = "<3.9" }, { version = "2.0", python = ">=3.9" }]

[tool.poetry.dependencies.subtable]
version = "4.4.4"

[tool.poetry.group.dev.dependencies]
mypy = "1.10.0"

[tool.uv.workspace]
members = ["packages/*"]
`))
	require.NoError(t, err)
	require.True(t, info.workspace)
	require.Equal(t, []string{
		"black 24.4.2", "django 5.0.1", "flask 3.0.0", "mypy 1.10.0", "pinned-eq 1.1.0",
		"pytest 8.2.0", "ruff 0.4.4", "sphinx 7.2.6 (===)", "subtable 4.4.4", "tabled 3.3.3",
	}, pinSummary(info.pins))
	// requests, flask, sphinx, pytest, ruff, black; django, pinned-eq,
	// caret, tabled, multi, subtable, mypy.
	require.Equal(t, 13, info.deps)

	info, err = parsePyprojectManifest([]byte("[project]\nname = \"x\"\ndynamic = [\"dependencies\"]\n"))
	require.NoError(t, err)
	require.True(t, info.declares(), "dynamic dependencies are unknown")

	info, err = parsePyprojectManifest([]byte("[build-system]\nrequires = [\"setuptools>=61\"]\n\n[project]\nname = \"x\"\n"))
	require.NoError(t, err)
	require.False(t, info.declares(), "build requirements are not project dependencies")

	info, err = parsePyprojectManifest([]byte("[tool.poetry.dependencies]\npython = \"^3.11\"\n"))
	require.NoError(t, err)
	require.False(t, info.declares(), "the Python constraint is not a package")

	_, err = parsePyprojectManifest([]byte("[project\n"))
	require.Error(t, err)
}

func TestParsePipfileManifest(t *testing.T) {
	info, err := parsePipfileManifest([]byte(`
[[source]]
url = "https://pypi.org/simple"
name = "pypi"

[packages]
requests = "*"
flask = "==3.0.0"
arb = "===1.0"
tabled = { version = "==2.0.0", extras = ["x"] }
local = { path = ".", editable = true }
vcs = { git = "https://example.com/v.git" }

[dev-packages]
pytest = ">=7"

[docs]
sphinx = "==7.2.6"

[requires]
python_version = "3.11"
`))
	require.NoError(t, err)
	require.Equal(t, 6, info.deps)
	require.Equal(t, []string{"arb 1.0 (===)", "flask 3.0.0", "sphinx 7.2.6", "tabled 2.0.0"}, pinSummary(info.pins))

	info, err = parsePipfileManifest([]byte("[requires]\npython_version = \"3.11\"\n[packages]\n"))
	require.NoError(t, err)
	require.False(t, info.declares())
}

func TestParseCargoManifest(t *testing.T) {
	info, err := parseCargoManifest([]byte(`
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0"
exact = "=0.3.10"
spaced = "= 1.2.3"
partial = "=1.2"
tabled = { version = "=2.0.0", features = ["x"] }
renamed = { package = "real-crate", version = "=3.1.4" }
local = { path = "../local" }
gitdep = { git = "https://example.com/g.git" }
private = { version = "=9.9.9", registry = "internal" }
inherited = { workspace = true }

[dependencies.subtable]
version = "=4.0.0"

[dev-dependencies]
dev-exact = "=5.0.0"

[target.'cfg(unix)'.dependencies]
unix-dep = "=6.0.0"

[build-dependencies]
cc = "1"
`))
	require.NoError(t, err)
	require.False(t, info.workspace)
	require.Equal(t, []string{"dev-exact 5.0.0", "exact 0.3.10", "real-crate 3.1.4", "spaced 1.2.3", "subtable 4.0.0", "tabled 2.0.0", "unix-dep 6.0.0"}, pinSummary(info.pins))
	// serde exact spaced partial tabled renamed private inherited
	// subtable dev-exact unix-dep cc.
	require.Equal(t, 12, info.deps)

	info, err = parseCargoManifest([]byte("[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nserde = \"=1.0.197\"\n"))
	require.NoError(t, err)
	require.True(t, info.workspace)
	require.Equal(t, []string{"serde 1.0.197"}, pinSummary(info.pins))

	info, err = parseCargoManifest([]byte("[package]\nname = \"x\"\nworkspace = \"..\"\n\n[dependencies]\nlocal = { path = \"../l\" }\n"))
	require.NoError(t, err)
	require.False(t, info.workspace, "a member names its root; it is not one")
	require.False(t, info.declares(), "path dependencies resolve nothing from crates.io")
}

func TestParseSetupPyManifest(t *testing.T) {
	info, err := parseSetupPyManifest([]byte("from setuptools import setup\nsetup(name='x', install_requires=read_reqs())\n"))
	require.NoError(t, err)
	require.True(t, info.declares())

	info, err = parseSetupPyManifest([]byte("from setuptools import setup\n# install_requires lives in setup.cfg\nsetup()\n"))
	require.NoError(t, err)
	require.False(t, info.declares(), "a shim without the keyword declares nothing itself")

	info, err = parseSetupPyManifest([]byte("setup(extras_require={'x': ['y']})\n"))
	require.NoError(t, err)
	require.True(t, info.declares())
	require.Empty(t, info.pins, "an extra without a version pins nothing")
}

func TestParseSetupCfgManifest(t *testing.T) {
	info, err := parseSetupCfgManifest([]byte(`[metadata]
name = app

[options]
packages = find:
Install_Requires =
    requests>=2
    # a comment
    flask==3.0.0 # pinned
python_requires = >=3.9

[options.extras_require]
test =
    pytest==8.2.0
docs = sphinx

[tool:pytest]
addopts = -q
`))
	require.NoError(t, err)
	require.Equal(t, 4, info.deps)
	require.Equal(t, []string{"flask 3.0.0", "pytest 8.2.0"}, pinSummary(info.pins))

	info, err = parseSetupCfgManifest([]byte("[options]\ninstall_requires = file: requirements.txt\n"))
	require.NoError(t, err)
	require.True(t, info.declares())

	info, err = parseSetupCfgManifest([]byte("[metadata]\nname = app\n[flake8]\nmax-line-length = 100\n"))
	require.NoError(t, err)
	require.False(t, info.declares())
}

func TestParseGemfileManifest(t *testing.T) {
	info, err := parseGemfileManifest([]byte(`source "https://rubygems.org"
ruby "3.3.0"

gem "rails", "7.1.3"
gem 'exact', '= 2.0.0'
gem "ranged", "~> 1.0"
gem "two", "1.0", "< 2"
gem "plain"
gem "gitgem", git: "https://example.com/g.git"
gem "pathgem", :path => "../p"
gem "private", "3.0.0", source: "https://gems.example.com"
# gem "commented", "9.9.9"
group :test do
  gem "rspec", "3.13.0", require: false
end
`))
	require.NoError(t, err)
	require.Equal(t, 7, info.deps)
	require.Equal(t, []string{"exact 2.0.0", "private 3.0.0", "rails 7.1.3", "rspec 3.13.0"}, pinSummary(info.pins))

	info, err = parseGemfileManifest([]byte("source \"https://rubygems.org\"\ngemspec\n"))
	require.NoError(t, err)
	require.True(t, info.declares(), "gemspec pulls the gem's runtime dependencies")

	info, err = parseGemfileManifest([]byte("source \"https://rubygems.org\"\n"))
	require.NoError(t, err)
	require.False(t, info.declares())
}

func TestParseCondaEnvironment(t *testing.T) {
	info, ok, err := parseCondaEnvironment([]byte("name: x\nchannels:\n  - conda-forge\ndependencies:\n  - python=3.11\n  - numpy\n  - pip\n  - pip:\n      - flask==3.0.0\n      - -r requirements.txt\n      - requests\n"))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 6, info.deps)
	require.Equal(t, []string{"flask 3.0.0"}, pinSummary(info.pins))

	for _, doc := range []string{
		"dependencies:\n  - name: redis\n    version: 1.0.0\n", // a Helm-like list
		"dependencies: []\n",
		"dependencies:\n  role: common\n",
		"- just\n- a list\n",
		"steps:\n  - run: make\n",
		"not: [valid",
	} {
		_, ok, err := parseCondaEnvironment([]byte(doc))
		require.NoError(t, err, doc)
		require.False(t, ok, "%q is not a conda environment", doc)
	}
}

func TestParseRequirementsInManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.in")
	writeFile(t, path, "django>=5\nflask==3.0.0\n-c constraints.txt\n")
	info, err := parseRequirementsInManifest(path, filepath.Dir(path), nil)
	require.NoError(t, err)
	require.True(t, info.declares())
	require.Equal(t, []string{"flask 3.0.0"}, pinSummary(info.pins))
	require.True(t, isRequirementsInName("requirements.in", "x"))
	require.True(t, isRequirementsInName("dev-requirements.in", "x"))
	require.True(t, isRequirementsInName("base.in", filepath.Join("x", "requirements")))
	require.False(t, isRequirementsInName("MANIFEST.in", "x"))
	require.False(t, isRequirementsInName(".in", "requirements"))
}

// Spellings npm and the other tools read as declaring dependencies, which
// a narrower reading would miss.
func TestManifestReadersCoverLooserForms(t *testing.T) {
	// npm loose mode: leading zeros and a pre-release without a hyphen
	// are one exact version; peers are installed by npm 7+ and pnpm.
	info, err := parsePackageJSONManifest([]byte(`{"peerDependencies":{"event-stream":"03.3.6","x":"1.2.3beta","r":"^18"}}`))
	require.NoError(t, err)
	require.Equal(t, 3, info.deps)
	require.Equal(t, []string{"event-stream 3.3.6", "x 1.2.3-beta"}, pinSummary(info.pins))

	// Inline tables are read like the tables they stand for.
	info, err = parsePyprojectManifest([]byte(`dependency-groups = { dev = ["pytest==8.2.0"] }
[project]
name = "x"
optional-dependencies = { docs = ["sphinx==7.2.6"] }
[tool.poetry]
dependencies = { python = "^3.11", requests = "2.32.3", local = { path = "../l" } }
[tool.poetry.group.dev]
dependencies = { mypy = { version = "1.10.0" } }
[tool.hatch.envs.test]
dependencies = ["coverage==7.5.1"]
extra-dependencies = ["hypothesis"]
`))
	require.NoError(t, err)
	require.Equal(t, []string{"coverage 7.5.1", "mypy 1.10.0", "pytest 8.2.0", "requests 2.32.3", "sphinx 7.2.6"}, pinSummary(info.pins))
	require.Equal(t, 6, info.deps)
	require.Equal(t, []string{"requests"}, info.defaultNames)

	// Gemfile: eval_gemfile and computed gem names declare dependencies
	// the text cannot name; gems in git and path blocks are not registry
	// pins.
	for _, doc := range []string{"eval_gemfile \"Gemfile.common\"\n", "%w[rails rack].each { |name| gem name }\n", "gem(dep)\n"} {
		info, err := parseGemfileManifest([]byte(doc))
		require.NoError(t, err, doc)
		require.True(t, info.declares(), doc)
	}
	info, err = parseGemfileManifest([]byte(`source "https://rubygems.org"
git "https://example.com/mono.git" do
  gem "inner", "1.0.0"
end
path "vendor/engines" do
  gem "engine", "2.0.0"
end
group :test do
  if ENV["CI"]
    gem "rspec", "3.13.0"
  end
end
gem "rails", "7.1.3"
`))
	require.NoError(t, err)
	require.Equal(t, []string{"rails 7.1.3", "rspec 3.13.0"}, pinSummary(info.pins))
	require.Equal(t, 2, info.deps)

	// setup.py unpacking keyword arguments into setup() can pass
	// dependencies under names the text never spells.
	info, err = parseSetupPyManifest([]byte("import json\nfrom setuptools import setup\nsetup(**json.load(open('setup.json')))\n"))
	require.NoError(t, err)
	require.True(t, info.declares())
	info, err = parseSetupPyManifest([]byte("from setuptools import setup\nsetup(name='x', version='1')\n"))
	require.NoError(t, err)
	require.False(t, info.declares())
}

// manifestTree writes files and returns the coverage entries the rule
// lists for them, keyed by relative path, given the lockfile targets that
// discovery found.
func manifestEntries(t *testing.T, files map[string]string, ecosystems []string) map[string]UnsupportedEvidence {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	targets, err := Discover(root, ecosystems)
	require.NoError(t, err)
	found, err := DiscoverUnevaluated(root, ecosystems)
	require.NoError(t, err)
	run, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
	require.NoError(t, err)
	listed := ManifestsWithoutLockfile(root, found.Manifests, CoveringLockfiles(targets, found.Unsupported), run.Requirements)
	out := map[string]UnsupportedEvidence{}
	for _, u := range listed {
		rel, err := filepath.Rel(root, u.Path)
		require.NoError(t, err)
		out[filepath.ToSlash(rel)] = u
	}
	return out
}

func listedNames(m map[string]UnsupportedEvidence) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const (
	pkgWithDeps    = `{"dependencies":{"express":"^4.18.0"}}`
	pkgWithoutDeps = `{"name":"x","scripts":{"test":"node t.js"}}`
	pnpmLock       = "lockfileVersion: '9.0'\npackages: {}\n"
	npmLock        = `{"lockfileVersion":3,"packages":{"":{"name":"x"}}}`
	cargoLock      = "version = 4\n"
)

func TestManifestsWithoutLockfileRule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"manifest alone", map[string]string{"package.json": pkgWithDeps}, []string{"package.json"}},
		{"manifest without dependencies", map[string]string{"package.json": pkgWithoutDeps}, nil},
		{"lockfile beside it", map[string]string{"package.json": pkgWithDeps, "package-lock.json": npmLock}, nil},
		{"unsupported lockfile beside it is listed on its own", map[string]string{"package.json": pkgWithDeps, "npm-shrinkwrap.json": "{}"}, nil},
		{"lockfile of another ecosystem does not count", map[string]string{"package.json": pkgWithDeps, "Cargo.lock": cargoLock}, []string{"package.json"}},
		{"parent lockfile covers a nested project", map[string]string{
			"package.json": pkgWithDeps, "package-lock.json": npmLock,
			"test/fixtures/app/package.json": pkgWithDeps,
		}, nil},
		{"nested lockfile covers only its subtree", map[string]string{
			"package.json": pkgWithDeps, "web/package.json": pkgWithDeps, "web/package-lock.json": npmLock,
		}, []string{"package.json"}},
		{"npm workspace without lockfile lists the root", map[string]string{
			"package.json":            `{"workspaces":["packages/*"],"devDependencies":{"turbo":"^2"}}`,
			"packages/a/package.json": pkgWithDeps,
			"packages/b/package.json": pkgWithDeps,
		}, []string{"package.json"}},
		{"workspace root without dependencies is listed for its members", map[string]string{
			"package.json":            `{"private":true,"workspaces":{"packages":["apps/*"]}}`,
			"apps/web/package.json":   pkgWithDeps,
			"apps/empty/package.json": pkgWithoutDeps,
		}, []string{"package.json"}},
		{"workspace with no dependencies anywhere", map[string]string{
			"package.json":          `{"workspaces":["apps/*"]}`,
			"apps/web/package.json": pkgWithoutDeps,
		}, nil},
		{"pnpm workspace lockfile covers members", map[string]string{
			"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n", "pnpm-lock.yaml": pnpmLock,
			"package.json": pkgWithoutDeps, "packages/a/package.json": pkgWithDeps,
		}, nil},
		{"pnpm workspace without lockfile", map[string]string{
			"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n", "package.json": pkgWithoutDeps,
			"packages/a/package.json": pkgWithDeps,
		}, []string{"package.json"}},
		{"pnpm workspace without a root package.json", map[string]string{
			"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n", "packages/a/package.json": pkgWithDeps,
		}, []string{"pnpm-workspace.yaml"}},
		{"cargo workspace lockfile covers members", map[string]string{
			"Cargo.toml": "[workspace]\nmembers = [\"crates/*\"]\n", "Cargo.lock": cargoLock,
			"crates/a/Cargo.toml": "[package]\nname = \"a\"\n[dependencies]\nserde = \"1\"\n",
		}, nil},
		{"cargo workspace without lockfile", map[string]string{
			"Cargo.toml":          "[workspace]\nmembers = [\"crates/*\"]\n",
			"crates/a/Cargo.toml": "[package]\nname = \"a\"\n[dependencies]\nserde = \"1\"\n",
			"crates/b/Cargo.toml": "[package]\nname = \"b\"\n[dependencies]\nlocal = { path = \"../a\" }\n",
		}, []string{"Cargo.toml"}},
		{"uv workspace lockfile covers members", map[string]string{
			"pyproject.toml":            "[project]\nname = \"root\"\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n",
			"uv.lock":                   "version = 1\n",
			"packages/a/pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"httpx\"]\n",
		}, nil},
		{"python requirements file is the project's pinned list", map[string]string{
			"pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\"flask\"]\n", "requirements.txt": "flask==3.0.0\n",
		}, nil},
		{"constraints alone do not cover", map[string]string{
			"pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\"flask\"]\n", "constraints.txt": "flask==3.0.0\n",
		}, []string{"pyproject.toml"}},
		{"every python manifest of an uncovered project", map[string]string{
			"setup.py": "setup(install_requires=['a'])\n", "setup.cfg": "[options]\ninstall_requires = b\n",
			"Pipfile": "[packages]\nc = \"*\"\n", "requirements.in": "d\n",
		}, []string{"Pipfile", "requirements.in", "setup.cfg", "setup.py"}},
		{"pip-tools input beside its output", map[string]string{"requirements.in": "flask\n", "requirements.txt": "flask==3.0.0\n"}, nil},
		{"composer and bundler", map[string]string{
			"composer.json": `{"require":{"vendor/pkg":"^1"}}`, "Gemfile": "gem \"rails\"\n",
			"api/composer.json": `{"require":{"vendor/pkg":"^1"}}`, "api/composer.lock": `{"packages":[]}`,
			"tools/Gemfile": "gem \"rake\"\n", "tools/Gemfile.lock": "GEM\n  specs:\n",
		}, []string{"Gemfile", "composer.json"}},
		{"conda environment is always listed", map[string]string{
			"environment.yml": "dependencies:\n  - numpy\n", "requirements.txt": "flask==3.0.0\n",
		}, []string{"environment.yml"}},
		{"installed trees and vendored files are not the project's", map[string]string{
			"node_modules/dep/package.json": pkgWithDeps, "vendor/x/composer.json": `{"require":{"a/b":"1"}}`,
			".venv/lib/python3.12/site-packages/x/pyproject.toml": "[project]\ndependencies = [\"a\"]\n",
		}, nil},
		{"unreadable manifest is listed", map[string]string{"package.json": "{not json"}, []string{"package.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := manifestEntries(t, tc.files, nil)
			if tc.want == nil {
				tc.want = []string{}
			}
			require.Equal(t, tc.want, listedNames(got))
		})
	}
}

// A requirements file stands for a Python manifest only when it records
// what installing the manifest resolves: no local project install, and an
// exact pin for every dependency the manifest pulls on a plain install.
func TestRequirementsFileCoversPythonManifestOnlyWhenItPinsIt(t *testing.T) {
	const project = "[project]\nname = \"app\"\ndependencies = [\"requests>=2\", \"Flask_Login\"]\n" +
		"[project.optional-dependencies]\ndocs = [\"sphinx\"]\n[dependency-groups]\ndev = [\"pytest\"]\n"
	for _, tc := range []struct {
		name     string
		files    map[string]string
		covered  bool
		detail   string
		notPinne []string
	}{
		{"editable install of the project", map[string]string{"pyproject.toml": project, "requirements.txt": "-e .\n"},
			false, "requirements.txt installs it as a local project and does not pin flask-login, requests", nil},
		{"bare dot", map[string]string{"pyproject.toml": project, "requirements.txt": ".\n"},
			false, "requirements.txt installs it as a local project", nil},
		{"editable install beside full pins", map[string]string{"pyproject.toml": project, "requirements.txt": "-e .\nrequests==2.32.3\nflask-login==0.6.3\n"},
			false, "installs a local project", nil},
		{"file URL", map[string]string{"pyproject.toml": project, "requirements.txt": "app @ file:///src/app\nrequests==2.32.3\nflask-login==0.6.3\n"},
			false, "installs a local project", nil},
		{"unrelated pinned file", map[string]string{"pyproject.toml": project, "requirements.txt": "black==24.4.2\n"},
			false, "requirements.txt does not pin flask-login, requests with == or ===", []string{"flask-login", "requests"}},
		{"partly pinned", map[string]string{"pyproject.toml": project, "requirements.txt": "requests==2.32.3\nflask-login>=0.6\n"},
			false, "does not pin flask-login", []string{"flask-login"}},
		{"compiled file pins the default set", map[string]string{"pyproject.toml": project,
			"requirements.txt": "certifi==2024.2.2\nflask-login==0.6.3 \\\n    --hash=sha256:00\nrequests==2.32.3\nurllib3==2.2.1\n"}, true, "", nil},
		{"pins through an include and a constraint", map[string]string{"pyproject.toml": project,
			"requirements.txt": "-r requirements/base.txt\n-c constraints.txt\nflask-login\n", "requirements/base.txt": "requests===2.32.3\n",
			"constraints.txt": "flask-login==0.6.3\n"}, true, "", nil},
		{"requirements in a parent directory", map[string]string{"app/pyproject.toml": project, "requirements.txt": "requests==2.32.3\nflask-login==0.6.3\n"}, true, "", nil},
		{"only groups declared, groups pinned", map[string]string{"pyproject.toml": "[project]\nname = \"x\"\n[dependency-groups]\ndev = [\"pytest\"]\n",
			"requirements.txt": "pytest==8.2.0\n"}, true, "", nil},
		{"only groups declared, not pinned", map[string]string{"pyproject.toml": "[project]\nname = \"x\"\n[dependency-groups]\ndev = [\"pytest\"]\n",
			"requirements.txt": "black==24.4.2\n"}, false, "does not pin pytest", []string{"pytest"}},
		{"setup.py reading a fully pinned file", map[string]string{"setup.py": "setup(install_requires=open('requirements.txt').read())\n", "requirements.txt": "requests==2.32.3\n"}, true, "", nil},
		{"setup.py reading another file", map[string]string{"setup.py": "setup(install_requires=open('r').read())\n", "requirements.txt": "requests==2.32.3\n"},
			false, "does not name requirements.txt as their source", nil},
		{"setup.py with an unpinned entry", map[string]string{"setup.py": "setup(install_requires=open('requirements.txt').read())\n", "requirements.txt": "requests==2.32.3\nflask\n"},
			false, "requirements.txt has entries without one exact version", nil},
		{"setup.py with no pin", map[string]string{"setup.py": "setup(install_requires=open('requirements.txt').read())\n", "requirements.txt": "-r other.txt\n", "other.txt": "# empty\n"},
			false, "requirements.txt pins no exact version", nil},
		{"Pipfile packages pinned", map[string]string{"Pipfile": "[packages]\nrequests = \"*\"\n[dev-packages]\npytest = \"*\"\n", "requirements.txt": "requests==2.32.3\n"}, true, "", nil},
		{"constraints alone", map[string]string{"pyproject.toml": project, "constraints.txt": "requests==2.32.3\nflask-login==0.6.3\n"}, false, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := manifestEntries(t, tc.files, nil)
			var entry UnsupportedEvidence
			listed := false
			for _, u := range got {
				if u.IsManifest() {
					entry, listed = u, true
				}
			}
			require.Equal(t, !tc.covered, listed, "%+v", got)
			if !listed {
				return
			}
			require.Contains(t, entry.Detail, tc.detail)
			if tc.notPinne != nil {
				require.Equal(t, tc.notPinne, entry.NotPinned)
			}
			if tc.detail != "" {
				require.NotEmpty(t, entry.RequirementsFile)
			}
		})
	}
}

func TestManifestsWithoutLockfileEntryFields(t *testing.T) {
	got := manifestEntries(t, map[string]string{
		"package.json":            `{"workspaces":["packages/*"],"dependencies":{"left-pad":"1.3.0"}}`,
		"packages/a/package.json": `{"dependencies":{"event-stream":"3.3.6"}}`,
		"packages/b/package.json": pkgWithoutDeps,
		"environment.yml":         "dependencies:\n  - pip:\n    - flask==3.0.0\n",
	}, nil)
	root := got["package.json"]
	require.Equal(t, ReasonManifestWithoutLockfile, root.Reason)
	require.Equal(t, "npm", root.Ecosystem)
	require.Equal(t, "package.json", root.Kind)
	require.Equal(t, 2, root.NestedManifests)
	require.Equal(t, []string{"event-stream 3.3.6", "left-pad 1.3.0"}, pinSummary(root.pins), "members' pins are checked with the root")
	for _, p := range root.pins {
		require.Equal(t, "package.json", p.Source)
		if p.Name == "event-stream" {
			require.True(t, strings.HasSuffix(p.Path, filepath.Join("packages", "a", "package.json")), p.Path)
		}
	}
	conda := got["environment.yml"]
	require.Equal(t, ReasonNoPackageIntelligence, conda.Reason)
	require.Equal(t, "conda", conda.Ecosystem)
	require.True(t, conda.NoIntel())
	require.Equal(t, []string{"flask 3.0.0"}, pinSummary(conda.pins))
}

func TestManifestDiscoveryFollowsEcosystemFilter(t *testing.T) {
	files := map[string]string{
		"package.json": pkgWithDeps, "pyproject.toml": "[project]\ndependencies = [\"a\"]\n",
		"environment.yml": "dependencies:\n  - numpy\n", "Cargo.toml": "[dependencies]\nserde = \"1\"\n",
	}
	require.Equal(t, []string{"package.json"}, listedNames(manifestEntries(t, files, []string{intel.EcosystemNPM})))
	require.Equal(t, []string{"environment.yml", "pyproject.toml"}, listedNames(manifestEntries(t, files, []string{intel.EcosystemPyPI})),
		"a conda environment's pip list is PyPI")
	require.Equal(t, []string{}, listedNames(manifestEntries(t, files, []string{intel.EcosystemGo})))
}

func TestManifestReadsAreBounded(t *testing.T) {
	root := t.TempDir()
	big := `{"dependencies":{"a":"1.0.0"},"pad":"` + strings.Repeat("x", int(maxDependencyManifestBytes)) + `"}`
	writeFile(t, filepath.Join(root, "package.json"), big)
	found, err := DiscoverUnevaluated(root, nil)
	require.NoError(t, err)
	require.Len(t, found.Manifests, 1)
	require.True(t, found.Manifests[0].Unreadable, "an oversized manifest is not read")
	require.True(t, found.Manifests[0].Declares, "and its dependencies are unknown")

	link := t.TempDir()
	writeFile(t, filepath.Join(link, "real.json"), pkgWithDeps)
	if err := os.Symlink(filepath.Join(link, "real.json"), filepath.Join(link, "package.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	found, err = DiscoverUnevaluated(link, nil)
	require.NoError(t, err)
	require.Len(t, found.Manifests, 1)
	require.True(t, found.Manifests[0].Unreadable, "a symlinked manifest is not followed")
}

// One discovery reads at most maxDiscoveryReadBytes from manifests and
// pip-name files together; past it a manifest is reported unread, with
// its dependencies unknown.
func TestDiscoveryReadBudget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	writeFile(t, path, pkgWithDeps)

	budget := &discoveryBudget{bytes: maxDiscoveryReadBytes - int64(len(pkgWithDeps)) + 1}
	m, ok := readManifestAt(path, root, nil, budget)
	require.True(t, ok)
	require.True(t, m.Unreadable, "the read would pass the budget")
	require.True(t, m.Declares)

	budget = &discoveryBudget{bytes: maxDiscoveryReadBytes - int64(len(pkgWithDeps))}
	m, ok = readManifestAt(path, root, nil, budget)
	require.True(t, ok)
	require.False(t, m.Unreadable, "the read fits the budget")
	require.Equal(t, maxDiscoveryReadBytes, budget.bytes)
	require.Equal(t, 1, budget.files)

	budget = &discoveryBudget{files: maxManifestsParsed}
	m, _ = readManifestAt(path, root, nil, budget)
	require.True(t, m.Unreadable, "past the file count")

	// The includes a requirements.in reads are charged too.
	in := filepath.Join(root, "requirements.in")
	const input, base = "-r base.in\n", "requests\nflask\n"
	writeFile(t, in, input)
	writeFile(t, filepath.Join(root, "base.in"), base)
	budget = &discoveryBudget{bytes: maxDiscoveryReadBytes - int64(len(input)+len(base)) + 1}
	m, ok = readManifestAt(in, root, nil, budget)
	require.True(t, ok)
	require.True(t, m.Unreadable, "the include would pass the budget")
	require.True(t, m.Declares)

	budget = &discoveryBudget{bytes: maxDiscoveryReadBytes - int64(len(input)+len(base))}
	m, _ = readManifestAt(in, root, nil, budget)
	require.False(t, m.Unreadable)
	require.Equal(t, []string{"requests", "flask"}, m.DefaultDependencies)
	require.Equal(t, maxDiscoveryReadBytes, budget.bytes)
	require.Equal(t, 2, budget.files)
}

// The exact pins of a listed manifest are matched against intelligence;
// everything else in the file stays unevaluated.
func TestMatchPinsReportsCompromisedManifestPins(t *testing.T) {
	m := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{
		{ID: "MAL-NPM", Ecosystem: intel.EcosystemNPM, Name: "evil", Kind: intel.KindMalicious, Versions: []string{"1.0.0"}},
		{ID: "MAL-PY", Ecosystem: intel.EcosystemPyPI, Name: "bad-py", Kind: intel.KindMalicious, Versions: []string{"1.0"}},
	}})
	entries := []UnsupportedEvidence{
		{Path: "package.json", Reason: ReasonManifestWithoutLockfile, pins: []PackageRef{
			{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0", Path: "package.json", Source: "package.json"},
			{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.1", Path: "package.json", Source: "package.json"},
		}},
		{Path: "pyproject.toml", Reason: ReasonManifestWithoutLockfile, pins: []PackageRef{
			{Ecosystem: intel.EcosystemPyPI, Name: "Bad_Py", Version: "1.0.0", Path: "pyproject.toml", Line: 3},
			{Ecosystem: intel.EcosystemPyPI, Name: "bad-py", Version: "1.0.0", Path: "pyproject.toml", Line: 4, ArbitraryEquality: true},
		}},
	}
	hits := MatchPins(m, entries)
	require.Len(t, hits, 2, "== pins use PEP 440 equality; === pins compare as pip does")
	require.Equal(t, "evil", hits[0].Ref.Name)
	require.Equal(t, []string{"MAL-NPM"}, hits[0].AdvisoryIDs)
	require.Equal(t, 3, hits[1].Ref.Line)
	require.Equal(t, 2, entries[0].ExactPinsChecked)
	require.Equal(t, 2, entries[1].ExactPinsChecked)
}

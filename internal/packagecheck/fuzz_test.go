package packagecheck

import (
	"os"
	"path/filepath"
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

func FuzzParseGo(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemGo, "go.sum", ParseGo,
		"github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.2.3/go.mod h1:def=\n",
	)
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

func FuzzParseNuGet(f *testing.F) {
	fuzzLockfile(f, intel.EcosystemNuGet, "packages.lock.json", ParseNuGet,
		`{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}`,
	)
}

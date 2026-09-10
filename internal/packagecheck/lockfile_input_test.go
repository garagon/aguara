package packagecheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestLockfileInputRejectsLinkedFiles(t *testing.T) {
	for _, tc := range []struct{ ecosystem, source, content string }{
		{intel.EcosystemGo, "go.sum", "example.com/pkg v1.0.0 h1:example\n"},
		{intel.EcosystemGo, "go.mod", "module example.com/root\nrequire example.com/pkg v1.0.0\n"},
		{intel.EcosystemCargo, "Cargo.lock", "[[package]]\nname = 'example'\nversion = '1.0.0'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\n"},
		{intel.EcosystemPackagist, "composer.lock", `{"packages":[{"name":"vendor/example","version":"1.0.0"}]}`},
		{intel.EcosystemRubyGems, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    example (1.0.0)\n"},
		{intel.EcosystemMaven, "pom.xml", "<project><dependencies><dependency><groupId>example</groupId><artifactId>pkg</artifactId><version>1.0.0</version></dependency></dependencies></project>"},
		{intel.EcosystemMaven, "gradle.lockfile", "example:pkg:1.0.0=runtime\n"},
		{intel.EcosystemNPM, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  example@1.0.0: {}\n"},
		{intel.EcosystemNPM, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}`},
		{intel.EcosystemNPM, "yarn.lock", "example@^1.0.0:\n  version \"1.0.0\"\n"},
		{intel.EcosystemNPM, "bun.lock", `{"packages":{"example":["example@1.0.0","",{},"sha512-example"]}}`},
	} {
		t.Run(tc.source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.source)
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))
			target := Target{Ecosystem: tc.ecosystem, Source: tc.source, Path: path}
			refs, err := parseTarget(target)
			require.NoError(t, err)
			require.Len(t, refs, 1, "regular-file control")
			for _, dangling := range []bool{false, true} {
				dir := t.TempDir()
				link := filepath.Join(dir, tc.source)
				dest := path
				if dangling {
					dest += ".missing"
				}
				if err := os.Symlink(dest, link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				target.Path = link
				refs, err := parseTarget(target)
				require.Error(t, err)
				require.Empty(t, refs)
				targets, err := Discover(dir, []string{tc.ecosystem})
				require.NoError(t, err)
				require.Len(t, targets, 1, "unsafe candidates must not disappear")
				result, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
				require.Error(t, err)
				require.Nil(t, result)
			}
		})
	}
}

func TestLockfileInputInvalidPreferredDoesNotFallBack(t *testing.T) {
	for _, tc := range []struct{ ecosystem, preferred, fallback string }{
		{intel.EcosystemGo, "go.sum", "go.mod"},
		{intel.EcosystemNPM, "bun.lock", "bun.lockb"},
	} {
		t.Run(tc.preferred, func(t *testing.T) {
			dir := t.TempDir()
			preferred := filepath.Join(dir, tc.preferred)
			if err := os.Symlink(filepath.Join(dir, "missing"), preferred); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, tc.fallback), []byte("module example.com/root\n"), 0o600))
			targets, err := Discover(dir, []string{tc.ecosystem})
			require.NoError(t, err)
			require.Len(t, targets, 1)
			require.Equal(t, preferred, targets[0].Path)
			result, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}

func TestLockfileInputGradleLinkedPerConfiguration(t *testing.T) {
	dir := t.TempDir()
	locks := filepath.Join(dir, "gradle", "dependency-locks")
	require.NoError(t, os.MkdirAll(locks, 0o700))
	good := filepath.Join(locks, "a.lockfile")
	require.NoError(t, os.WriteFile(good, []byte("example:pkg:1.0.0=runtime\n"), 0o600))
	if err := os.Symlink(good, filepath.Join(locks, "z.lockfile")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	targets, err := Discover(dir, []string{intel.EcosystemMaven})
	require.NoError(t, err)
	require.Len(t, targets, 2)
	result, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
	require.Error(t, err)
	require.Nil(t, result, "do not return the preceding valid target as a complete check")
}

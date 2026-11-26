package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

const hostedPrefix = "https://files.pythonhosted.org/packages/ab/cd/0123456789abcdef/"

func TestPythonHostedIdentity(t *testing.T) {
	for _, tc := range []struct {
		url, name, version string
	}{
		{hostedPrefix + "requests-2.31.0-py3-none-any.whl", "requests", "2.31.0"},
		{hostedPrefix + "foo_bar-1.0-1-cp312-cp312-manylinux_2_17_x86_64.whl", "foo_bar", "1.0"},
		{hostedPrefix + "requests-2.31.0-py3-none-any.whl#sha256=00ff", "requests", "2.31.0"},
		{hostedPrefix + "evil_pkg-0.0.1.tar.gz", "evil_pkg", "0.0.1"},
		{hostedPrefix + "evil-pkg-0.0.1.tar.gz", "evil-pkg", "0.0.1"},
		{hostedPrefix + "evil_pkg-0.0.1.zip", "evil_pkg", "0.0.1"},
		{"https://FILES.pythonhosted.org/packages/x/requests-2.31.0.tar.gz", "requests", "2.31.0"},
		{hostedPrefix + "pkg-1.0%2Blocal-py3-none-any.whl", "pkg", "1.0+local"},
	} {
		name, version, ok := pythonHostedIdentity(tc.url)
		require.True(t, ok, tc.url)
		require.Equal(t, tc.name, name, tc.url)
		require.Equal(t, tc.version, version, tc.url)
	}
	for _, url := range []string{
		"https://example.com/packages/requests-2.31.0-py3-none-any.whl",
		"http://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
		"https://user@files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
		"https://files.pythonhosted.org.evil.example/requests-2.31.0-py3-none-any.whl",
		"https://files.pythonhosted.org:8443/requests-2.31.0-py3-none-any.whl",
		hostedPrefix + "requests-2.31.0-py3-none.whl",               // too few tags
		hostedPrefix + "requests-2.31.0-x1-py3-none-any.whl",        // build tag must start with a digit
		hostedPrefix + "requests-2.31.0-1-2-py3-none-any.whl",       // too many parts
		hostedPrefix + "requests-not.a.version-py3-none-any.whl",    // invalid version
		hostedPrefix + "requests.tar.gz",                            // no version
		hostedPrefix + "requests-2.31.0.tar.bz2",                    // not a source distribution format
		hostedPrefix + "requests-2.31.0.exe",                        // not a distribution
		hostedPrefix,                                                // no file
		"git+https://files.pythonhosted.org/requests-2.31.0.tar.gz", // not https
	} {
		_, _, ok := pythonHostedIdentity(url)
		require.False(t, ok, url)
	}
}

// A requirement or lock entry that points at a file uploaded to PyPI is
// that release; other URLs keep having no PyPI identity.
func TestPythonHostedReferencesAreMatched(t *testing.T) {
	matcher := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{{
		ID: "MAL-HOSTED", Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg", Kind: intel.KindMalicious, Versions: []string{"0.0.1"},
	}}})
	wheel := hostedPrefix + "evil_pkg-0.0.1-py3-none-any.whl"
	for _, tc := range []struct {
		source, content string
		hit             bool
	}{
		{"requirements.txt", wheel + "\n", true},
		{"requirements.txt", "evil-pkg @ " + wheel + " ; python_version >= '3.8'\n", true},
		{"requirements.txt", "evil-pkg @ " + wheel + " --hash=sha256:00\n", true},
		{"requirements.txt", "other-pkg @ " + wheel + "\n", false}, // pip rejects the name mismatch
		{"requirements.txt", "evil-pkg @ https://example.com/evil_pkg-0.0.1-py3-none-any.whl\n", false},
		{"requirements.txt", hostedPrefix + "evil_pkg-0.0.2-py3-none-any.whl\n", false},
		{"uv.lock", "version = 1\n\n[[package]]\nname = \"evil-pkg\"\nversion = \"0.0.1\"\nsource = { url = \"" + wheel + "\" }\n", true},
		{"uv.lock", "version = 1\n\n[[package]]\nname = \"evil-pkg\"\nversion = \"0.0.1\"\nsource = { url = \"https://example.com/evil_pkg-0.0.1-py3-none-any.whl\" }\n", false},
		{"poetry.lock", "[[package]]\nname = \"evil-pkg\"\nversion = \"0.0.1\"\n\n[package.source]\ntype = \"url\"\nurl = \"" + wheel + "\"\n\n[metadata]\nlock-version = \"2.0\"\n", true},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, tc.source)
		writeFile(t, path, tc.content)
		res, err := (&Runner{Matcher: matcher}).Run([]Target{{Ecosystem: intel.EcosystemPyPI, Path: path, Source: tc.source, Root: dir}})
		require.NoError(t, err, tc.content)
		require.Equal(t, tc.hit, len(res.Hits) == 1, "%s: %q", tc.source, tc.content)
		if tc.hit {
			require.Equal(t, "0.0.1", res.Hits[0].Ref.Version)
		}
	}
}

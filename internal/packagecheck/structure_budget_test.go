package packagecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

const cratesSource = `source = "registry+https://github.com/rust-lang/crates.io-index"` + "\n"

func parseFile(t *testing.T, ecosystem, source, content string) ([]PackageRef, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), source)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return parseTarget(Target{Ecosystem: ecosystem, Path: path, Source: source})
}

// A Cargo.lock made of one huge array drove the TOML parser's node arena
// to gigabytes; it is rejected by the same budget as the Python lockfiles.
func TestCargoLockRejectsHugeExpression(t *testing.T) {
	lock := "version = 3\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n" + cratesSource +
		"dependencies = [" + strings.Repeat("1,", maxTOMLExpressionNodes+1) + "1]\n"
	_, err := parseCargoBytes([]byte(lock), "Cargo.lock")
	require.ErrorContains(t, err, "node limit")
}

// lowerEntryLimit sets maxLockfileEntries for one test.
func lowerEntryLimit(t *testing.T, n int) {
	t.Helper()
	old := maxLockfileEntries
	maxLockfileEntries = n
	t.Cleanup(func() { maxLockfileEntries = old })
}

func TestCargoLockEntryLimit(t *testing.T) {
	lowerEntryLimit(t, 50)
	cargo := func(n int) []byte {
		var b strings.Builder
		b.WriteString("version = 3\n")
		for i := range n {
			fmt.Fprintf(&b, "[[package]]\nname = \"c%d\"\nversion = \"1.0.0\"\n%s", i, cratesSource)
		}
		return []byte(b.String())
	}
	refs, err := parseCargoBytes(cargo(50), "Cargo.lock")
	require.NoError(t, err)
	require.Len(t, refs, 50)
	_, err = parseCargoBytes(cargo(51), "Cargo.lock")
	require.ErrorContains(t, err, "more than 50 package entries")
}

// wideJSON nests arrays of members values each, so the document has many
// values without any one container passing the member limit.
func wideJSON(arrays, members int) string {
	one := "[" + strings.Repeat("0,", members-1) + "0]"
	return "[" + strings.TrimSuffix(strings.Repeat(one+",", arrays), ",") + "]"
}

func TestJSONNodeBudget(t *testing.T) {
	// Structure inside strings, including escaped quotes, does not count.
	require.NoError(t, checkJSONNodeBudget([]byte(`{"a":"[,,,{\",,,"}`), "x"))
	members := maxContainerMembers - 1
	over := wideJSON(maxStructuredNodes/members+1, members)
	require.ErrorContains(t, checkJSONNodeBudget([]byte(over), "x"), "node limit")
	under := wideJSON(maxStructuredNodes/members-1, members)
	require.NoError(t, checkJSONNodeBudget([]byte(under), "x"))
}

// One container wider than the member limit is rejected before decoding,
// so a lockfile with more entries than the entry limit is never
// materialised: a package-lock.json of 650,000 entries used to peak near
// 1 GiB before the entry limit applied.
func TestJSONMemberLimit(t *testing.T) {
	keys := func(n int) string {
		var b strings.Builder
		b.WriteString(`{"lockfileVersion":3,"packages":{`)
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"node_modules/p%d":{"version":"1.0.0"}`, i)
		}
		b.WriteString("}}")
		return b.String()
	}
	require.ErrorContains(t, checkJSONNodeBudget([]byte(keys(maxContainerMembers+1)), "x"), "more than 100000 members")
	require.NoError(t, checkJSONNodeBudget([]byte(keys(maxContainerMembers)), "x"))
	// Commas inside strings are not members.
	require.NoError(t, checkJSONNodeBudget([]byte(`["`+strings.Repeat(",", maxContainerMembers+1)+`"]`), "x"))
}

// A lockfileVersion 1 tree repeats packages at many paths, so its nested
// entries are counted while it is decoded, up to four times the entry
// limit, instead of after the whole tree is materialised.
func TestPackageLockV1TreeStopsWhileDecoding(t *testing.T) {
	lowerEntryLimit(t, 10)
	tree := func(parents, children int) string {
		var b strings.Builder
		b.WriteString(`{"lockfileVersion":1,"dependencies":{`)
		for p := range parents {
			if p > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"p%d":{"version":"1.0.0","dependencies":{`, p)
			for c := range children {
				if c > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`"shared":{"version":"1.0.0"}`)
				_ = c
			}
			b.WriteString("}}")
		}
		b.WriteString("}}")
		return b.String()
	}
	// 3 parents with one repeated child each: 6 nested entries, 4 refs.
	_, err := parseFile(t, intel.EcosystemNPM, "package-lock.json", tree(3, 1))
	require.NoError(t, err)
	// 41 parents with one child each: 82 nested entries, over 4 x 10.
	_, err = parseFile(t, intel.EcosystemNPM, "package-lock.json", tree(41, 1))
	require.ErrorContains(t, err, "decoding budget")
}

func TestJSONLockfilesRejectOverBudgetDocuments(t *testing.T) {
	array := wideJSON(maxStructuredNodes/(maxContainerMembers-1)+1, maxContainerMembers-1)
	for _, c := range []struct{ ecosystem, source, content string }{
		{intel.EcosystemNPM, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"x":` + array + `}}}`},
		{intel.EcosystemNPM, "bun.lock", `{"lockfileVersion":1,"packages":{"a":` + array + `}}`},
		{intel.EcosystemPackagist, "composer.lock", `{"packages":` + array + `}`},
		{intel.EcosystemPyPI, "Pipfile.lock", `{"_meta":{"pipfile-spec":6},"default":{"a":{"x":` + array + `}}}`},
		{intel.EcosystemNuGet, "packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"a":{"x":` + array + `}}}}`},
	} {
		_, err := parseFile(t, c.ecosystem, c.source, c.content)
		require.ErrorContains(t, err, "node limit", c.source)
	}
}

func TestYAMLNodeBudget(t *testing.T) {
	// Quoted scalars and comments do not count.
	quoted := "a: '" + strings.Repeat(",", maxStructuredNodes) + "'\nb: \"" + strings.Repeat("-", maxStructuredNodes) + "\"\n# " + strings.Repeat(":", maxStructuredNodes) + "\n"
	require.NoError(t, checkYAMLNodeBudget([]byte(quoted), "x"))
	flowSeqs := func(seqs, members int, open, close string) string {
		var b strings.Builder
		for i := range seqs {
			fmt.Fprintf(&b, "k%d: %s%s%s\n", i, open, strings.TrimSuffix(strings.Repeat("k,", members), ","), close)
		}
		return b.String()
	}
	members := maxContainerMembers - 1
	require.ErrorContains(t, checkYAMLNodeBudget([]byte(flowSeqs(maxStructuredNodes/members+1, members, "[", "]")), "x"), "node limit")
	require.NoError(t, checkYAMLNodeBudget([]byte(flowSeqs(maxStructuredNodes/members/2-1, members, "[", "]")), "x"))
	// An entry of a flow mapping counts twice: a key without ':' is a key
	// and an implicit null value.
	require.ErrorContains(t, checkYAMLNodeBudget([]byte(flowSeqs(maxStructuredNodes/members/2+1, members, "{", "}")), "x"), "node limit")
}

// The member limit applies to flow collections by their ','s and to block
// collections by the lines that start at their indentation.
func TestYAMLMemberLimit(t *testing.T) {
	block := func(n int, indent string) string {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\npackages:\n")
		for i := range n {
			fmt.Fprintf(&b, "%sp%d@1.0.0:\n%s  resolution: {integrity: sha512-x}\n", indent, i, indent)
		}
		return b.String()
	}
	require.ErrorContains(t, checkYAMLNodeBudget([]byte(block(maxContainerMembers+1, "  ")), "x"), "more than 100000 members")
	require.NoError(t, checkYAMLNodeBudget([]byte(block(maxContainerMembers-10, "  ")), "x"))
	seq := "a:\n" + strings.Repeat("  - x\n", maxContainerMembers+1)
	require.ErrorContains(t, checkYAMLNodeBudget([]byte(seq), "x"), "more than 100000 members")
	flow := "a: [" + strings.Repeat("x,", maxContainerMembers) + "x]\n"
	require.ErrorContains(t, checkYAMLNodeBudget([]byte(flow), "x"), "more than 100000 members")
	// Blank lines, comments and the lines of a quoted scalar are not entries.
	quiet := "a:\n" + strings.Repeat("\n  # note\n", maxContainerMembers+1) + "  b: \"" + strings.Repeat("x\n", maxContainerMembers+1) + "\"\n"
	require.NoError(t, checkYAMLNodeBudget([]byte(quiet), "x"))
}

func pnpmKeysOf(t *testing.T, lock string) ([]string, error) {
	t.Helper()
	refs, err := parseFile(t, intel.EcosystemNPM, "pnpm-lock.yaml", lock)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range refs {
		out = append(out, r.Name+"@"+r.Version)
	}
	sort.Strings(out)
	return out, nil
}

// The pnpm parser reads keys from the node tree instead of decoding the
// document into Go maps. It must keep the decoder's view of the keys.
func TestPNPMLockKeysMatchDecoderSemantics(t *testing.T) {
	keys, err := pnpmKeysOf(t, `lockfileVersion: '9.0'
base: &base
  event-stream@3.3.6: {}
packages:
  <<: *base
  ? !!binary bG9kYXNoQDQuMTcuMjE=
  : {}
  'left-pad@1.3.0':
    resolution: {integrity: sha512-x}
`)
	require.NoError(t, err)
	require.Equal(t, []string{"event-stream@3.3.6", "left-pad@1.3.0", "lodash@4.17.21"}, keys,
		"merged, !!binary and quoted keys decode as before")

	aliased, err := pnpmKeysOf(t, "pk: &pk\n  a@1.0.0: {}\npackages: *pk\n")
	require.NoError(t, err)
	require.Equal(t, []string{"a@1.0.0"}, aliased)

	for _, lock := range []string{"", "~\n", "lockfileVersion: '9.0'\n", "packages:\n", "packages: ~\n"} {
		keys, err := pnpmKeysOf(t, lock)
		require.NoError(t, err, "%q", lock)
		require.Empty(t, keys)
	}
}

func TestPNPMLockRejectsMalformedDocuments(t *testing.T) {
	for name, lock := range map[string]string{
		"duplicate top-level key":   "packages: {}\npackages: {}\n",
		"duplicate package key":     "packages:\n  a@1.0.0: {}\n  a@1.0.0: {}\n",
		"duplicate nested key":      "packages:\n  a@1.0.0:\n    resolution: {}\n    resolution: {}\n",
		"sequence document":         "- a\n",
		"packages is a sequence":    "packages: [a]\n",
		"merge of a scalar":         "packages:\n  <<: x\n",
		"syntax error":              "packages: [\n",
		"collection as package key": "packages:\n  ? [a]\n  : {}\n",
	} {
		_, err := pnpmKeysOf(t, lock)
		require.Error(t, err, name)
	}
}

// Decoding into Go maps compared every key of the packages mapping with
// every other key, so 99,000 keys took tens of seconds (200,000 did not
// finish in a minute); the node walk is linear.
func TestPNPMLockManyKeysIsLinear(t *testing.T) {
	lowerEntryLimit(t, 1_000_000)
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\npackages:\n")
	const n = 99_000
	for i := range n {
		fmt.Fprintf(&b, "  p%d@1.0.0: {}\n", i)
	}
	path := filepath.Join(t.TempDir(), "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	done := make(chan error, 1)
	var refs []PackageRef
	go func() {
		var err error
		refs, err = parseTarget(Target{Ecosystem: intel.EcosystemNPM, Path: path, Source: "pnpm-lock.yaml"})
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
		require.Len(t, refs, n)
	case <-time.After(15 * time.Second):
		t.Fatal("parsing a pnpm-lock.yaml with many package keys did not finish")
	}
}

// Aliases inside package values are never expanded, so an alias fan-out
// costs nothing.
func TestPNPMLockDoesNotExpandAliases(t *testing.T) {
	var b strings.Builder
	b.WriteString("a: &a [x,x,x,x,x,x,x,x,x,x]\n")
	prev := "a"
	for _, name := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		fmt.Fprintf(&b, "%s: &%s [%s]\n", name, name, strings.TrimSuffix(strings.Repeat("*"+prev+",", 10), ","))
		prev = name
	}
	b.WriteString("packages:\n  a@1.0.0: [*i,*i,*i,*i,*i,*i,*i,*i,*i,*i]\n")
	keys, err := pnpmKeysOf(t, b.String())
	require.NoError(t, err)
	require.Equal(t, []string{"a@1.0.0"}, keys)
}

func TestXMLBudget(t *testing.T) {
	deep := "<project>" + strings.Repeat("<a>", maxXMLDepth) + strings.Repeat("</a>", maxXMLDepth) + "</project>"
	require.ErrorContains(t, checkXMLBudget([]byte(deep), "pom.xml"), "levels deep")
	wide := "<project>" + strings.Repeat("<a/>", maxStructuredNodes/2+1) + "</project>"
	require.ErrorContains(t, checkXMLBudget([]byte(wide), "pom.xml"), "token limit")
	require.NoError(t, checkXMLBudget([]byte("<project><dependencies><dependency/></dependencies></project>"), "pom.xml"))

	for _, c := range []struct{ ecosystem, source string }{
		{intel.EcosystemMaven, "pom.xml"},
		{intel.EcosystemNuGet, "csproj"},
	} {
		path := filepath.Join(t.TempDir(), "file.xml")
		require.NoError(t, os.WriteFile(path, []byte(deep), 0o600))
		_, err := parseTarget(Target{Ecosystem: c.ecosystem, Path: path, Source: c.source})
		require.ErrorContains(t, err, "levels deep", c.source)
	}
}

// Every format stops at the entry limit: the streaming parsers while they
// read, the others when they return.
func TestLineLockfilesEntryLimit(t *testing.T) {
	lowerEntryLimit(t, 50)
	lines := func(format string) string {
		var b strings.Builder
		for i := 0; i <= maxLockfileEntries; i++ {
			fmt.Fprintf(&b, format, i)
		}
		return b.String()
	}
	for _, c := range []struct{ ecosystem, source, content string }{
		{intel.EcosystemGo, "go.sum", lines("example.com/m%d v1.0.0 h1:x\n")},
		{intel.EcosystemGo, "go.mod", "module x\n\nrequire (\n" + lines("\texample.com/m%d v1.0.0\n") + ")\n"},
		{intel.EcosystemRubyGems, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n" + lines("    g%d (1.0.0)\n")},
		{intel.EcosystemMaven, "gradle.lockfile", lines("g:a%d:1.0.0=runtimeClasspath\n")},
		{intel.EcosystemNPM, "yarn.lock", "# yarn lockfile v1\n\n" + lines("p%d@1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/p/-/p-1.0.0.tgz\"\n\n")},
	} {
		_, err := parseFile(t, c.ecosystem, c.source, c.content)
		require.ErrorContains(t, err, "more than 50 package entries", c.source)
	}
}

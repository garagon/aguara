package packagecheck

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// ParseGo reads a Go lockfile and returns the declared module
// dependencies. The function is the single Go-parser entry point;
// it dispatches on target.Source to the go.sum or go.mod reader.
//
// No external tools (`go list`, `go mod`) are invoked, and the
// reader never touches the network. Comments are stripped, replace
// directives are skipped, and (module, version) duplicates are
// folded so the same dependency is not double-counted.
func ParseGo(target Target) ([]PackageRef, error) {
	switch target.Source {
	case "go.sum":
		return parseGoSum(target)
	case "go.mod":
		return parseGoMod(target)
	default:
		return nil, fmt.Errorf("packagecheck: ParseGo: unsupported source %q (want go.sum or go.mod)", target.Source)
	}
}

// parseGoSum reads `module version hash` and `module version/go.mod
// hash` lines and returns one ref per (module, version).
//
// The two kinds of line record different things (Go Modules Reference,
// "go.sum files"): the zip hash is written when the module's content was
// downloaded to build or load packages; a `/go.mod` hash alone is written
// when only the module's go.mod was read during version selection, as for
// a version that minimal version selection considered and then replaced
// by a higher one. Such a version is in the module graph but its code was
// never fetched or built, so its ref is GraphOnly: the runner matches it
// only against advisories that cover every version of the module, never
// against an exact version or a range.
//
// When the directory also has a go.mod, its `require` lines are the
// versions the build selects: a required version is never graph-only,
// and a required version missing from go.sum is added, so a go.mod
// requiring a compromised release is reported whatever go.sum holds.
//
// Lines we do NOT recognise are skipped silently; go.sum is a
// stable format but stray blank lines / future suffixes should not
// abort the parse.
func parseGoSum(target Target) ([]PackageRef, error) {
	f, err := openManifest(target.Path, "go.sum")
	if err != nil {
		return nil, fmt.Errorf("open go.sum: %w", err)
	}
	defer func() { _ = f.Close() }()

	type key struct{ name, version string }
	index := make(map[key]int)
	hasZip := make(map[key]bool)
	var refs []PackageRef

	scanner := bufio.NewScanner(boundedManifestReader(f, maxManifestBytes, "go.sum"))
	// go.sum lines are short; the default Scanner buffer (64 KiB)
	// is far more than enough for a single line.
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		version, modOnly := strings.CutSuffix(fields[1], "/go.mod")
		if version == "" {
			continue
		}
		k := key{name, version}
		if !modOnly {
			hasZip[k] = true
		}
		if _, ok := index[k]; ok {
			continue
		}
		if err := checkEntryLimit(len(refs), "go.sum"); err != nil {
			return nil, err
		}
		index[k] = len(refs)
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemGo,
			Name:      name,
			Version:   version,
			Path:      target.Path,
			Source:    "go.sum",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}

	required := make(map[key]bool)
	var mod goModFile
	modPath := filepath.Join(filepath.Dir(target.Path), "go.mod")
	if manifestCandidate(modPath) {
		var err error
		mod, err = readGoMod(Target{Ecosystem: intel.EcosystemGo, Path: modPath, Source: "go.mod"})
		if err != nil {
			return nil, err
		}
		for _, r := range mod.requires {
			k := key{r.Name, r.Version}
			required[k] = true
			if _, ok := index[k]; !ok {
				index[k] = len(refs)
				refs = append(refs, r)
			}
		}
	}
	for i := range refs {
		k := key{refs[i].Name, refs[i].Version}
		refs[i].GraphOnly = refs[i].Source == "go.sum" && !hasZip[k] && !required[k]
	}
	mod.apply(refs)
	return refs, nil
}

// goModFile is what readGoMod keeps from a go.mod: the require lines, the
// replace directives and the excluded (module, version) pairs.
type goModFile struct {
	requires []PackageRef
	replaces []goReplace
	excludes map[[2]string]bool
}

// apply records on refs what the go.mod's replace and exclude directives
// say about them.
func (m goModFile) apply(refs []PackageRef) {
	applyGoReplaces(refs, m.replaces)
	for i := range refs {
		refs[i].Excluded = m.excludes[[2]string{refs[i].Name, refs[i].Version}]
	}
}

// goReplace is one go.mod replace directive: `old [version] => new
// [version]`, where new is a module path or a local directory.
type goReplace struct {
	oldPath, oldVersion string
	replacement         string
}

// applyGoReplaces records on each ref the replacement a go.mod replace
// directive substitutes for it. The ref is still reported: the advisory
// names the module and version the dependency graph asks for, and the
// finding says the build uses the replacement instead.
func applyGoReplaces(refs []PackageRef, replaces []goReplace) {
	for i := range refs {
		for _, r := range replaces {
			if r.oldPath == refs[i].Name && (r.oldVersion == "" || r.oldVersion == refs[i].Version) {
				refs[i].Replacement = r.replacement
			}
		}
	}
}

// parseGoMod reads `require` declarations from a go.mod. Both the
// single-line form and the block form are supported; the parser
// strips inline `// ...` comments before splitting.
//
// `replace` directives do not change what is matched: the require line
// still names the module and version the graph asks for. They are
// recorded on the ref (Replacement) so the finding can say that the build
// uses the replacement module or local directory instead.
//
// `exclude` directives do not change what is matched either: since Go
// 1.16 the go command ignores a requirement on an excluded version, but
// the require line still names a compromised release, so the ref is
// matched and marked Excluded for the finding to say so.
//
// `module` and `go` directives are also skipped; they declare the
// CURRENT module, not a dependency.
func parseGoMod(target Target) ([]PackageRef, error) {
	mod, err := readGoMod(target)
	if err != nil {
		return nil, err
	}
	mod.apply(mod.requires)
	return mod.requires, nil
}

func readGoMod(target Target) (goModFile, error) {
	var mod goModFile
	f, err := openManifest(target.Path, "go.mod")
	if err != nil {
		return mod, fmt.Errorf("open go.mod: %w", err)
	}
	defer func() { _ = f.Close() }()

	mod.excludes = map[[2]string]bool{}
	directive := func(verb, body string) error {
		switch verb {
		case "require":
			if ref, ok := parseRequireLine(body, target.Path); ok {
				if err := checkEntryLimit(len(mod.requires), "go.mod"); err != nil {
					return err
				}
				mod.requires = append(mod.requires, ref)
			}
		case "replace":
			if r, ok := parseReplaceLine(body); ok && len(mod.replaces) < maxManifestEntries {
				mod.replaces = append(mod.replaces, r)
			}
		case "exclude":
			if fields := strings.Fields(body); len(fields) == 2 && len(mod.excludes) < maxManifestEntries {
				mod.excludes[[2]string{unquoteGoModToken(fields[0]), unquoteGoModToken(fields[1])}] = true
			}
		}
		// Everything else (module / go / retract / toolchain / use /
		// godebug / tool / ignore) is skipped.
		return nil
	}
	block := ""

	scanner := bufio.NewScanner(boundedManifestReader(f, maxManifestBytes, "go.mod"))
	for scanner.Scan() {
		raw := scanner.Text()
		// Strip an inline `// comment` so a require line
		// followed by a comment still parses cleanly.
		if i := strings.Index(raw, "//"); i >= 0 {
			raw = raw[:i]
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		if block == "" {
			// The go.mod lexer ends a directive's verb at white space or
			// at the "(" that opens a block ("require(").
			verb, rest := line, ""
			if i := strings.IndexAny(line, " \t("); i >= 0 {
				verb, rest = line[:i], strings.TrimSpace(line[i:])
			}
			if rest == "(" {
				block = verb
				continue
			}
			if err := directive(verb, rest); err != nil {
				return goModFile{}, err
			}
			continue
		}

		if line == ")" {
			block = ""
			continue
		}
		if err := directive(block, line); err != nil {
			return goModFile{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return goModFile{}, fmt.Errorf("read go.mod: %w", err)
	}
	return mod, nil
}

// parseReplaceLine reads `old [version] => new [version]`.
func parseReplaceLine(body string) (goReplace, bool) {
	left, right, ok := strings.Cut(body, "=>")
	if !ok {
		return goReplace{}, false
	}
	lf, rf := strings.Fields(left), strings.Fields(right)
	if len(lf) == 0 || len(lf) > 2 || len(rf) == 0 || len(rf) > 2 {
		return goReplace{}, false
	}
	r := goReplace{oldPath: unquoteGoModToken(lf[0])}
	if len(lf) == 2 {
		r.oldVersion = unquoteGoModToken(lf[1])
	}
	r.replacement = unquoteGoModToken(rf[0])
	if len(rf) == 2 {
		r.replacement += " " + unquoteGoModToken(rf[1])
	}
	return r, true
}

// parseRequireLine extracts a (module, version) pair from a single
// require body. The body looks like `example.com/mod v1.2.3` or
// `example.com/mod v1.2.3 indirect` (the `indirect` is a comment
// the line-stripper already removed). Returns ok=false for
// malformed bodies; the caller silently skips them so a single bad
// line cannot abort the whole parse.
func parseRequireLine(body, path string) (PackageRef, bool) {
	fields := strings.Fields(body)
	if len(fields) < 2 {
		return PackageRef{}, false
	}
	// go.mod may quote a module path or version as a Go string literal
	// (Go Modules Reference, "go.mod files: Lexical elements").
	name := unquoteGoModToken(fields[0])
	version := unquoteGoModToken(fields[1])
	if name == "" || version == "" {
		return PackageRef{}, false
	}
	return PackageRef{
		Ecosystem: intel.EcosystemGo,
		Name:      name,
		Version:   version,
		Path:      path,
		Source:    "go.mod",
	}, true
}

// unquoteGoModToken returns an interpreted ("...") or raw (`...`) Go
// string token without its quotes, and any other token unchanged. A
// token that does not unquote cleanly is returned as written, so it
// simply matches nothing.
func unquoteGoModToken(tok string) string {
	if len(tok) < 2 || (tok[0] != '"' && tok[0] != '`') {
		return tok
	}
	s, err := strconv.Unquote(tok)
	if err != nil {
		return tok
	}
	return s
}

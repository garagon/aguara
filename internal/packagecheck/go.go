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
	modPath := filepath.Join(filepath.Dir(target.Path), "go.mod")
	if manifestCandidate(modPath) {
		mod, err := parseGoMod(Target{Ecosystem: intel.EcosystemGo, Path: modPath, Source: "go.mod"})
		if err != nil {
			return nil, err
		}
		for _, r := range mod {
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
	return refs, nil
}

// parseGoMod reads `require` declarations from a go.mod. Both the
// single-line form and the block form are supported; the parser
// strips inline `// ...` comments before splitting.
//
// `replace` directives are intentionally skipped in this first
// cut: local replacements (`=> ../local`) do not have a Go-module
// version the matcher could consume, and registry replacements
// (`=> module v1.2.3`) require resolving the substitution chain
// before the rest of the file's requires hash to the substituted
// version. PR #2 covers the require-only surface; replace handling
// lands in a follow-up alongside the gradle / Maven multi-source
// parsers.
//
// `module` and `go` directives are also skipped; they declare the
// CURRENT module, not a dependency.
func parseGoMod(target Target) ([]PackageRef, error) {
	f, err := openManifest(target.Path, "go.mod")
	if err != nil {
		return nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer func() { _ = f.Close() }()

	var refs []PackageRef
	inRequire := false

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

		if !inRequire {
			switch {
			case line == "require (":
				inRequire = true
				continue
			case strings.HasPrefix(line, "require ("):
				// Defensive: a `require (` with trailing
				// whitespace before the open paren.
				inRequire = true
				continue
			case strings.HasPrefix(line, "require "):
				if ref, ok := parseRequireLine(strings.TrimPrefix(line, "require "), target.Path); ok {
					refs = append(refs, ref)
				}
				continue
			}
			// Skip everything else (module / go / replace / retract
			// / exclude / toolchain / use / godebug).
			continue
		}

		if line == ")" {
			inRequire = false
			continue
		}
		if ref, ok := parseRequireLine(line, target.Path); ok {
			refs = append(refs, ref)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	return refs, nil
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

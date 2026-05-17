package packagecheck

import (
	"bufio"
	"fmt"
	"os"
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
// hash` lines. The runtime matcher only cares about (module,
// version), so we dedupe across both entry kinds. When only the
// `/go.mod` line is present (a transitive dependency Go resolved
// the module proxy hash for without downloading the module zip),
// we strip the `/go.mod` suffix and treat it as a real version.
//
// Lines we do NOT recognise are skipped silently; go.sum is a
// stable format but stray blank lines / future suffixes should not
// abort the parse.
func parseGoSum(target Target) ([]PackageRef, error) {
	f, err := os.Open(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open go.sum: %w", err)
	}
	defer func() { _ = f.Close() }()

	type key struct{ name, version string }
	seen := make(map[key]bool)
	var refs []PackageRef

	scanner := bufio.NewScanner(f)
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
		version := fields[1]
		// The `/go.mod` suffix marks the proxy-side resolved
		// module-spec hash; the underlying version is the same
		// as the zip entry's, so strip it for dedupe.
		version = strings.TrimSuffix(version, "/go.mod")
		if version == "" {
			continue
		}
		k := key{name, version}
		if seen[k] {
			continue
		}
		seen[k] = true
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
	f, err := os.Open(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer func() { _ = f.Close() }()

	var refs []PackageRef
	inRequire := false

	scanner := bufio.NewScanner(f)
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
	name := fields[0]
	version := fields[1]
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

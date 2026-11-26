package aguara

import (
	"runtime/debug"

	"github.com/garagon/aguara/internal/types"
)

// ToolInfo identifies the Aguara build: name, version and, when known, the
// source commit. CLI JSON reports carry the same object as `tool`.
type ToolInfo = types.ToolInfo

// CatalogInfo identifies a rule catalog: detection and rule counts and a
// digest that changes whenever a rule is added, removed, disabled, re-rated
// or edited. CLI JSON reports carry the same object as `catalog`.
type CatalogInfo = types.CatalogInfo

// modulePath is the import path ToolIdentity looks for in the build info.
const modulePath = "github.com/garagon/aguara"

// ToolIdentity returns the version of the Aguara module linked into the
// running program, read from the Go build information: the dependency
// version (for example "v0.29.0" or a pseudo-version) when Aguara is used as
// a library, or the main module version and VCS revision when the program
// is Aguara itself. Version is "dev" when the build information does not
// record one, as in `go run` or test binaries.
func ToolIdentity() ToolInfo {
	info := ToolInfo{Name: "aguara", Version: "dev"}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	if bi.Main.Path == modulePath {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			info.Version = v
		}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				info.Commit = s.Value
			}
		}
		return info
	}
	for _, dep := range bi.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			info.Version = dep.Replace.Version
		} else if dep.Version != "" {
			info.Version = dep.Version
		}
		break
	}
	return info
}

// CatalogIdentity returns the identity of the rule catalog the options
// select: the built-in rules plus WithCustomRules directories, after
// WithDisabledRules and WithRuleOverrides. Invalid rule configuration is
// reported the way ListRulesE reports it.
func CatalogIdentity(opts ...Option) (CatalogInfo, error) {
	res, err := resolveConfig(applyOpts(opts))
	if err != nil {
		return CatalogInfo{}, err
	}
	return res.Identity(), nil
}

// CatalogIdentity returns the identity of the rule catalog this scanner
// uses.
func (sc *Scanner) CatalogIdentity() CatalogInfo {
	return sc.resolution.Identity()
}

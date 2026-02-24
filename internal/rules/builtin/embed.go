// Package builtin embeds the YAML detection rule files via go:embed.
package builtin

import "embed"

//go:embed *.yaml
var builtinRules embed.FS

// FS returns the embedded filesystem containing built-in rules.
func FS() embed.FS {
	return builtinRules
}

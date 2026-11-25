package rulecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/types"
)

// digestRule is the canonical, versioned projection of one rule that the
// catalog digest hashes. Field order is fixed by the struct, so the JSON
// encoding (and therefore the digest) depends only on rule content.
type digestRule struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Severity       string          `json:"severity"`
	Category       string          `json:"category"`
	Analyzer       string          `json:"analyzer"`
	Description    string          `json:"description"`
	Remediation    string          `json:"remediation"`
	CWE            []string        `json:"cwe"`
	Targets        []string        `json:"targets,omitempty"`
	ExcludeTargets []string        `json:"exclude_targets,omitempty"`
	MatchAll       bool            `json:"match_all,omitempty"`
	WithinLines    int             `json:"within_lines,omitempty"`
	Sensitive      bool            `json:"sensitive,omitempty"`
	Patterns       []digestPattern `json:"patterns,omitempty"`
	Excludes       []digestExclude `json:"excludes,omitempty"`
}

type digestPattern struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type digestExclude struct {
	digestPattern
	Scope int `json:"scope"`
}

// digestVersion prefixes the hashed document so a change to the projection
// itself cannot collide with an older digest.
const digestVersion = "aguara-catalog-digest/v1"

// Identity returns the counts and digest of the effective catalog: built-in
// and custom pattern rules plus analyzer rules, after disabled rules are
// removed and severity overrides applied. The digest is stable across runs
// and platforms for the same rule set.
func (r *Resolution) Identity() types.CatalogInfo {
	catalog := r.Catalog("")
	compiled := make(map[string]*rules.CompiledRule, len(r.Compiled))
	for _, c := range r.Compiled {
		compiled[c.ID] = c
	}

	info := types.CatalogInfo{Detections: len(catalog), PatternRules: len(r.Compiled)}
	doc := make([]digestRule, 0, len(catalog))
	for _, meta := range catalog {
		d := digestRule{
			ID:          meta.ID,
			Name:        meta.Name,
			Severity:    meta.Severity,
			Category:    meta.Category,
			Analyzer:    meta.Analyzer,
			Description: meta.Description,
			Remediation: meta.Remediation,
			CWE:         append([]string{}, meta.CWE...),
		}
		if meta.Analyzer != "" {
			info.AnalyzerRules++
		}
		if c, ok := compiled[meta.ID]; ok && meta.Analyzer == "" {
			d.Targets = c.Targets
			d.ExcludeTargets = c.ExcludeTargets
			d.MatchAll = c.MatchMode == rules.MatchAll
			d.WithinLines = c.WithinLines
			d.Sensitive = c.Sensitive
			for _, p := range c.Patterns {
				d.Patterns = append(d.Patterns, projectPattern(p))
			}
			for _, e := range c.ExcludePatterns {
				d.Excludes = append(d.Excludes, digestExclude{projectPattern(e.CompiledPattern), int(e.Scope)})
			}
		}
		doc = append(doc, d)
	}

	h := sha256.New()
	h.Write([]byte(digestVersion))
	h.Write([]byte{0})
	// Marshalling plain structs and slices cannot fail.
	data, _ := json.Marshal(doc)
	h.Write(data)
	info.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return info
}

func projectPattern(p rules.CompiledPattern) digestPattern {
	if p.Type == rules.PatternRegex && p.Regex != nil {
		return digestPattern{Type: string(p.Type), Value: p.Regex.String()}
	}
	return digestPattern{Type: string(p.Type), Value: p.Value}
}

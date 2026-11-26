package packagecheck

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/garagon/aguara/internal/intel"
	"github.com/pelletier/go-toml/v2/unstable"
)

// Python lockfile limits. maxLockfileEntries bounds the refs one file
// may produce, as for every dependency file;
// maxTOMLExpressionNodes bounds the parser's per-expression node arena;
// maxTOMLKeyParts bounds dotted keys and table headers.
const (
	maxTOMLExpressionNodes = 200_000
	maxTOMLKeyParts        = 16
)

// tomlExpr is one top-level TOML expression as the Python lockfile
// parsers consume it: a table header, an array-of-tables header, or a
// key/value pair inside the current table.
type tomlExpr struct {
	kind unstable.Kind
	// keys is the header path for Table/ArrayTable and the (possibly
	// dotted) key for KeyValue, relative to the current table.
	keys []string
	// value is the value node of a KeyValue; nil for headers.
	value *unstable.Node
	// line is the 1-based line where the expression starts.
	line int
}

// walkTOML streams data through the go-toml expression parser and calls
// visit for every table header and key/value pair. It never materialises
// the document: the general decoder tracks duplicate keys by searching
// earlier siblings, which turns untrusted metadata into quadratic work.
// Parsers apply their own duplicate checks to the identity fields they
// read.
func walkTOML(data []byte, label string, visit func(tomlExpr) error) error {
	if err := checkTOMLNodeBudget(data, label); err != nil {
		return err
	}
	var parser unstable.Parser
	parser.Reset(data)
	lines := lineCounter{data: data, line: 1}
	for parser.NextExpression() {
		expr := parser.Expression()
		if expr.Kind != unstable.Table && expr.Kind != unstable.ArrayTable && expr.Kind != unstable.KeyValue {
			continue
		}
		it := expr.Key()
		var keys []string
		offset := -1
		for it.Next() {
			node := it.Node()
			if offset < 0 {
				offset = int(node.Raw.Offset)
			}
			if len(keys) == maxTOMLKeyParts {
				return errBudget("parse %s: key has more than %d parts", label, maxTOMLKeyParts)
			}
			keys = append(keys, string(node.Data))
		}
		if expr.Kind == unstable.KeyValue {
			offset = int(expr.Raw.Offset)
		}
		e := tomlExpr{kind: expr.Kind, keys: keys, line: lines.at(offset)}
		if expr.Kind == unstable.KeyValue {
			e.value = expr.Value()
		}
		if err := visit(e); err != nil {
			return err
		}
	}
	if parser.Error() != nil {
		// Parser diagnostics may quote credential-bearing input
		// (index URLs with tokens), so do not echo them.
		return fmt.Errorf("parse %s: invalid TOML syntax", label)
	}
	return nil
}

// lineCounter maps monotonically increasing byte offsets to 1-based
// line numbers in O(len(data)) total, instead of rescanning from the
// start of the document for every expression.
type lineCounter struct {
	data []byte
	off  int
	line int
}

func (c *lineCounter) at(offset int) int {
	if offset < 0 || offset > len(c.data) {
		return 0
	}
	if offset < c.off {
		c.off, c.line = 0, 1
	}
	c.line += bytes.Count(c.data[c.off:offset], []byte{'\n'})
	c.off = offset
	return c.line
}

// checkTOMLNodeBudget bounds the memory the streaming parser can spend
// on one expression. go-toml keeps every node of the expression being
// parsed in one arena, so a single 50 MiB array of one-byte values
// would allocate gigabytes before any semantic check runs. This lexical
// pre-pass skips strings and comments, tracks bracket depth to find
// expression boundaries, and counts the bytes that can start a node.
// It over-approximates on purpose; real lockfiles stay far below the
// limit.
func checkTOMLNodeBudget(data []byte, label string) error {
	depth, count := 0, 0
	for i := 0; i < len(data); {
		switch c := data[i]; c {
		case '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		case '"', '\'':
			i = skipTOMLString(data, i)
			count++
		case '[', '{':
			depth++
			count++
			i++
		case ']', '}':
			if depth > 0 {
				depth--
			}
			i++
		case ',', '=', '.':
			count++
			i++
		case '\n':
			if depth == 0 {
				count = 0
			}
			i++
		default:
			i++
		}
		if count > maxTOMLExpressionNodes {
			return errBudget("parse %s: a TOML expression exceeds the %d-node limit", label, maxTOMLExpressionNodes)
		}
	}
	return nil
}

// skipTOMLString returns the offset just past the string starting at
// data[i]. Single-line strings that reach a newline end there, which is
// where the real parser reports the syntax error and stops.
func skipTOMLString(data []byte, i int) int {
	quote := data[i]
	if bytes.HasPrefix(data[i:], []byte{quote, quote, quote}) {
		for j := i + 3; j < len(data); {
			if quote == '"' && data[j] == '\\' {
				j += 2
				continue
			}
			if data[j] == quote {
				k := j
				for k < len(data) && data[k] == quote {
					k++
				}
				if k-j >= 3 {
					return k
				}
				j = k
				continue
			}
			j++
		}
		return len(data)
	}
	for j := i + 1; j < len(data); j++ {
		switch data[j] {
		case '\\':
			if quote == '"' {
				j++
			}
		case '\n':
			return j
		case quote:
			return j + 1
		}
	}
	return len(data)
}

// tomlString returns a string value, rejecting every other kind.
func tomlString(n *unstable.Node) (string, bool) {
	if n == nil || n.Kind != unstable.String {
		return "", false
	}
	return string(n.Data), true
}

// tomlStringArray returns an array whose elements are all strings.
func tomlStringArray(n *unstable.Node) ([]string, bool) {
	if n == nil || n.Kind != unstable.Array {
		return nil, false
	}
	var out []string
	it := n.Children()
	for it.Next() {
		s, ok := tomlString(it.Node())
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// tomlInlineTable returns the members of an inline table keyed by their
// single-part key. ok is false when the node is not an inline table, a
// member key is dotted, or a key repeats.
func tomlInlineTable(n *unstable.Node) (members map[string]*unstable.Node, ok bool) {
	if n == nil || n.Kind != unstable.InlineTable {
		return nil, false
	}
	members = map[string]*unstable.Node{}
	it := n.Children()
	for it.Next() {
		kv := it.Node()
		if kv.Kind != unstable.KeyValue {
			continue
		}
		keys := kv.Key()
		var key string
		parts := 0
		for keys.Next() {
			parts++
			key = string(keys.Node().Data)
		}
		if parts != 1 {
			return nil, false
		}
		if _, dup := members[key]; dup {
			return nil, false
		}
		members[key] = kv.Value()
	}
	return members, true
}

// lockVersionMajor parses the major component of a dotted lockfile
// format version ("2.1" -> 2).
func lockVersionMajor(v string) (int, bool) {
	major, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(major)
	if err != nil || n < 0 || strings.HasPrefix(major, "+") {
		return 0, false
	}
	return n, true
}

// pythonRefCollector deduplicates refs per file on the PEP 503 name and
// the exact version string, keeps the first occurrence (and its line),
// and enforces the per-file entry limit.
type pythonRefCollector struct {
	label string
	refs  []PackageRef
	seen  map[string]bool
}

func newPythonRefCollector(label string) *pythonRefCollector {
	return &pythonRefCollector{label: label, seen: map[string]bool{}}
}

func (c *pythonRefCollector) add(ref PackageRef) error {
	ref.Ecosystem = intel.EcosystemPyPI
	key := intel.PEP503Normalize(ref.Name) + "\x00" + ref.Version + "\x00" + ref.Constraint
	if c.seen[key] {
		return nil
	}
	if len(c.refs) >= maxLockfileEntries {
		return errBudget("parse %s: more than %d package entries", c.label, maxLockfileEntries)
	}
	c.seen[key] = true
	c.refs = append(c.refs, ref)
	return nil
}

// groupLabel joins dependency groups for display. A package that is in
// the format's main group is a main dependency and carries no label,
// even when development groups also pull it in.
func groupLabel(groups []string, main string) string {
	var out []string
	for _, g := range groups {
		if g == main {
			return ""
		}
		if g != "" {
			out = append(out, g)
		}
	}
	return strings.Join(out, ", ")
}

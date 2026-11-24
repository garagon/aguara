package packagecheck

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/types"
)

// Requirements-file limits. Includes are followed to a bounded depth and
// a bounded number of distinct files per discovered file; a logical
// line (after joining backslash continuations) is bounded in bytes.
const (
	maxRequirementsIncludeDepth = 8
	maxRequirementsFiles        = 1_000
	maxRequirementsLineBytes    = 1 << 20
)

// utf8BOM is the byte-order mark some editors write at the start of a
// UTF-8 file; pip accepts it.
const utf8BOM = "\xef\xbb\xbf"

// isRequirementsSource reports whether a file name is one discovery
// treats as a pip requirements or constraints file.
func isRequirementsSource(base string) bool {
	return strings.HasSuffix(base, ".txt") &&
		(strings.HasPrefix(base, "requirements") || strings.HasPrefix(base, "constraints"))
}

// pep508Name is the PEP 508 project-name grammar (case-insensitive).
var pep508Name = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// pipCommentRe is pip's COMMENT_RE: a '#' at the start of a line or
// preceded by whitespace starts a comment. pipCommentLine is the same
// pattern anchored at the line start, which is how pip decides that a
// line ending in a backslash is a comment rather than a continuation.
var (
	pipCommentRe   = regexp.MustCompile(`(^|\s+)#.*$`)
	pipCommentLine = regexp.MustCompile(`^\s*#`)
)

// requirementsCache parses each requirements file once per Runner.Run,
// keyed by its resolved path, so a file included by many discovered
// files is not re-read for each of them.
type requirementsCache struct {
	files map[string]*requirementsFile
}

func newRequirementsCache() *requirementsCache {
	return &requirementsCache{files: map[string]*requirementsFile{}}
}

// requirementsFile is one parsed file: requirement entries and include
// directives in file order.
type requirementsFile struct {
	items []requirementsItem
}

type requirementsItem struct {
	ref *PackageRef // nil for an include
	// include is set for -r / -c directives.
	include    string
	constraint bool
	line       int
}

// ParseRequirements reads a pip requirements or constraints file and
// returns the packages it names. `name==version` (and `===`) pins are
// returned with their version; any other named requirement (a range,
// a wildcard, no specifier) is returned as unpinned. Extras and
// environment markers are accepted; markers are not evaluated, so a pin
// counts whatever environment it targets. Editable installs, local
// paths, archive files, VCS links and direct URL references have no
// PyPI identity and are skipped. Index options and per-requirement
// options such as --hash are read and ignored.
//
// -r and -c includes are followed relative to the including file, only
// inside the project root (Target.Root), to a bounded depth. A URL,
// a path outside the project or a missing file is not read; the runner
// reports each one (RunResult.UnresolvedIncludes) and their count per
// target (unresolved_includes). An unsupported
// option, a malformed requirement or an unsafe file is an error.
// No pip execution, no environment-variable expansion, no network.
func ParseRequirements(target Target) ([]PackageRef, error) {
	parsed, err := parseRequirementsTarget(target, newRequirementsCache())
	return parsed.refs, err
}

func parseRequirementsTarget(target Target, cache *requirementsCache) (parsedTarget, error) {
	root := target.Root
	if root == "" {
		root = filepath.Dir(target.Path)
	}
	rootReal, err := realDir(root)
	if err != nil {
		return parsedTarget{}, fmt.Errorf("resolve project root: %w", err)
	}
	w := requirementsWalk{
		cache:    cache,
		rootReal: rootReal,
		visited:  map[string]bool{},
		coll:     newPythonRefCollector(target.Source),
	}
	constraint := strings.HasPrefix(filepath.Base(target.Path), "constraints")
	if err := w.visit(target.Path, constraint, 0); err != nil {
		return parsedTarget{}, err
	}
	return parsedTarget{refs: w.coll.refs, unresolved: w.unresolved}, nil
}

type requirementsWalk struct {
	cache      *requirementsCache
	rootReal   string
	visited    map[string]bool
	coll       *pythonRefCollector
	unresolved []UnresolvedInclude
}

func (w *requirementsWalk) visit(path string, constraint bool, depth int) error {
	if depth > maxRequirementsIncludeDepth {
		return fmt.Errorf("requirements includes nest deeper than %d levels", maxRequirementsIncludeDepth)
	}
	dirReal, err := realDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	key := filepath.Join(dirReal, filepath.Base(path))
	if w.visited[key] {
		return nil
	}
	if len(w.visited) >= maxRequirementsFiles {
		return fmt.Errorf("requirements includes reference more than %d files", maxRequirementsFiles)
	}
	w.visited[key] = true
	file, ok := w.cache.files[key]
	if !ok {
		file, err = parseRequirementsFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		w.cache.files[key] = file
	}
	for _, item := range file.items {
		if item.ref != nil {
			ref := *item.ref
			ref.Path = path
			ref.Source = filepath.Base(path)
			if constraint {
				ref.Group = "constraint"
			}
			if err := w.coll.add(ref); err != nil {
				return err
			}
			continue
		}
		next, reason := w.resolveInclude(path, item.include)
		if reason != "" {
			w.unresolved = append(w.unresolved, UnresolvedInclude{
				Path:     path,
				Line:     item.line,
				Argument: types.SanitizeURLUserinfo(item.include, "redacted@"),
				Reason:   reason,
			})
			continue
		}
		if err := w.visit(next, constraint || item.constraint, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// resolveInclude maps an include argument to a file inside the project
// root, or returns why it is not followed: a URL, an environment-variable
// reference, a path that leaves the root (directly or through a
// symlinked directory), or a file that does not exist.
func (w *requirementsWalk) resolveInclude(from, arg string) (string, string) {
	switch {
	case strings.Contains(arg, "://") || hasURLScheme(arg):
		return "", UnresolvedIncludeURL
	case arg == "" || strings.Contains(arg, "${"):
		return "", UnresolvedIncludeVariable
	}
	p := filepath.FromSlash(arg)
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(from), p)
	}
	// Resolve the nearest existing directory so a missing file inside the
	// project is told apart from a path that leaves it.
	for d := filepath.Dir(p); ; {
		if r, err := realDir(d); err == nil {
			if !withinDir(w.rootReal, r) {
				return "", UnresolvedIncludeOutside
			}
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", UnresolvedIncludeOutside
		}
		d = parent
	}
	if dirReal, err := realDir(filepath.Dir(p)); err != nil {
		return "", UnresolvedIncludeMissing
	} else if !withinDir(w.rootReal, dirReal) {
		return "", UnresolvedIncludeOutside
	}
	if _, err := os.Lstat(p); err != nil {
		return "", UnresolvedIncludeMissing
	}
	return p, ""
}

func realDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func withinDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// hasURLScheme reports a scheme prefix such as "https:" or "file:",
// excluding a Windows drive letter ("C:").
func hasURLScheme(s string) bool {
	m := urlScheme.FindString(s)
	return len(m) > 2
}

// pipCodingDeclaration is pip's PEP263_ENCODING_RE on bytes; Python's
// bytes \s is [ \t\n\r\f\v] and \w is [A-Za-z0-9_].
var pipCodingDeclaration = regexp.MustCompile(`coding[:=][ \t\n\r\f\v]*([-A-Za-z0-9_.]+)`)

// utf8CodingNames are the declared encodings that decode a requirements
// file exactly as UTF-8 does (ASCII is a subset; pip rejects non-ASCII
// bytes under it, which is never a way to hide an entry). Names are
// compared after lower-casing and mapping "-" to "_", as Python's codec
// lookup does.
var utf8CodingNames = map[string]bool{"utf_8": true, "utf8": true, "utf_8_sig": true, "ascii": true, "us_ascii": true}

// decodeRequirements mirrors how pip decodes a requirements file: a
// UTF-8 byte-order mark is stripped; otherwise a PEP 263 declaration in
// either of the first two "\n"-delimited lines, when that line starts
// with '#', selects the codec. A declared codec other than UTF-8 or
// ASCII is an error, not a guess: pip would decode the file differently
// (UTF-7, for example, can spell a newline as "+AAo-") and could install
// a requirement this parser never sees. Content that is not valid UTF-8
// is an error too; pip would fall back to the locale encoding.
func decodeRequirements(data []byte) (string, error) {
	if bytes.HasPrefix(data, []byte(utf8BOM)) {
		data = data[len(utf8BOM):]
	} else {
		lines := bytes.SplitN(data, []byte{'\n'}, 3)
		for i := 0; i < len(lines) && i < 2; i++ {
			if !bytes.HasPrefix(lines[i], []byte{'#'}) {
				continue
			}
			if m := pipCodingDeclaration.FindSubmatch(lines[i]); m != nil {
				name := strings.ReplaceAll(strings.ToLower(string(m[1])), "-", "_")
				if !utf8CodingNames[name] {
					return "", fmt.Errorf("line %d declares encoding %q; only UTF-8 requirements files are supported", i+1, m[1])
				}
				break
			}
		}
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("not valid UTF-8")
	}
	return string(data), nil
}

// forEachPythonLine calls fn for each line of s split the way Python's
// str.splitlines() splits it, which is how pip reads a requirements
// file: "\r\n", "\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", U+0085,
// U+2028 and U+2029 all end a line, and a trailing separator does not
// start an empty final line. s must be valid UTF-8. Line numbers are
// 1-based and count every separator, as pip's diagnostics do.
func forEachPythonLine(s string, fn func(line int, text string) error) error {
	lineNo, start := 0, 0
	for i := 0; i < len(s); {
		width := 0
		switch c := s[i]; {
		case c == '\r' && i+1 < len(s) && s[i+1] == '\n':
			width = 2
		case c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == 0x1c || c == 0x1d || c == 0x1e:
			width = 1
		case c == 0xc2 && i+1 < len(s) && s[i+1] == 0x85:
			width = 2 // U+0085
		case c == 0xe2 && i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xa8 || s[i+2] == 0xa9):
			width = 3 // U+2028, U+2029
		}
		if width == 0 {
			i++
			continue
		}
		lineNo++
		if err := fn(lineNo, s[start:i]); err != nil {
			return err
		}
		i += width
		start = i
	}
	if start < len(s) {
		return fn(lineNo+1, s[start:])
	}
	return nil
}

func parseRequirementsFile(path string) (*requirementsFile, error) {
	data, err := readManifest(path, "requirements")
	if err != nil {
		return nil, err
	}
	content, err := decodeRequirements(data)
	if err != nil {
		return nil, err
	}
	out := &requirementsFile{}
	var pending strings.Builder
	pendingLine := 0
	emit := func(line int, text string) error {
		text = strings.TrimSpace(pipCommentRe.ReplaceAllString(text, ""))
		if text == "" {
			return nil
		}
		items, err := parseRequirementsLine(text, line)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if len(out.items)+len(items) > maxPythonLockEntries {
			return fmt.Errorf("more than %d entries", maxPythonLockEntries)
		}
		out.items = append(out.items, items...)
		return nil
	}
	err = forEachPythonLine(content, func(lineNo int, text string) error {
		if len(text) > maxRequirementsLineBytes {
			return fmt.Errorf("line %d exceeds %d bytes", lineNo, maxRequirementsLineBytes)
		}
		// pip joins a line ending in a backslash with the next one,
		// unless the line is a comment.
		if strings.HasSuffix(text, `\`) && !pipCommentLine.MatchString(text) {
			if pending.Len() == 0 {
				pendingLine = lineNo
			}
			if pending.Len()+len(text) > maxRequirementsLineBytes {
				return fmt.Errorf("line %d: continued line exceeds %d bytes", pendingLine, maxRequirementsLineBytes)
			}
			pending.WriteString(strings.Trim(text, `\`))
			return nil
		}
		if pending.Len() > 0 {
			if pipCommentLine.MatchString(text) {
				text = " " + text
			}
			pending.WriteString(text)
			joined := pending.String()
			pending.Reset()
			return emit(pendingLine, joined)
		}
		return emit(lineNo, text)
	})
	if err != nil {
		return nil, err
	}
	if pending.Len() > 0 {
		if err := emit(pendingLine, pending.String()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Options pip accepts on their own line in a requirements file. The
// value says whether the option takes an argument.
var requirementsGlobalOptions = map[string]bool{
	"-i": true, "--index-url": true, "--extra-index-url": true, "--no-index": false,
	"-f": true, "--find-links": true, "--trusted-host": true,
	"-r": true, "--requirement": true, "-c": true, "--constraint": true,
	"-e": true, "--editable": true,
	"--pre": false, "--prefer-binary": false, "--only-binary": true, "--no-binary": true,
	"--require-hashes": false, "--no-require-hashes": false, "--use-feature": true,
	"--all-releases": false, "--only-final": false,
}

// Options pip accepts after a requirement on the same line.
var requirementsPerReqOptions = map[string]bool{
	"--hash": true, "--config-settings": true, "--global-option": true, "--install-option": true,
}

// shortWithValue are the short options pip also accepts with the value
// attached ("-rbase.txt", "-e.").
var shortWithValue = []string{"-r", "-c", "-e", "-i", "-f"}

func parseRequirementsLine(text string, line int) ([]requirementsItem, error) {
	if strings.HasPrefix(text, "-") {
		return parseRequirementsOptions(text, line)
	}
	// pip splits the requirement from trailing options at the first
	// space-separated token that starts with "-".
	tokens := strings.Split(text, " ")
	var args []string
	i := 0
	for ; i < len(tokens); i++ {
		if strings.HasPrefix(tokens[i], "-") {
			break
		}
		args = append(args, tokens[i])
	}
	if i < len(tokens) {
		if err := checkPerRequirementOptions(strings.Join(tokens[i:], " ")); err != nil {
			return nil, err
		}
	}
	ref, err := parseNamedRequirement(strings.TrimSpace(strings.Join(args, " ")))
	if err != nil || ref == nil {
		return nil, err
	}
	ref.Line = line
	return []requirementsItem{{ref: ref, line: line}}, nil
}

func parseRequirementsOptions(text string, line int) ([]requirementsItem, error) {
	words, err := shellWords(text)
	if err != nil {
		return nil, err
	}
	var items []requirementsItem
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			// pip ignores positional leftovers on an option line.
			continue
		}
		name, value, hasValue := strings.Cut(w, "=")
		if !strings.HasPrefix(w, "--") {
			name, value, hasValue = w, "", false
			for _, short := range shortWithValue {
				if len(w) > len(short) && strings.HasPrefix(w, short) {
					name, value, hasValue = short, strings.TrimPrefix(w[len(short):], "="), true
				}
			}
		}
		takesValue, known := requirementsGlobalOptions[name]
		if !known {
			return nil, fmt.Errorf("unsupported option %q", name)
		}
		if takesValue && !hasValue {
			if i+1 >= len(words) {
				return nil, fmt.Errorf("option %s needs a value", name)
			}
			i++
			value = words[i]
		}
		switch name {
		case "-r", "--requirement":
			items = append(items, requirementsItem{include: value, line: line})
		case "-c", "--constraint":
			items = append(items, requirementsItem{include: value, constraint: true, line: line})
		}
	}
	return items, nil
}

func checkPerRequirementOptions(text string) error {
	words, err := shellWords(text)
	if err != nil {
		return err
	}
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			continue
		}
		name, _, hasValue := strings.Cut(w, "=")
		takesValue, known := requirementsPerReqOptions[name]
		if !known {
			return fmt.Errorf("unsupported requirement option %q", name)
		}
		if takesValue && !hasValue {
			if i+1 >= len(words) {
				return fmt.Errorf("option %s needs a value", name)
			}
			i++
		}
	}
	return nil
}

// parseNamedRequirement parses one requirement specifier. It returns
// nil without error for direct references (`name @ url`), local paths,
// archives and URLs, which have no registry identity.
func parseNamedRequirement(s string) (*PackageRef, error) {
	if s == "" {
		return nil, nil
	}
	if looksLikeRequirementPath(s) {
		return nil, nil
	}
	spec, marker, hasMarker := strings.Cut(s, ";")
	if hasMarker && strings.TrimSpace(marker) == "" {
		return nil, fmt.Errorf("empty environment marker")
	}
	spec = strings.TrimSpace(spec)
	end := 0
	for end < len(spec) && isNameByte(spec[end]) {
		end++
	}
	name := spec[:end]
	if !pep508Name.MatchString(name) {
		return nil, fmt.Errorf("invalid requirement")
	}
	rest := strings.TrimSpace(spec[end:])
	if strings.HasPrefix(rest, "[") {
		closeIdx := strings.IndexByte(rest, ']')
		if closeIdx < 0 {
			return nil, fmt.Errorf("unterminated extras for %s", name)
		}
		for _, extra := range strings.Split(rest[1:closeIdx], ",") {
			if extra = strings.TrimSpace(extra); extra != "" && !pep508Name.MatchString(extra) {
				return nil, fmt.Errorf("invalid extra for %s", name)
			}
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}
	if strings.HasPrefix(rest, "@") {
		return nil, nil // direct URL reference
	}
	ref := &PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name}
	if strings.Contains(rest, "${") {
		// pip would expand an environment variable here; the value is
		// not known offline.
		ref.Unpinned, ref.Constraint = true, rest
		return ref, nil
	}
	if strings.HasPrefix(rest, "(") {
		if !strings.HasSuffix(rest, ")") {
			return nil, fmt.Errorf("unterminated version for %s", name)
		}
		rest = strings.TrimSpace(rest[1 : len(rest)-1])
	}
	version, pinned, err := parseVersionSpecifier(rest)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if pinned {
		ref.Version = version
	} else {
		ref.Unpinned, ref.Constraint = true, rest
	}
	return ref, nil
}

var specifierOperators = []string{"===", "==", "!=", "~=", "<=", ">=", "<", ">"}

var specifierVersion = regexp.MustCompile(`^[A-Za-z0-9._*+!-]+$`)

// parseVersionSpecifier validates a PEP 440 specifier set and reports
// the version when the set pins exactly one release: a single `==`
// clause without a wildcard, or a single `===` clause.
func parseVersionSpecifier(spec string) (string, bool, error) {
	if spec == "" {
		return "", false, nil
	}
	var pin string
	pins := 0
	for _, clause := range strings.Split(spec, ",") {
		clause = strings.TrimSpace(clause)
		op := ""
		for _, candidate := range specifierOperators {
			if strings.HasPrefix(clause, candidate) {
				op = candidate
				break
			}
		}
		if op == "" {
			return "", false, fmt.Errorf("invalid version specifier")
		}
		v := strings.TrimSpace(clause[len(op):])
		if v == "" || (op != "===" && !specifierVersion.MatchString(v)) || strings.ContainsAny(v, " \t") {
			return "", false, fmt.Errorf("invalid version specifier")
		}
		switch {
		case op == "===":
			pins++
			pin = v
		case op == "==" && !strings.HasSuffix(v, ".*"):
			if _, ok := intel.PEP440Canonical(v); !ok {
				return "", false, fmt.Errorf("invalid version %q", v)
			}
			pins++
			pin = v
		}
	}
	if pins == 1 {
		return pin, true, nil
	}
	return "", false, nil
}

func isNameByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

var archiveSuffixes = []string{".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tar", ".zip"}

// looksLikeRequirementPath reports a requirement line that pip treats as
// a local path, an archive file or a URL rather than a project name.
func looksLikeRequirementPath(s string) bool {
	first := s
	if i := strings.IndexAny(s, " \t;"); i >= 0 {
		first = s[:i]
	}
	if strings.Contains(first, "://") || hasURLScheme(first) {
		return true
	}
	if strings.HasPrefix(first, ".") || strings.HasPrefix(first, "~") || strings.ContainsAny(first, `/\`) {
		return true
	}
	lower := strings.ToLower(first)
	for _, suffix := range archiveSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// shellWords splits an option string the way pip's shlex.split does for
// the cases requirements files use: whitespace-separated words, single
// and double quotes, and backslash escapes outside single quotes.
func shellWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("unterminated quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated quote")
			}
			inWord = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

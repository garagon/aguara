package packagecheck

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// RequirementsSyntaxError is a line of a requirements file that the
// parser's pip grammar does not accept: an unknown or ambiguous option, a
// malformed requirement, specifier, version, extras or marker, an
// unterminated quote, or an option without its value. The line is
// skipped and the rest of the file is read: its entries are matched and
// its includes followed as usual, and the file is also reported as not
// evaluated in full (format_not_parsed), so it never stands for a
// manifest. A requirement whose trailing options are rejected is still
// read, since the requirement itself parsed. Everything else a reader
// refuses, such as an unsafe or oversized file, a declared encoding other
// than UTF-8, content that is not UTF-8, an overlong line, too many
// entries or includes nested too deeply, remains an error, because pip
// could read such a file and install a pin Aguara never saw.
type RequirementsSyntaxError struct {
	// Path is the file that holds the line, which can be a file
	// reached through an include.
	Path string
	Line int
	err  error
}

func (e *RequirementsSyntaxError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.err)
}

func (e *RequirementsSyntaxError) Unwrap() error { return e.err }

// isRequirementsSource reports whether a file name is one discovery
// treats as a pip requirements or constraints file.
func isRequirementsSource(base string) bool {
	return strings.HasSuffix(base, ".txt") &&
		(strings.HasPrefix(base, "requirements") || strings.HasPrefix(base, "constraints"))
}

// constraintGroup is the PackageRef.Group of entries read from a
// constraints file or through a -c include.
const constraintGroup = "constraint"

// IsConstraintsFile reports a file read as pip constraints, by base
// name, the rule discovery applies: constraints install nothing, they
// only limit the versions requirements may resolve to.
func IsConstraintsFile(path string) bool {
	return strings.HasPrefix(filepath.Base(path), "constraints")
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
// directives in file order, and the first line it skipped (with the
// number of skipped lines).
type requirementsFile struct {
	items       []requirementsItem
	syntax      *RequirementsSyntaxError
	syntaxLines int
}

type requirementsItem struct {
	ref *PackageRef // nil for an include or a local entry
	// include is set for -r / -c directives.
	include    string
	constraint bool
	// local marks an editable install (-e) or a requirement that is a
	// local path or file: URL: pip builds that project and resolves its
	// own dependency metadata, which the file does not record. localPath
	// is the path or URL as written.
	local     bool
	localPath string
	line      int
}

// ParseRequirements reads a pip requirements or constraints file and
// returns the packages it names. `name==version` (and `===`) pins are
// returned with their version; any other named requirement (a range,
// a wildcard, no specifier) is returned as unpinned. Extras and
// environment markers are accepted; markers are not evaluated, so a pin
// counts whatever environment it targets. Editable installs, local
// paths, archive files, VCS links and direct URL references have no
// PyPI identity and are skipped, except a URL of a wheel or sdist on
// files.pythonhosted.org, which is pinned to the PyPI release its file
// name names. Index options and per-requirement
// options such as --hash are read and ignored.
//
// -r and -c includes are followed relative to the including file, only
// inside the project root (Target.Root), to a bounded depth. A URL,
// a path outside the project or a missing file is not read; the runner
// reports each one (RunResult.UnresolvedIncludes) and their count per
// target (unresolved_includes). An unsafe file is an error. A line
// outside the grammar (an unsupported option, a malformed requirement)
// is skipped: the entries that parsed are returned together with the
// first such line as a *RequirementsSyntaxError.
// No pip execution, no environment-variable expansion, no network.
func ParseRequirements(target Target) ([]PackageRef, error) {
	parsed, err := parseRequirementsTarget(target, newRequirementsCache())
	if err == nil && parsed.syntax != nil {
		return parsed.refs, parsed.syntax
	}
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
	constraint := IsConstraintsFile(target.Path)
	if err := w.visit(target.Path, constraint, 0); err != nil {
		return parsedTarget{}, err
	}
	files := make([]string, 0, len(w.visited))
	for key := range w.visited {
		files = append(files, key)
	}
	return parsedTarget{refs: w.coll.refs, unresolved: w.unresolved, files: files, local: w.local,
		localProjects: w.localProjects, localOther: w.localOther,
		syntax: w.syntax, syntaxLines: w.syntaxLines}, nil
}

type requirementsWalk struct {
	cache      *requirementsCache
	rootReal   string
	visited    map[string]bool
	coll       *pythonRefCollector
	unresolved []UnresolvedInclude
	// local is set when the file or one it includes has an editable or
	// local-path entry.
	local bool
	// localProjects are the project directories inside the root that
	// those entries install; localOther counts the entries that install
	// anything else (an archive, a VCS checkout, a path outside the root).
	localProjects []string
	localOther    int
	// syntax is the first line skipped in the file or one it includes,
	// in reading order; syntaxLines counts the skipped lines.
	syntax      *RequirementsSyntaxError
	syntaxLines int
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
	if file.syntax != nil {
		if w.syntax == nil {
			w.syntax = file.syntax
		}
		w.syntaxLines += file.syntaxLines
	}
	for _, item := range file.items {
		if item.local {
			w.local = true
			dirs := w.localProjectDirs(path, item.localPath)
			if len(dirs) == 0 {
				w.localOther++
			}
			for _, d := range dirs {
				if !slices.Contains(w.localProjects, d) && len(w.localProjects) < maxRequirementsFiles {
					w.localProjects = append(w.localProjects, d)
				}
			}
			continue
		}
		if item.ref != nil {
			ref := *item.ref
			ref.Path = path
			ref.Source = filepath.Base(path)
			if constraint {
				ref.Group = constraintGroup
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

// localProjectDirs returns the Python project directories inside the
// root that a local entry may install: its path taken relative to the
// file, and relative to the root, since pip reads a local path relative to
// the directory it runs in, which is usually the project root. A
// directory counts when it holds pyproject.toml, setup.py or setup.cfg.
// An archive, a VCS or remote URL, a home-relative path or one outside the
// root yields nothing.
func (w *requirementsWalk) localProjectDirs(from, arg string) []string {
	target := strings.TrimSpace(arg)
	if name, ref, ok := strings.Cut(target, "@"); ok && pep508Name.MatchString(strings.TrimSpace(strings.SplitN(name, "[", 2)[0])) {
		target = strings.TrimSpace(ref)
	}
	if i := strings.IndexAny(target, " \t;#"); i >= 0 {
		target = target[:i]
	}
	if rest, ok := cutPrefixFold(target, "file:"); ok {
		switch {
		case strings.HasPrefix(rest, "///"):
			target = rest[2:]
		case strings.HasPrefix(rest, "//localhost/"):
			target = rest[len("//localhost"):]
		case strings.HasPrefix(rest, "//"):
			return nil
		default:
			target = rest
		}
		if unescaped, err := url.PathUnescape(target); err == nil {
			target = unescaped
		}
	} else if strings.Contains(target, "://") || hasURLScheme(target) {
		return nil
	}
	if i := strings.IndexByte(target, '['); i >= 0 && strings.HasSuffix(target, "]") {
		target = target[:i]
	}
	if target == "" || strings.HasPrefix(target, "~") {
		return nil
	}
	p := filepath.FromSlash(target)
	candidates := []string{p}
	if !filepath.IsAbs(p) {
		candidates = []string{filepath.Join(filepath.Dir(from), p), filepath.Join(w.rootReal, p)}
	}
	var out []string
	for _, c := range candidates {
		real, err := realDir(c)
		if err != nil || !withinDir(w.rootReal, real) || slices.Contains(out, real) {
			continue
		}
		if info, err := os.Stat(real); err != nil || !info.IsDir() {
			continue
		}
		for _, name := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
			if manifestCandidate(filepath.Join(real, name)) {
				out = append(out, real)
				break
			}
		}
	}
	return out
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
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
			// Skip the line (keeping a requirement whose trailing
			// options were rejected) and read on.
			if out.syntax == nil {
				out.syntax = &RequirementsSyntaxError{Path: path, Line: line, err: err}
			}
			out.syntaxLines++
			if len(items) == 0 && !strings.HasPrefix(text, "-") {
				// An exact pin the line still starts with is kept for
				// matching: matching more than pip would install is
				// harmless, missing a pin it installs is not.
				if ref := salvageExactPin(text); ref != nil {
					ref.Line = line
					items = []requirementsItem{{ref: ref, line: line}}
				}
			}
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

// pip releases whose requirements-file option parser the table below
// follows (pip._internal.req.req_file.build_parser).
const (
	pipRelease252 uint8 = 1 << iota
	pipRelease260
	pipReleases = pipRelease252 | pipRelease260
)

// pipOption is one option of pip's requirements-file parser. pip uses
// the same parser for an option line and for the options after a
// requirement, then ignores the options that do not apply to the line.
type pipOption struct {
	long, short string
	value       bool
	releases    uint8
}

// pipOptions are the options pip 25.2 and pip 26.0 accept in a
// requirements file, with the releases that have each one: the global
// options (-i, --extra-index-url, --no-index, -c, -r, -e, -f,
// --no-binary, --only-binary, --prefer-binary, --require-hashes, --pre,
// --trusted-host, --use-feature, and --all-releases and --only-final
// from pip 26.0) and the per-requirement options (--hash,
// --config-settings, and --global-option until pip 26.0).
var pipOptions = []pipOption{
	{long: "--index-url", short: "-i", value: true, releases: pipReleases},
	{long: "--pypi-url", value: true, releases: pipReleases},
	{long: "--extra-index-url", value: true, releases: pipReleases},
	{long: "--no-index", releases: pipReleases},
	{long: "--constraint", short: "-c", value: true, releases: pipReleases},
	{long: "--requirement", short: "-r", value: true, releases: pipReleases},
	{long: "--editable", short: "-e", value: true, releases: pipReleases},
	{long: "--find-links", short: "-f", value: true, releases: pipReleases},
	{long: "--no-binary", value: true, releases: pipReleases},
	{long: "--only-binary", value: true, releases: pipReleases},
	{long: "--prefer-binary", releases: pipReleases},
	{long: "--require-hashes", releases: pipReleases},
	{long: "--pre", releases: pipReleases},
	{long: "--all-releases", value: true, releases: pipRelease260},
	{long: "--only-final", value: true, releases: pipRelease260},
	{long: "--trusted-host", value: true, releases: pipReleases},
	{long: "--use-feature", value: true, releases: pipReleases},
	{long: "--global-option", value: true, releases: pipRelease252},
	{long: "--hash", value: true, releases: pipReleases},
	{long: "--config-settings", short: "-C", value: true, releases: pipReleases},
}

// lookupPipLongOption resolves a long option name as pip's optparse
// does: the exact name, or else a prefix of exactly one option. It is
// resolved against each pip release in the table, and accepted when the
// releases that resolve it agree on one option, so a file either release
// reads is read; a prefix that no release resolves to a single option
// is an error ("--req" could be --requirement or --require-hashes).
func lookupPipLongOption(name string) (*pipOption, error) {
	var found *pipOption
	ambiguous := false
	for rel := pipRelease252; rel&pipReleases != 0; rel <<= 1 {
		var exact, only *pipOption
		matches := 0
		for i := range pipOptions {
			o := &pipOptions[i]
			if o.releases&rel == 0 {
				continue
			}
			if o.long == name {
				exact = o
				break
			}
			if strings.HasPrefix(o.long, name) {
				matches++
				only = o
			}
		}
		pick := exact
		if pick == nil {
			switch matches {
			case 0:
				continue
			case 1:
				pick = only
			default:
				ambiguous = true
				continue
			}
		}
		if found != nil && found != pick {
			return nil, fmt.Errorf("ambiguous option %s", name)
		}
		found = pick
	}
	switch {
	case found != nil:
		return found, nil
	case ambiguous:
		return nil, fmt.Errorf("ambiguous option %s", name)
	default:
		return nil, fmt.Errorf("unsupported option %s", name)
	}
}

func lookupPipShortOption(name string) *pipOption {
	for i := range pipOptions {
		if pipOptions[i].short == name {
			return &pipOptions[i]
		}
	}
	return nil
}

// pipOptionValue is one option read from a line, with its value.
type pipOptionValue struct {
	opt   *pipOption
	value string
}

// parsePipOptions reads an option string the way pip's optparse does: a
// long option as --name or --name=value, resolved by
// lookupPipLongOption; a short option with its value attached ("-rbase.txt")
// or in the next word; a value-taking option takes the next word even
// when it starts with "-". "--" ends the options, and other words are
// arguments, which pip ignores. A flag given a value, a missing value, or
// an unknown or ambiguous option is an error.
func parsePipOptions(text string) ([]pipOptionValue, error) {
	words, err := shellWords(text)
	if err != nil {
		return nil, err
	}
	var out []pipOptionValue
	for i := 0; i < len(words); i++ {
		w := words[i]
		var opt *pipOption
		value, hasValue := "", false
		switch {
		case w == "--":
			return out, nil
		case strings.HasPrefix(w, "--"):
			var name string
			name, value, hasValue = strings.Cut(w, "=")
			if opt, err = lookupPipLongOption(name); err != nil {
				return nil, err
			}
			if !opt.value && hasValue {
				return nil, fmt.Errorf("option %s does not take a value", opt.long)
			}
		case len(w) > 1 && w[0] == '-':
			if opt = lookupPipShortOption(w[:2]); opt == nil {
				return nil, fmt.Errorf("unsupported option %s", w[:2])
			}
			if len(w) > 2 {
				// optparse takes the rest of the word as the value;
				// "-r=base.txt" is read as "-r base.txt".
				value, hasValue = strings.TrimPrefix(w[2:], "="), true
			}
		default:
			continue
		}
		if opt.value && !hasValue {
			if i+1 >= len(words) {
				return nil, fmt.Errorf("option %s needs a value", opt.long)
			}
			i++
			value = words[i]
		}
		out = append(out, pipOptionValue{opt: opt, value: value})
	}
	return out, nil
}

// parseRequirementsLine reads one logical line. It returns the line's
// items and, for a line pip would reject, an error; a requirement whose
// trailing options are rejected is returned with the error.
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
	var optErr error
	if i < len(tokens) {
		// pip parses them with the full option parser and keeps only
		// --hash, --config-settings and --global-option; an include or
		// an index option after a requirement does nothing.
		_, optErr = parsePipOptions(strings.Join(tokens[i:], " "))
	}
	spec := strings.TrimSpace(strings.Join(args, " "))
	ref, err := parseNamedRequirement(spec)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		if isLocalRequirement(spec) {
			return []requirementsItem{{local: true, localPath: spec, line: line}}, optErr
		}
		return nil, optErr
	}
	ref.Line = line
	return []requirementsItem{{ref: ref, line: line}}, optErr
}

// isLocalRequirement reports a requirement pip builds from the local file
// system: a path (".", "./pkg", "../x", "/abs", "~/x", "pkg.tar.gz"), a
// file: URL, or `name @` either of those. Remote URLs and VCS references
// are not local.
func isLocalRequirement(spec string) bool {
	target := spec
	if name, ref, ok := strings.Cut(spec, "@"); ok && pep508Name.MatchString(strings.TrimSpace(strings.SplitN(name, "[", 2)[0])) {
		target = strings.TrimSpace(ref)
	}
	if i := strings.IndexAny(target, " \t;"); i >= 0 {
		target = target[:i]
	}
	if target == "" {
		return false
	}
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "file:") {
		return true
	}
	if strings.Contains(target, "://") || hasURLScheme(target) {
		return false
	}
	return looksLikeRequirementPath(target)
}

// parseRequirementsOptions reads a line of options. pip acts on one entry
// per line: an editable install (-e) if there is one, else the first -r
// include, else the first -c include; the other options configure the
// install and are ignored here, and so are leftover arguments.
func parseRequirementsOptions(text string, line int) ([]requirementsItem, error) {
	opts, err := parsePipOptions(text)
	if err != nil {
		return nil, err
	}
	var editable, include, constraint *pipOptionValue
	for i := range opts {
		o := &opts[i]
		switch {
		case o.opt.long == "--editable" && editable == nil:
			editable = o
		case o.opt.long == "--requirement" && include == nil:
			include = o
		case o.opt.long == "--constraint" && constraint == nil:
			constraint = o
		}
	}
	switch {
	case editable != nil:
		return []requirementsItem{{local: true, localPath: editable.value, line: line}}, nil
	case include != nil:
		return []requirementsItem{{include: include.value, line: line}}, nil
	case constraint != nil:
		return []requirementsItem{{include: constraint.value, constraint: true, line: line}}, nil
	}
	return nil, nil
}

// parseNamedRequirement parses one requirement specifier. It returns
// nil without error for direct references (`name @ url`), local paths,
// archives and URLs, which have no registry identity, except a URL of a
// wheel or source distribution on files.pythonhosted.org: that file is a
// PyPI release, named by its file name (see pythonHostedIdentity).
func parseNamedRequirement(s string) (*PackageRef, error) {
	if s == "" {
		return nil, nil
	}
	if looksLikeRequirementPath(s) {
		first := s
		if i := strings.IndexAny(s, " \t;"); i >= 0 {
			first = s[:i]
		}
		return pythonHostedRef("", first), nil
	}
	// pip splits the marker off at the first ";" and reads an empty one
	// as no marker ("name==1.0;"); a marker that is there must parse.
	spec, marker, _ := strings.Cut(s, ";")
	if marker = strings.TrimSpace(marker); marker != "" {
		if err := checkPEP508Marker(marker); err != nil {
			return nil, err
		}
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
		// An empty list is allowed; otherwise every comma separates two
		// names ("[a,]" and "[,a]" are rejected, as pip rejects them).
		if inner := strings.TrimSpace(rest[1:closeIdx]); inner != "" {
			for _, extra := range strings.Split(inner, ",") {
				if !pep508Name.MatchString(strings.TrimSpace(extra)) {
					return nil, fmt.Errorf("invalid extra for %s", name)
				}
			}
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}
	if strings.HasPrefix(rest, "@") {
		// Direct URL reference: no registry identity unless it names a
		// file uploaded to PyPI.
		return pythonHostedRef(name, strings.TrimSpace(rest[1:])), nil
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
	version, pinned, arbitrary, err := parseVersionSpecifier(rest)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if pinned {
		ref.Version = version
		ref.ArbitraryEquality = arbitrary
	} else {
		ref.Unpinned, ref.Constraint = true, rest
	}
	return ref, nil
}

// salvagedPin is how a requirement starts when it pins one release: a
// PEP 508 name, optional extras, an optional "(" and an == or === pin.
var (
	salvagedPin       = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)[ \t]*(?:\[[^\]]*\][ \t]*)?\(?[ \t]*(===|==)[ \t]*([^\s,;()]+)`)
	salvagedDirectRef = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)[ \t]*(?:\[[^\]]*\][ \t]*)?@[ \t]*(\S+)`)
)

// salvageExactPin reads the exact pin at the start of a requirement line
// that does not parse as a whole (a malformed marker, extras or trailing
// clause): `name==1.0`, `name[x] (===1.0`, or a direct reference to a
// files.pythonhosted.org artifact, bare or after `name @`. It returns nil
// when the start pins nothing.
func salvageExactPin(text string) *PackageRef {
	text = strings.TrimSpace(text)
	if first, _, _ := strings.Cut(text, " "); looksLikeRequirementPath(first) {
		return pythonHostedRef("", strings.TrimRight(first, ";"))
	}
	if m := salvagedDirectRef.FindStringSubmatch(text); m != nil {
		return pythonHostedRef(m[1], strings.TrimRight(m[2], ";"))
	}
	m := salvagedPin.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	version := m[3]
	if m[2] == "==" {
		if strings.HasSuffix(version, ".*") {
			return nil
		}
		if _, ok := intel.PEP440Canonical(version); !ok {
			return nil
		}
	}
	return &PackageRef{Ecosystem: intel.EcosystemPyPI, Name: m[1], Version: version, ArbitraryEquality: m[2] == "==="}
}

var specifierOperators = []string{"===", "==", "!=", "~=", "<=", ">=", "<", ">"}

var specifierVersion = regexp.MustCompile(`^[A-Za-z0-9._*+!-]+$`)

// parseVersionSpecifier validates a PEP 440 specifier set and reports
// the version when the set pins exactly one release: `==` clauses
// without a wildcard, or `===` clauses, that all agree. arbitrary is true
// when a `===` clause takes part: pip then selects only a release whose
// normalized version string equals the pin, which the matcher must
// compare the same way (intel.MatchInput.ArbitraryEquality).
func parseVersionSpecifier(spec string) (version string, pinned, arbitrary bool, err error) {
	version, pinned, err = parsePinnedSpecifier(spec)
	if pinned {
		for _, clause := range strings.Split(spec, ",") {
			if strings.HasPrefix(strings.TrimSpace(clause), "===") {
				arbitrary = true
			}
		}
	}
	return version, pinned, arbitrary, err
}

func parsePinnedSpecifier(spec string) (string, bool, error) {
	if spec == "" {
		return "", false, nil
	}
	// Repeated pins name one release when they agree: literally, or as
	// `==` clauses equal under PEP 440 ("==1.0,==1.0.0"). An `===` pin is
	// a string comparison in pip, so it only agrees with an identical
	// string. The first pin is reported.
	var pin string
	pins := 0
	agree := true
	allEqualsOp := true
	addPin := func(op, v string) {
		pins++
		if op == "===" {
			allEqualsOp = false
		}
		if pins == 1 {
			pin = v
			return
		}
		if v != pin && (!allEqualsOp || !intel.PEP440Equal(v, pin)) {
			agree = false
		}
	}
	clauses := strings.Split(spec, ",")
	if n := len(clauses); n > 1 && strings.TrimSpace(clauses[n-1]) == "" {
		// One trailing comma is allowed ("==1.0,"), as pip allows it;
		// ",," and a leading comma stay errors.
		clauses = clauses[:n-1]
	}
	for _, clause := range clauses {
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
			addPin(op, v)
		case op == "==" && !strings.HasSuffix(v, ".*"):
			if _, ok := intel.PEP440Canonical(v); !ok {
				return "", false, fmt.Errorf("invalid version %q", v)
			}
			addPin(op, v)
		}
	}
	if pins > 0 && agree {
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

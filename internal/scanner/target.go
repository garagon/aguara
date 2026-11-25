package scanner

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/text/unicode/norm"

	"github.com/garagon/aguara/internal/types"
)

// DefaultMaxFileSize is the default maximum file size (50 MiB) read from disk.
// Eligible files exceeding it cause an incomplete-scan error.
const DefaultMaxFileSize = 50 << 20

// Target represents a file to be scanned.
type Target struct {
	Path    string
	RelPath string
	Content []byte
	// OriginalContent is set by inline callers when text normalization changed
	// the bytes. Structured parsers use SourceContent to preserve key identity.
	OriginalContent []byte
	MaxFileSize     int64 // 0 means use DefaultMaxFileSize

	linesOnce  sync.Once
	lines      []string
	strOnce    sync.Once
	strContent string
	privilege  privilegeMemo
}

// SourceContent returns original syntax bytes, falling back to Content for
// disk targets and inline content that did not need normalization.
func (t *Target) SourceContent() []byte {
	if t.OriginalContent != nil {
		return t.OriginalContent
	}
	return t.Content
}

// LoadContent reads the file content into memory.
// If Content is already populated (e.g. in-memory targets), it is a no-op.
// Files larger than the configured MaxFileSize (or DefaultMaxFileSize) are rejected.
func (t *Target) LoadContent() error {
	if t.Content != nil {
		return nil
	}
	limit := t.MaxFileSize
	if limit <= 0 {
		limit = DefaultMaxFileSize
	}
	f, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > limit {
		return &fileSizeError{limit: limit}
	}
	data, err := readTargetBytes(f, limit)
	if err != nil {
		return err
	}
	t.Content = data
	return nil
}

type fileSizeError struct{ limit int64 }

func (e *fileSizeError) Error() string {
	return fmt.Sprintf("file too large: exceeds %d-byte limit", e.limit)
}

// Read one extra byte to distinguish a complete input from a truncated prefix.
// API callers may set any positive int64 limit, including MaxInt64.
func readTargetBytes(r io.Reader, limit int64) ([]byte, error) {
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(r, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &fileSizeError{limit: limit}
	}
	return data, nil
}

// StringContent returns the content as a NFKC-normalized string. The result is cached.
// NFKC normalization prevents Unicode evasion attacks (e.g. fullwidth chars).
func (t *Target) StringContent() string {
	t.strOnce.Do(func() {
		t.strContent = norm.NFKC.String(string(t.Content))
	})
	return t.strContent
}

// Lines returns the NFKC-normalized content split into lines. The result is cached.
func (t *Target) Lines() []string {
	t.linesOnce.Do(func() {
		t.lines = strings.Split(t.StringContent(), "\n")
	})
	return t.lines
}

// TargetDiscovery walks a directory and returns scannable targets.
type TargetDiscovery struct {
	IgnorePatterns    []string
	MaxFileSize       int64 // 0 means use DefaultMaxFileSize
	IgnoreProjectFile bool  // do not load target-owned .aguaraignore

	// Discover counts the entries each pattern source excluded: the
	// caller's IgnorePatterns and the patterns read from .aguaraignore.
	// A source that excluded nothing did not change the result. A
	// directory excluded whole counts as one entry.
	ExcludedByCallerPatterns int
	ExcludedByIgnoreFile     int

	rules     []*ignoreRule // compiled caller patterns, then file patterns
	bareNames map[string][]*ignoreRule
}

// Discover walks root and returns all targets, respecting .aguaraignore.
func (td *TargetDiscovery) Discover(root string) ([]*Target, error) {
	if err := td.prepare(root); err != nil {
		return nil, err
	}
	var targets []*Target
	if err := filepath.Walk(root, td.walkFunc(root, &targets)); err != nil {
		return nil, err
	}
	return targets, nil
}

// prepare compiles the caller's patterns and, unless IgnoreProjectFile is
// set, the patterns of root's .aguaraignore, and resets the counters.
func (td *TargetDiscovery) prepare(root string) error {
	td.ExcludedByCallerPatterns, td.ExcludedByIgnoreFile = 0, 0
	td.rules, td.bareNames = nil, nil
	for _, p := range td.IgnorePatterns {
		td.addRule(p, "", 0)
	}
	if !td.IgnoreProjectFile {
		if err := td.loadIgnoreFile(root); err != nil {
			return IncompleteScanError("read ignore policy", filepath.Join(root, ".aguaraignore"), "", err)
		}
	}
	return nil
}

func (td *TargetDiscovery) addRule(pattern, file string, line int) {
	r := compileIgnoreRule(pattern)
	r.file, r.line, r.caller = file, line, file == ""
	td.rules = append(td.rules, r)
	if r.bareName {
		if td.bareNames == nil {
			td.bareNames = make(map[string][]*ignoreRule)
		}
		td.bareNames[r.glob] = append(td.bareNames[r.glob], r)
	}
}

// ensureRules compiles the caller's patterns for callers that match
// without running Discover first.
func (td *TargetDiscovery) ensureRules() {
	if td.rules == nil && len(td.IgnorePatterns) > 0 {
		for _, p := range td.IgnorePatterns {
			td.addRule(p, "", 0)
		}
	}
}

// walkFunc returns the filepath.Walk callback that appends the targets it
// finds to targets, with RelPath relative to root.
func (td *TargetDiscovery) walkFunc(root string, targets *[]*Target) filepath.WalkFunc {
	limit := td.MaxFileSize
	if limit <= 0 {
		limit = DefaultMaxFileSize
	}
	return func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == ".aguara" {
				return filepath.SkipDir
			}
		}
		relPath, _ := filepath.Rel(root, path)
		// A directory pattern excludes the directory and everything in it,
		// so its contents are never read.
		if info != nil && info.IsDir() && td.prunes(relPath) {
			return filepath.SkipDir
		}
		if err != nil {
			if td.isIgnoredSubtree(relPath) || (info != nil && !info.IsDir() && (td.isIgnored(relPath) || isBinaryExt(path))) {
				return nil
			}
			return IncompleteScanError("discover target", relPath, "", err)
		}
		if info.IsDir() {
			td.noteDir(relPath)
			return nil
		}
		// skip symlinks to prevent path traversal
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		// Explicit exclusions take precedence over the file-size boundary.
		if isBinaryExt(path) {
			return nil
		}
		if td.isIgnored(relPath) {
			return nil
		}
		if info.Size() > limit {
			return IncompleteScanError("discover target", relPath, "", &fileSizeError{limit: limit})
		}
		*targets = append(*targets, &Target{
			Path:        path,
			RelPath:     relPath,
			MaxFileSize: td.MaxFileSize,
		})
		return nil
	}
}

func (td *TargetDiscovery) loadIgnoreFile(root string) error {
	path := filepath.Join(root, ".aguaraignore")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			td.addRule(line, path, n)
		}
	}
	return scanner.Err()
}

// isIgnored reports whether a pattern excludes the file at relPath. Every
// matching pattern is counted as used; the exclusion is attributed to the
// first one.
func (td *TargetDiscovery) isIgnored(relPath string) bool {
	td.ensureRules()
	var first *ignoreRule
	for _, r := range td.rules {
		if r.matchFile(relPath) {
			r.matched++
			if first == nil {
				first = r
			}
		}
	}
	if first == nil {
		return false
	}
	td.recordExclusion(first)
	return true
}

// prunes reports whether a directory pattern excludes the directory at
// relPath, counting every matching pattern as used.
func (td *TargetDiscovery) prunes(relPath string) bool {
	dir := filepath.ToSlash(relPath)
	var first *ignoreRule
	for _, r := range td.rules {
		if r.directoryForm() && r.matchDir(dir) {
			r.matched++
			if first == nil {
				first = r
			}
		}
	}
	if first == nil {
		return false
	}
	td.recordExclusion(first)
	return true
}

// noteDir records a scanned directory whose name a bare-name pattern
// spells, so an unmatched pattern can suggest the directory form.
func (td *TargetDiscovery) noteDir(relPath string) {
	if len(td.bareNames) == 0 || relPath == "." {
		return
	}
	for _, r := range td.bareNames[filepath.Base(relPath)] {
		r.dirSeen = true
	}
}

// recordExclusion attributes an exclusion to the source of r.
func (td *TargetDiscovery) recordExclusion(r *ignoreRule) {
	if r.caller {
		td.ExcludedByCallerPatterns++
	} else {
		td.ExcludedByIgnoreFile++
	}
}

// PatternUses describes every pattern the last Discover
// evaluated, caller patterns first, then the lines of the .aguaraignore in
// root (the directory the caller passed, used for the File field).
func (td *TargetDiscovery) PatternUses(root string) []types.IgnorePatternUse {
	if len(td.rules) == 0 {
		return nil
	}
	uses := make([]types.IgnorePatternUse, 0, len(td.rules))
	for _, r := range td.rules {
		u := types.IgnorePatternUse{Pattern: r.pattern, Line: r.line, Matched: r.matched, Unsupported: r.unsupported}
		if !r.caller {
			u.File = filepath.Join(root, ".aguaraignore")
		}
		if r.matched == 0 && r.dirSeen {
			u.Hint = fmt.Sprintf("a directory named %s was scanned; a bare name matches files only, write %s/ to exclude directories with that name", r.glob, r.glob)
		}
		uses = append(uses, u)
	}
	return uses
}

// Only skip an unreadable subtree when every descendant is excluded. A file
// glob matching the directory's name alone says nothing about its contents.
func (td *TargetDiscovery) isIgnoredSubtree(relPath string) bool {
	td.ensureRules()
	relPath = filepath.ToSlash(relPath)
	if relPath == "." {
		return false
	}
	for _, r := range td.rules {
		if r.unsupported != "" {
			continue
		}
		pattern := r.pattern
		excluded := pattern == "*" || pattern == "**" || (r.directoryForm() && r.matchDir(relPath))
		if prefix, recursive := strings.CutSuffix(pattern, "/**"); recursive && (relPath == prefix || strings.HasPrefix(relPath, prefix+"/")) {
			excluded = true
		}
		if excluded {
			r.matched++
			td.recordExclusion(r)
			return true
		}
	}
	return false
}

// matchGlob supports ** globs that filepath.Match does not.
// "dir/**" matches any file under dir/ at any depth.
// "**/*.yaml" matches any .yaml file at any depth.
func matchGlob(pattern, relPath string) bool {
	// Fast path: no ** means filepath.Match is sufficient
	if !strings.Contains(pattern, "**") {
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
			return true
		}
		return false
	}
	// Recursive patterns use slash-delimited segments on every platform.
	// ToSlash preserves literal backslashes in Unix filenames.
	relPath = filepath.ToSlash(relPath)

	// "prefix/**" → match anything under prefix/
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if strings.HasPrefix(relPath, prefix+"/") || relPath == prefix {
			return true
		}
	}

	// "**/<glob>" → match <glob> against every path suffix
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		// Check against full relPath and every nested suffix
		parts := strings.Split(relPath, "/")
		for i := range parts {
			candidate := strings.Join(parts[i:], "/")
			if matched, _ := filepath.Match(suffix, candidate); matched {
				return true
			}
		}
	}

	// "prefix/**/suffix" → prefix matches start, suffix matches rest
	if idx := strings.Index(pattern, "/**/"); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+4:]
		if strings.HasPrefix(relPath, prefix+"/") {
			rest := strings.TrimPrefix(relPath, prefix+"/")
			parts := strings.Split(rest, "/")
			for i := range parts {
				candidate := strings.Join(parts[i:], "/")
				if matched, _ := filepath.Match(suffix, candidate); matched {
					return true
				}
			}
		}
	}

	return false
}

var binaryExts = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".ico": true, ".svg": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".zip": true, ".tar": true,
	".gz": true, ".bz2": true, ".xz": true, ".7z": true,
	".pdf": true, ".mp3": true, ".mp4": true, ".avi": true,
	".mov": true, ".bin": true, ".o": true, ".a": true,
}

func isBinaryExt(path string) bool {
	return binaryExts[strings.ToLower(filepath.Ext(path))]
}

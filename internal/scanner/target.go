package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/unicode/norm"

	"github.com/garagon/aguara/internal/safefile"
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
	// NoFollow refuses a symbolic link as the last component of Path when
	// the content is loaded. Discovery sets it: a walked or listed entry
	// that was not a link when it was inspected must not become one.
	NoFollow bool

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
// Files larger than the configured MaxFileSize (or DefaultMaxFileSize) are
// rejected, and so is anything that is not a regular file when it is
// opened: a named pipe, socket or device is never read (see
// safefile.OpenRegular), so a file replaced after discovery cannot block
// or flood the scan.
func (t *Target) LoadContent() error {
	if t.Content != nil {
		return nil
	}
	limit := t.MaxFileSize
	if limit <= 0 {
		limit = DefaultMaxFileSize
	}
	f, info, err := safefile.OpenRegular(t.Path, !t.NoFollow)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
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
	// A source that excluded nothing did not change the result.
	ExcludedByCallerPatterns int
	ExcludedByIgnoreFile     int

	// Skipped lists the entries Discover did not return because they are
	// not regular files (see SkippedFile), in walk order. Entries that an
	// ignore pattern or the binary-extension filter excludes anyway are
	// not listed.
	Skipped []types.SkippedFile

	// Failures lists the entries Discover could not inspect or will not
	// read (an unreadable directory, a file over the size limit), in walk
	// order. The walk continues past them, and a scan of the targets is
	// incomplete. Only a failure at the root or reading .aguaraignore is
	// returned as Discover's error.
	Failures []error

	callerPatterns int    // IgnorePatterns[:callerPatterns] are the caller's
	relPrefix      string // prepended to every relative path (a changed directory walked by ScanPaths)
}

// maxIgnoreFileBytes bounds a target's .aguaraignore, like .aguara.yml.
const maxIgnoreFileBytes = 1 << 20

// skipKind names why an entry with this mode is not scanned, or returns ""
// for a regular file.
func skipKind(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return ""
	case mode&os.ModeSymlink != 0:
		return types.SkippedSymlink
	case mode&os.ModeNamedPipe != 0:
		return types.SkippedNamedPipe
	case mode&os.ModeSocket != 0:
		return types.SkippedSocket
	case mode&os.ModeDevice != 0:
		return types.SkippedDevice
	default:
		return types.SkippedIrregular
	}
}

// SortSkipped orders skipped entries by path, then kind.
func SortSkipped(skipped []types.SkippedFile) {
	sort.Slice(skipped, func(i, j int) bool {
		if skipped[i].Path != skipped[j].Path {
			return skipped[i].Path < skipped[j].Path
		}
		return skipped[i].Kind < skipped[j].Kind
	})
}

// Discover walks root and returns all targets, respecting .aguaraignore.
func (td *TargetDiscovery) Discover(root string) ([]*Target, error) {
	td.callerPatterns = len(td.IgnorePatterns)
	if !td.IgnoreProjectFile {
		if err := td.loadIgnoreFile(root); err != nil {
			return nil, IncompleteScanError("read ignore policy", filepath.Join(root, ".aguaraignore"), "", err)
		}
	}

	limit := td.MaxFileSize
	if limit <= 0 {
		limit = DefaultMaxFileSize
	}

	var targets []*Target
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == ".aguara" {
				return filepath.SkipDir
			}
		}
		relPath, _ := filepath.Rel(root, path)
		if td.relPrefix != "" {
			relPath = filepath.Join(td.relPrefix, relPath)
		}
		if err != nil {
			if td.isIgnoredSubtree(relPath) || (info != nil && !info.IsDir() && (td.isIgnored(relPath) || isBinaryExt(path))) {
				return nil
			}
			if path == root {
				return IncompleteScanError("discover target", relPath, "", err)
			}
			// Record the entry and keep walking (nil skips an unreadable
			// directory's contents): the scan of the other files is then
			// reported as incomplete instead of discarded.
			td.Failures = append(td.Failures, IncompleteScanError("discover target", relPath, "", err))
			return nil
		}
		if info.IsDir() {
			return nil
		}
		// Symbolic links (never followed, to prevent path traversal), named
		// pipes, sockets and devices hold no file content to scan, and
		// opening a pipe or device can block or never end. They are listed
		// as skipped unless an exclusion covers them anyway; as before, a
		// pattern that matches one is not counted as an exclusion.
		if kind := skipKind(info.Mode()); kind != "" {
			if !isBinaryExt(path) && !td.matchesIgnore(relPath) {
				td.Skipped = append(td.Skipped, types.SkippedFile{Path: relPath, Kind: kind})
			}
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
			td.Failures = append(td.Failures, IncompleteScanError("read target", relPath, "", &fileSizeError{limit: limit}))
			return nil
		}
		targets = append(targets, &Target{
			Path:        path,
			RelPath:     relPath,
			MaxFileSize: td.MaxFileSize,
			NoFollow:    true,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return targets, nil
}

// loadIgnoreFile reads the target's .aguaraignore. A link to a regular file
// is followed, as before; a named pipe, device or other special file is an
// error rather than a read that can block or never end.
func (td *TargetDiscovery) loadIgnoreFile(root string) error {
	data, err := safefile.ReadRegular(filepath.Join(root, ".aguaraignore"), true, maxIgnoreFileBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			td.IgnorePatterns = append(td.IgnorePatterns, line)
		}
	}
	return scanner.Err()
}

func (td *TargetDiscovery) isIgnored(relPath string) bool {
	for i, pattern := range td.IgnorePatterns {
		if matchGlob(pattern, relPath) {
			td.recordExclusion(i)
			return true
		}
	}
	return false
}

// matchesIgnore is isIgnored without counting the exclusion.
func (td *TargetDiscovery) matchesIgnore(relPath string) bool {
	for _, pattern := range td.IgnorePatterns {
		if matchGlob(pattern, relPath) {
			return true
		}
	}
	return false
}

// recordExclusion attributes an exclusion to the source of pattern i.
func (td *TargetDiscovery) recordExclusion(i int) {
	if i < td.callerPatterns {
		td.ExcludedByCallerPatterns++
	} else {
		td.ExcludedByIgnoreFile++
	}
}

// Only skip an unreadable subtree when every descendant is excluded. A file
// glob matching the directory's name alone says nothing about its contents.
func (td *TargetDiscovery) isIgnoredSubtree(relPath string) bool {
	relPath = filepath.ToSlash(relPath)
	if relPath == "." {
		return false
	}
	for i, pattern := range td.IgnorePatterns {
		if pattern == "*" || pattern == "**" {
			td.recordExclusion(i)
			return true
		}
		prefix, recursive := strings.CutSuffix(pattern, "/**")
		if recursive && (relPath == prefix || strings.HasPrefix(relPath, prefix+"/")) {
			td.recordExclusion(i)
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

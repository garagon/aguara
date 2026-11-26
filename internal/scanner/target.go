package scanner

import (
	"bufio"
	"bytes"
	"errors"
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
	// A source that excluded nothing did not change the result. A
	// directory excluded whole counts as one entry.
	ExcludedByCallerPatterns int
	ExcludedByIgnoreFile     int

	// Skipped lists the entries discovery found and did not return, in
	// walk order (see types.SkippedFile for the kinds): symbolic links,
	// named pipes, sockets and devices found by a walk or named directly;
	// paths named directly inside the directories a walk always skips
	// (.git, node_modules, .aguara) or excluded by an ignore pattern; and
	// files this invocation writes (OutputFiles). Entries a walk finds that
	// an ignore pattern or the binary-extension filter excludes anyway are
	// not listed. NamedSkipped is the part of Skipped that DiscoverPaths
	// was given by name.
	Skipped      []types.SkippedFile
	NamedSkipped []types.SkippedFile

	// Failures lists the entries discovery could not inspect or will not
	// read (an unreadable directory, a file over the size limit, a path
	// named directly that does not exist or is not a regular file or a
	// directory), in walk order. Discovery continues past them, and a scan
	// of the targets is incomplete. Only a failure at the root, reading
	// .aguaraignore, or a named path outside the root is returned as an
	// error.
	Failures []error

	// OutputFiles are files the current invocation writes, such as its
	// report or baseline. Discovery never returns them, so a report left
	// in the scanned directory by an earlier run of the same command is
	// not scanned and cannot change the result. Other files, including
	// other reports, are scanned as usual. SkippedOutputs lists the ones
	// that were present and skipped (they are also in Skipped).
	OutputFiles    []string
	SkippedOutputs []string

	rules       []*ignoreRule // compiled caller patterns, then file patterns
	bareNames   map[string][]*ignoreRule
	outputs     map[string]bool // resolved OutputFiles
	outputBases map[string]bool // their base names, a cheap first check
	prepared    bool

	linkRoot string // the resolved scan root links are classified against
	entries  int    // entries the last walk saw below its start, read or not
}

// entryAction is what a walk does with one entry. The walk and
// linkResolution both use classify, so a link is called inside only for
// content the walk itself reads.
type entryAction int

const (
	actionDescend  entryAction = iota // a directory the walk enters
	actionSkipDir                     // a directory the walk never enters (.git, node_modules, .aguara)
	actionPruned                      // a directory an ignore pattern excludes whole
	actionRead                        // a regular file the walk reads
	actionSpecial                     // a link, named pipe, socket or device: never read, listed as skipped
	actionExcluded                    // a file a binary extension or an ignore pattern excludes
	actionOutput                      // a file this invocation writes
	actionTooLarge                    // a regular file over the size limit: not read, a failure
)

// sizeLimit is the largest file the walk reads.
func (td *TargetDiscovery) sizeLimit() int64 {
	if td.MaxFileSize <= 0 {
		return DefaultMaxFileSize
	}
	return td.MaxFileSize
}

// classify says what a walk does with the entry at path, relPath relative
// to the scan root, whose Lstat information is info. record counts a
// matching ignore pattern as used and as an exclusion, as the walk does;
// link resolution classifies without counting. The checks run in the
// walk's order: a directory the walk never enters, a directory pattern,
// then for a file its type, binary extension, output file, ignore pattern
// and size.
func (td *TargetDiscovery) classify(path, relPath string, info os.FileInfo, record bool) entryAction {
	if info.IsDir() {
		switch info.Name() {
		case ".git", "node_modules", ".aguara":
			return actionSkipDir
		}
		if td.prunes(relPath, record) {
			return actionPruned
		}
		return actionDescend
	}
	if SkipKind(info.Mode()) != "" {
		return actionSpecial
	}
	// Explicit exclusions take precedence over the file-size boundary.
	if isBinaryExt(path) {
		return actionExcluded
	}
	if td.isOutputPath(path) {
		return actionOutput
	}
	if td.isIgnoredFile(relPath, false, record) {
		return actionExcluded
	}
	if info.Size() > td.sizeLimit() {
		return actionTooLarge
	}
	return actionRead
}

// linkResolution says where the symbolic link at path resolves relative to
// root (the resolved scan root): to content a walk of root reads (inside),
// to a part of root a walk does not read (excluded: a file with a binary
// extension, under .git, node_modules or .aguara, covered by an ignore
// pattern, written by this invocation, over the size limit or not a
// regular file, or a directory the walk does not enter or whose content an
// ignore pattern covers), outside root, or nowhere (dangling). It resolves
// links and stats entries; no file content is read.
func (td *TargetDiscovery) linkResolution(root, path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return types.LinkDangling
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return types.LinkOutside
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return types.LinkDangling
	}
	if rel != "." {
		// Every directory on the way must be one the walk enters. The
		// resolved path holds no links, so each step is a directory.
		parts := strings.Split(rel, string(filepath.Separator))
		for i := range parts[:len(parts)-1] {
			dirRel := filepath.Join(parts[:i+1]...)
			dirPath := filepath.Join(root, dirRel)
			dirInfo, err := os.Lstat(dirPath)
			if err != nil {
				return types.LinkDangling
			}
			if td.classify(dirPath, dirRel, dirInfo, false) != actionDescend {
				return types.LinkExcluded
			}
		}
	}
	switch action := td.classify(resolved, rel, info, false); {
	case action == actionRead:
		return types.LinkInside
	case action == actionDescend && !td.ignoredSubtree(rel, false):
		return types.LinkInside
	default:
		return types.LinkExcluded
	}
}

// resolvedRoot returns path with symbolic links resolved, or path itself
// when it cannot be resolved.
func resolvedRoot(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// maxIgnoreFileBytes bounds a target's .aguaraignore, like .aguara.yml.
const maxIgnoreFileBytes = 1 << 20

// SkipKind names why an entry with this mode is not scanned, or returns ""
// for a regular file.
func SkipKind(mode os.FileMode) string {
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
	if err := td.prepare(root); err != nil {
		return nil, err
	}
	if td.linkRoot == "" {
		td.linkRoot = resolvedRoot(root)
	}
	var targets []*Target
	if err := filepath.Walk(root, td.walkFunc(root, root, &targets)); err != nil {
		return nil, err
	}
	return targets, nil
}

// prepare compiles the caller's patterns and, unless IgnoreProjectFile is
// set, the patterns of root's .aguaraignore, and resets the counters.
func (td *TargetDiscovery) prepare(root string) error {
	td.ExcludedByCallerPatterns, td.ExcludedByIgnoreFile = 0, 0
	td.rules, td.bareNames = nil, nil
	td.SkippedOutputs, td.outputs, td.outputBases = nil, nil, nil
	td.prepared = true
	for _, p := range td.IgnorePatterns {
		td.addRule(p, "", 0)
	}
	for _, p := range td.OutputFiles {
		if resolved, ok := resolveOutputFile(p); ok {
			if td.outputs == nil {
				td.outputs, td.outputBases = make(map[string]bool), make(map[string]bool)
			}
			td.outputs[resolved] = true
			td.outputBases[filepath.Base(resolved)] = true
		}
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

// ensureRules compiles the caller's patterns and output files for callers
// that match without running Discover first.
func (td *TargetDiscovery) ensureRules() {
	if td.prepared {
		return
	}
	td.prepared = true
	for _, p := range td.IgnorePatterns {
		td.addRule(p, "", 0)
	}
	for _, p := range td.OutputFiles {
		if resolved, ok := resolveOutputFile(p); ok {
			if td.outputs == nil {
				td.outputs, td.outputBases = make(map[string]bool), make(map[string]bool)
			}
			td.outputs[resolved] = true
			td.outputBases[filepath.Base(resolved)] = true
		}
	}
}

// walkFunc returns the filepath.Walk callback for a walk that starts at
// start, inside root, and appends the targets it finds to targets, with
// RelPath relative to root. An entry the walk cannot inspect or will not
// read is recorded in Failures and the walk continues past it; only a
// failure at start ends it.
func (td *TargetDiscovery) walkFunc(root, start string, targets *[]*Target) filepath.WalkFunc {
	td.entries = 0
	linkRoot := td.linkRoot
	if linkRoot == "" {
		linkRoot = resolvedRoot(root)
	}
	return func(path string, info os.FileInfo, err error) error {
		if path != start {
			td.entries++
		}
		relPath, _ := filepath.Rel(root, path)
		if info != nil && info.IsDir() {
			// A directory a walk never enters, or one a directory pattern
			// excludes with everything in it, is never read.
			switch td.classify(path, relPath, info, true) {
			case actionSkipDir, actionPruned:
				return filepath.SkipDir
			}
		}
		if err != nil {
			if td.isIgnoredSubtree(relPath) || (info != nil && !info.IsDir() && (td.isIgnored(relPath) || isBinaryExt(path))) {
				return nil
			}
			if path == start {
				return IncompleteScanError("discover target", relPath, "", err)
			}
			// Record the entry and keep walking (nil skips an unreadable
			// directory's contents): the scan of the other files is then
			// reported as incomplete instead of discarded.
			td.Failures = append(td.Failures, IncompleteScanError("discover target", relPath, "", err))
			return nil
		}
		if info.IsDir() {
			td.noteDir(relPath)
			return nil
		}
		switch td.classify(path, relPath, info, true) {
		case actionSpecial:
			// Symbolic links (never followed, to prevent path traversal),
			// named pipes, sockets and devices hold no file content to scan,
			// and opening a pipe or device can block or never end. They are
			// listed as skipped unless an exclusion covers them anyway; as
			// before, a pattern that matches one is not counted as an
			// exclusion.
			if !isBinaryExt(path) && !td.isIgnoredFile(relPath, false, false) {
				kind := SkipKind(info.Mode())
				entry := types.SkippedFile{Path: relPath, Kind: kind}
				if kind == types.SkippedSymlink {
					entry.Resolves = td.linkResolution(linkRoot, path)
				}
				td.Skipped = append(td.Skipped, entry)
			}
			return nil
		case actionOutput:
			td.skipOutput(path, relPath)
			return nil
		case actionExcluded:
			return nil
		case actionTooLarge:
			td.Failures = append(td.Failures, IncompleteScanError("read target", relPath, "", &fileSizeError{limit: td.sizeLimit()}))
			return nil
		}
		*targets = append(*targets, &Target{
			Path:        path,
			RelPath:     relPath,
			MaxFileSize: td.MaxFileSize,
			NoFollow:    true,
		})
		return nil
	}
}

// DiscoverPaths returns the targets for several files and directories
// scanned as one scan rooted at root, which must be a directory containing
// every path. RelPath is relative to root, and the caller's patterns and
// root's .aguaraignore apply to every path, files named directly included,
// as they would in a Discover of root; a directory is walked the way
// Discover walks root. A path reached more than once is returned once.
//
// A path named directly that a Discover of root would not read is listed
// in Skipped and NamedSkipped: a symbolic link (not followed, with where
// it resolves), a path inside a directory a walk always skips (.git,
// node_modules, .aguara), a path an ignore pattern excludes and a file
// this invocation writes. A path that does not exist, is not a regular
// file or a directory, or is over the size limit is a failure: the other
// paths are still returned and a scan of them is incomplete. A path that
// resolves outside root is an error.
func (td *TargetDiscovery) DiscoverPaths(root string, paths []string) ([]*Target, error) {
	td.Skipped, td.NamedSkipped, td.Failures = nil, nil, nil
	realRoot, err := filepath.Abs(root)
	if err == nil {
		realRoot, err = filepath.EvalSymlinks(realRoot)
	}
	if err != nil {
		return nil, IncompleteScanError("resolve root", root, "", err)
	}
	if err := td.prepare(realRoot); err != nil {
		return nil, err
	}
	td.linkRoot = realRoot

	var targets []*Target
	seen := make(map[string]bool)
	var walked []string
	skip := func(entry types.SkippedFile) {
		td.Skipped = append(td.Skipped, entry)
		td.NamedSkipped = append(td.NamedSkipped, entry)
	}
	for _, p := range paths {
		full, rel, info, err := resolveInRoot(realRoot, root, p)
		if err != nil {
			if errors.Is(err, errOutsideRoot) {
				return nil, err
			}
			td.Failures = append(td.Failures, err)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			skip(types.SkippedFile{Path: rel, Kind: types.SkippedSymlink, Resolves: td.linkResolution(realRoot, full)})
			continue
		}
		if dir := alwaysSkippedParent(rel, info.IsDir()); dir != "" {
			skip(types.SkippedFile{Path: rel, Kind: types.SkippedInSkippedDir})
			continue
		}
		if info.IsDir() {
			if coveredBy(walked, rel) {
				continue
			}
			if td.excludedDir(rel) {
				skip(types.SkippedFile{Path: rel, Kind: types.SkippedIgnored})
				continue
			}
			walked = append(walked, rel)
			start := len(targets)
			if err := filepath.Walk(full, td.walkFunc(realRoot, full, &targets)); err != nil {
				td.Failures = append(td.Failures, err)
				continue
			}
			kept := targets[:start]
			for _, t := range targets[start:] {
				if !seen[t.RelPath] {
					seen[t.RelPath] = true
					kept = append(kept, t)
				}
			}
			targets = kept
			continue
		}
		if !info.Mode().IsRegular() {
			// A named pipe or device named directly is never opened.
			td.Failures = append(td.Failures, IncompleteScanError("inspect target", rel, "", &safefile.NotRegularError{Path: p, Mode: info.Mode()}))
			continue
		}
		if seen[rel] || isBinaryExt(full) {
			continue
		}
		if td.isOutputPath(full) {
			seen[rel] = true
			td.skipOutput(full, rel)
			td.NamedSkipped = append(td.NamedSkipped, td.Skipped[len(td.Skipped)-1])
			continue
		}
		if td.isIgnoredNamed(rel) {
			seen[rel] = true
			skip(types.SkippedFile{Path: rel, Kind: types.SkippedIgnored})
			continue
		}
		if info.Size() > td.sizeLimit() {
			td.Failures = append(td.Failures, IncompleteScanError("read target", rel, "", &fileSizeError{limit: td.sizeLimit()}))
			continue
		}
		seen[rel] = true
		targets = append(targets, &Target{Path: full, RelPath: rel, MaxFileSize: td.MaxFileSize, NoFollow: true})
	}
	return targets, nil
}

// errOutsideRoot marks a named path outside the scan root, a usage error
// rather than a part of the scan that could not be read.
var errOutsideRoot = errors.New("outside the scan root")

// alwaysSkippedParent returns the name of the directory a walk always
// skips (.git, node_modules, .aguara) that rel is in, or that rel is when
// it names a directory, or "".
func alwaysSkippedParent(rel string, isDir bool) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if !isDir {
		parts = parts[:len(parts)-1]
	}
	for _, part := range parts {
		if part == ".git" || part == "node_modules" || part == ".aguara" {
			return part
		}
	}
	return ""
}

// resolveInRoot locates p (as the user typed it, relative to the working
// directory) inside realRoot, the resolved scan root. p itself is not
// followed when it is a symbolic link: its directory is resolved instead
// and the link itself returned, for the caller to skip. Otherwise the path
// is resolved, so it cannot reach outside root through a linked parent
// directory. It returns the path (resolved, or the link), the path
// relative to realRoot and p's own file information; a path outside root
// is an error matching errOutsideRoot.
func resolveInRoot(realRoot, root, p string) (string, string, os.FileInfo, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return "", "", nil, IncompleteScanError("inspect target", p, "", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", "", nil, IncompleteScanError("inspect target", p, "", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
		if err != nil {
			return "", "", nil, IncompleteScanError("inspect target", p, "", err)
		}
		abs = filepath.Join(dir, filepath.Base(abs))
	} else if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return "", "", nil, IncompleteScanError("inspect target", p, "", err)
	}
	rel, err := filepath.Rel(realRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", nil, fmt.Errorf("%s is %w %s", p, errOutsideRoot, root)
	}
	return abs, rel, info, nil
}

// coveredBy reports whether rel is one of dirs or inside one of them.
func coveredBy(dirs []string, rel string) bool {
	for _, d := range dirs {
		if d == "." || rel == d || strings.HasPrefix(rel, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// loadIgnoreFile reads the target's .aguaraignore, at most 1 MiB. A link
// to a regular file is followed, as before; a named pipe, device or other
// special file is an error rather than a read that can block or never end.
func (td *TargetDiscovery) loadIgnoreFile(root string) error {
	path := filepath.Join(root, ".aguaraignore")
	data, err := safefile.ReadRegular(path, true, maxIgnoreFileBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			td.addRule(line, path, n)
		}
	}
	return scanner.Err()
}

// isIgnored reports whether a pattern excludes the file at relPath, which
// a walk reached, so its parent directories were already checked (pruned).
// Every matching pattern is counted as used; the exclusion is attributed
// to the first one.
func (td *TargetDiscovery) isIgnored(relPath string) bool {
	return td.isIgnoredFile(relPath, false, true)
}

// isIgnoredNamed is isIgnored for a file named directly, whose parent
// directories no walk has checked.
func (td *TargetDiscovery) isIgnoredNamed(relPath string) bool {
	return td.isIgnoredFile(relPath, true, true)
}

// isIgnoredFile reports whether a pattern excludes the file at relPath.
// record counts every matching pattern as used and the exclusion against
// the first one; without it nothing is counted.
func (td *TargetDiscovery) isIgnoredFile(relPath string, parents, record bool) bool {
	td.ensureRules()
	var first *ignoreRule
	for _, r := range td.rules {
		if r.matchFile(relPath, parents) {
			if !record {
				return true
			}
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
// relPath. record counts every matching pattern as used and the exclusion
// against the first one.
func (td *TargetDiscovery) prunes(relPath string, record bool) bool {
	td.ensureRules()
	dir := filepath.ToSlash(relPath)
	var first *ignoreRule
	for _, r := range td.rules {
		if r.directoryForm() && r.matchDir(dir) {
			if !record {
				return true
			}
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

// excludedDir reports whether a directory pattern excludes relPath or one
// of its parent directories, for a directory named directly instead of
// reached by a walk from the root.
func (td *TargetDiscovery) excludedDir(relPath string) bool {
	dir := filepath.ToSlash(relPath)
	for i := 0; i <= len(dir); i++ {
		if (i == len(dir) || dir[i] == '/') && td.prunes(dir[:i], true) {
			return true
		}
	}
	return false
}

// resolveOutputFile returns the absolute path of an output file with its
// directory resolved, the form discovery compares against. The file need
// not exist yet; its directory must.
func resolveOutputFile(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", false
	}
	return filepath.Join(dir, filepath.Base(abs)), true
}

// isOutputPath reports whether path is one of the files this invocation
// writes.
func (td *TargetDiscovery) isOutputPath(path string) bool {
	td.ensureRules()
	if len(td.outputs) == 0 || !td.outputBases[filepath.Base(path)] {
		return false
	}
	resolved, ok := resolveOutputFile(path)
	return ok && td.outputs[resolved]
}

// skipOutput records a file this invocation writes that discovery found
// and did not return.
func (td *TargetDiscovery) skipOutput(path, relPath string) {
	td.SkippedOutputs = append(td.SkippedOutputs, path)
	td.Skipped = append(td.Skipped, types.SkippedFile{Path: relPath, Kind: types.SkippedOutputFile})
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

// PatternUses describes every pattern the last Discover or DiscoverPaths
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

// isIgnoredSubtree reports whether an ignore pattern excludes every entry
// under the directory relPath, counting the exclusion: only then is an
// unreadable subtree skipped. A file glob matching the directory's name
// alone says nothing about its contents.
func (td *TargetDiscovery) isIgnoredSubtree(relPath string) bool {
	return td.ignoredSubtree(relPath, true)
}

// ignoredSubtree is isIgnoredSubtree; record counts the exclusion, and
// link resolution, which only asks whether a link to the directory reaches
// anything a walk reads, does not.
func (td *TargetDiscovery) ignoredSubtree(relPath string, record bool) bool {
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
			if record {
				r.matched++
				td.recordExclusion(r)
			}
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

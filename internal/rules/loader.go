package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/garagon/aguara/internal/safefile"
)

// LoadFromFS loads rules from an embed.FS or any fs.FS.
func LoadFromFS(fsys fs.FS) ([]RawRule, error) {
	var all []RawRule
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		rules, err := parseMultiDocYAML(data, path)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		all = append(all, rules...)
		return nil
	})
	return all, err
}

// maxRuleFileSize is the maximum size for a single YAML rule file (1 MB).
const maxRuleFileSize = 1 << 20

// Bounds on one rules directory. Real rule packs hold tens to hundreds of
// files a few levels deep; these limits only stop a directory that is not
// a rule pack at all (a home directory, a filesystem root) or one built to
// exhaust the scanner. Variables so tests can lower them.
var (
	// maxRuleDirEntries bounds the files and directories walked.
	maxRuleDirEntries = 100000
	// maxRuleFiles bounds the YAML rule files loaded.
	maxRuleFiles = 10000
	// maxRuleBytes bounds the total size of the YAML rule files loaded.
	maxRuleBytes int64 = 128 << 20
	// maxRuleDirDepth bounds how many directories deep below the rules
	// directory rule files are looked for.
	maxRuleDirDepth = 32
)

// SkippedFile is a rule file LoadFromDir did not load.
type SkippedFile struct {
	Path   string
	Reason string
}

// LoadFromDir loads rules from a directory on disk. Unknown YAML keys are
// rejected.
//
// A symlinked dir is resolved and its target is walked; filepath.Walk does
// not follow a symlinked root, so such a directory used to load nothing.
// Inside the directory, a symlinked YAML file is read from its target (and
// the size limit applies to the target), while a symlinked subdirectory is
// not followed. A rule file must resolve to a regular file: a named pipe,
// socket or device is not read, because reading it could block or never
// end. Rule files are read through a bounded reader, so the 1 MB limit holds
// whatever their reported size.
//
// The walk is bounded: at most 100,000 files and directories, 10,000 rule
// files and 128 MiB of rule files in total, and rule files at most 32
// directories below dir. Files over 1 MB, rule files that are not regular files,
// symlinked subdirectories, directories below the depth limit and a walk
// stopped at a limit are returned in skipped so the caller can report them
// instead of losing the rules silently.
func LoadFromDir(dir string) (rules []RawRule, skipped []SkippedFile, err error) {
	root := dir
	if info, lerr := os.Lstat(dir); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, rerr := filepath.EvalSymlinks(dir)
		if rerr != nil {
			return nil, nil, fmt.Errorf("resolving symbolic link %s: %w", dir, rerr)
		}
		root = resolved
	}
	entries, files := 0, 0
	var loaded int64
	stop := func(reason string) error {
		skipped = append(skipped, SkippedFile{Path: dir, Reason: reason + "; the rules directory was not loaded completely"})
		return filepath.SkipAll
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > maxRuleDirEntries {
			return stop(fmt.Sprintf("more than %d files and directories", maxRuleDirEntries))
		}
		if info.IsDir() && path != root && ruleDirDepth(root, path) > maxRuleDirDepth {
			skipped = append(skipped, SkippedFile{
				Path:   path,
				Reason: fmt.Sprintf("directory is more than %d levels below the rules directory; rules under it were not loaded", maxRuleDirDepth),
			})
			return filepath.SkipDir
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, serr := os.Stat(path)
			if serr != nil {
				return fmt.Errorf("reading %s: %w", path, serr)
			}
			if target.IsDir() {
				skipped = append(skipped, SkippedFile{
					Path:   path,
					Reason: "symbolic link to a directory is not followed; rules under it were not loaded (pass the target directory itself)",
				})
				return nil
			}
			info = target
		}
		if info.IsDir() || !isYAML(path) {
			return nil
		}
		if !info.Mode().IsRegular() {
			skipped = append(skipped, notRegularRuleFile(path, info.Mode()))
			return nil
		}
		if info.Size() > maxRuleFileSize {
			skipped = append(skipped, oversizedRuleFile(path, info.Size()))
			return nil
		}
		files++
		if files > maxRuleFiles {
			return stop(fmt.Sprintf("more than %d rule files", maxRuleFiles))
		}
		data, err := safefile.ReadRegular(path, true, maxRuleFileSize)
		if err != nil {
			var notRegular *safefile.NotRegularError
			switch {
			case errors.As(err, &notRegular):
				skipped = append(skipped, notRegularRuleFile(path, notRegular.Mode))
				return nil
			case errors.Is(err, safefile.ErrTooLarge):
				skipped = append(skipped, oversizedRuleFile(path, -1))
				return nil
			}
			return fmt.Errorf("reading %s: %w", path, err)
		}
		loaded += int64(len(data))
		if loaded > maxRuleBytes {
			return stop(fmt.Sprintf("rule files over %d bytes in total", maxRuleBytes))
		}
		parsed, err := parseMultiDocYAML(data, path)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		rules = append(rules, parsed...)
		return nil
	})
	return rules, skipped, err
}

func notRegularRuleFile(path string, mode os.FileMode) SkippedFile {
	return SkippedFile{
		Path:   path,
		Reason: fmt.Sprintf("rule file is a %s, not a regular file; it was not read", safefile.DescribeMode(mode)),
	}
}

// oversizedRuleFile reports a rule file over the size limit; size < 0 means
// the size was found while reading.
func oversizedRuleFile(path string, size int64) SkippedFile {
	reason := fmt.Sprintf("rule file is over the %d-byte limit; its rules were not loaded", maxRuleFileSize)
	if size >= 0 {
		reason = fmt.Sprintf("rule file is %d bytes, over the %d-byte limit; its rules were not loaded", size, maxRuleFileSize)
	}
	return SkippedFile{Path: path, Reason: reason}
}

// ruleDirDepth counts the directories between root and dir.
func ruleDirDepth(root, dir string) int {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/") + 1
}

// UniqueDirs returns dirs without empty entries and without repeats of a
// directory already listed, keeping the order of first appearance.
// Directories are compared by absolute path with symbolic links resolved
// (when resolution succeeds), so a relative path, an absolute path and a
// symlink to the same directory count once. Loading the same directory
// twice would define every rule in it twice.
func UniqueDirs(dirs []string) []string {
	var out []string
	seen := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		key, err := filepath.Abs(dir)
		if err != nil {
			key = filepath.Clean(dir)
		}
		if resolved, err := filepath.EvalSymlinks(key); err == nil {
			key = resolved
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dir)
	}
	return out
}

// parseMultiDocYAML splits a YAML file on "---" boundaries and parses each
// document. Empty documents are skipped. A document with content but no id
// is kept so that Compile reports it, rather than dropping the rule unseen.
func parseMultiDocYAML(data []byte, source string) ([]RawRule, error) {
	var rules []RawRule
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	for document := 1; ; document++ {
		var raw RawRule
		err := decoder.Decode(&raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if raw.ID == "" && reflect.ValueOf(raw).IsZero() {
			continue
		}
		raw.Source = source
		raw.Document = document
		rules = append(rules, raw)
	}
	return rules, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

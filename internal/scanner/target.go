package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxFileSize is the maximum file size (50 MB) that will be scanned.
// Files larger than this are silently skipped during discovery.
const maxFileSize = 50 << 20

// Target represents a file to be scanned.
type Target struct {
	Path    string
	RelPath string
	Content []byte
}

// LoadContent reads the file content into memory.
// If Content is already populated (e.g. in-memory targets), it is a no-op.
// Files larger than maxFileSize are rejected as defense-in-depth.
func (t *Target) LoadContent() error {
	if t.Content != nil {
		return nil
	}
	info, err := os.Stat(t.Path)
	if err != nil {
		return err
	}
	if info.Size() > maxFileSize {
		return fmt.Errorf("file too large: %s (%d bytes, max %d)", t.Path, info.Size(), maxFileSize)
	}
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return err
	}
	t.Content = data
	return nil
}

// Lines returns the content split into lines.
func (t *Target) Lines() []string {
	return strings.Split(string(t.Content), "\n")
}

// TargetDiscovery walks a directory and returns scannable targets.
type TargetDiscovery struct {
	IgnorePatterns []string
}

// Discover walks root and returns all targets, respecting .aguaraignore.
func (td *TargetDiscovery) Discover(root string) ([]*Target, error) {
	td.loadIgnoreFile(root)

	var targets []*Target
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == ".aguara" {
				return filepath.SkipDir
			}
			return nil
		}
		// skip binary/large files by extension
		if isBinaryExt(path) {
			return nil
		}
		// skip oversized files
		if info.Size() > maxFileSize {
			return nil
		}
		relPath, _ := filepath.Rel(root, path)
		if td.isIgnored(relPath) {
			return nil
		}
		targets = append(targets, &Target{
			Path:    path,
			RelPath: relPath,
		})
		return nil
	})
	return targets, err
}

func (td *TargetDiscovery) loadIgnoreFile(root string) {
	f, err := os.Open(filepath.Join(root, ".aguaraignore"))
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			td.IgnorePatterns = append(td.IgnorePatterns, line)
		}
	}
}

func (td *TargetDiscovery) isIgnored(relPath string) bool {
	for _, pattern := range td.IgnorePatterns {
		if matchGlob(pattern, relPath) {
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

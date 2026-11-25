package scanner

import (
	"path"
	"path/filepath"
	"strings"
)

// ignoreRule is one compiled ignore pattern from the caller or from a
// .aguaraignore file.
//
// Every pattern is first evaluated with matchGlob, the matcher of earlier
// releases, so a pattern keeps matching every file it matched before. The
// gitignore forms that matched nothing there are added on top:
//
//   - a trailing slash ("dist/") matches a directory and everything under
//     it, at any depth unless the pattern also has a leading slash or a
//     slash in the middle;
//   - a leading slash or "./" ("/build", "./build/") anchors the pattern
//     to the scan root, where it matches a file or a directory;
//   - a literal path with a slash in it ("docs/internal") also covers the
//     directory it names, which cannot also be a file;
//   - "**" alone matches everything.
//
// A bare name without a slash ("vendor", "*.log") keeps matching file
// names only. Widening it to directories would make an existing entry for
// a build output such as "aguara" also hide a source directory such as
// cmd/aguara/. Character classes accept gitignore's [!...] negation as
// well as [^...]. A pattern starting with "!" (gitignore negation) is not
// supported and never matches.
type ignoreRule struct {
	pattern string // as written
	file    string // .aguaraignore it came from; "" for caller patterns
	line    int
	caller  bool

	legacy      string // pattern given to matchGlob; "" when it cannot match
	glob        string // slash-separated pattern for the directory forms
	dirOnly     bool   // trailing slash
	anchored    bool   // leading slash or "./"
	literalPath bool   // no glob characters and a slash in the middle
	matchAll    bool   // "**" or "/**"
	bareName    bool   // literal name without any slash (for the hint)
	unsupported string

	matched int
	dirSeen bool // a scanned directory has bareName's name
}

func compileIgnoreRule(pattern string) *ignoreRule {
	r := &ignoreRule{pattern: pattern}
	if strings.HasPrefix(pattern, "!") {
		r.unsupported = "negation (!) is not supported; the pattern has no effect"
		return r
	}
	p := translateNegatedClasses(pattern)
	r.legacy = p

	g := filepath.ToSlash(p)
	if rest, ok := strings.CutPrefix(g, "./"); ok {
		g, r.anchored = rest, true
	}
	if strings.HasPrefix(g, "/") {
		g, r.anchored = strings.TrimLeft(g, "/"), true
	}
	if strings.HasSuffix(g, "/") {
		g, r.dirOnly = strings.TrimRight(g, "/"), true
	}
	if g == "" {
		// "/" or "./" names the scan root itself, which gitignore never
		// matches either.
		r.anchored, r.dirOnly = false, false
		return r
	}
	r.glob = g
	if g == "**" && !r.dirOnly {
		// "**" and "/**" match everything. "**/" names every directory,
		// so it leaves the files at the scan root, as in gitignore.
		r.matchAll = true
		return r
	}
	literal := !strings.ContainsAny(g, `*?[\`)
	r.literalPath = literal && !r.anchored && !r.dirOnly && strings.Contains(g, "/")
	r.bareName = literal && !r.anchored && !r.dirOnly && !strings.Contains(g, "/")
	return r
}

// directoryForm reports whether the rule can match a directory, and so
// exclude a whole subtree.
func (r *ignoreRule) directoryForm() bool {
	return r.matchAll || r.dirOnly || r.anchored || r.literalPath
}

// matchFile reports whether the rule excludes the file at rel, a path
// relative to the scan root in the native separator. Directory forms
// match when the file itself or one of its parent directories matches.
func (r *ignoreRule) matchFile(rel string) bool {
	if r.unsupported != "" {
		return false
	}
	if r.legacy != "" && matchGlob(r.legacy, rel) {
		return true
	}
	if !r.directoryForm() {
		return false
	}
	if r.matchAll {
		return true
	}
	slashRel := filepath.ToSlash(rel)
	if r.anchored && !r.dirOnly && matchSegments(r.glob, slashRel) {
		return true
	}
	for i := 0; i < len(slashRel); i++ {
		if slashRel[i] == '/' && r.matchDir(slashRel[:i]) {
			return true
		}
	}
	return false
}

// matchDir reports whether the rule excludes the directory at dir, a
// slash-separated path relative to the scan root, and so everything in it.
// Only the directory forms match directories.
func (r *ignoreRule) matchDir(dir string) bool {
	switch {
	case r.unsupported != "" || dir == "" || dir == ".":
		return false
	case r.matchAll:
		return true
	case r.dirOnly && !r.anchored && !strings.Contains(r.glob, "/"):
		// A name such as "dist/" matches a directory at any depth.
		ok, _ := path.Match(r.glob, path.Base(dir))
		return ok
	case r.dirOnly || r.anchored:
		return matchSegments(r.glob, dir)
	case r.literalPath:
		return dir == r.glob
	}
	return false
}

// matchSegments matches a slash-separated name against a slash-separated
// pattern segment by segment, as gitignore does: "*", "?" and classes stay
// within one segment, and a "**" segment matches any number of segments
// (at least one when it ends the pattern). It runs in O(segments of
// pattern x segments of name), whatever the number of "**".
func matchSegments(pattern, name string) bool {
	pat := strings.Split(pattern, "/")
	segs := strings.Split(name, "/")
	// cur[j] reports whether the pattern segments so far match segs[:j].
	cur := make([]bool, len(segs)+1)
	cur[0] = true
	for i, p := range pat {
		next := make([]bool, len(segs)+1)
		if p == "**" {
			last := i == len(pat)-1
			reached := false
			for j := range next {
				if last {
					next[j] = reached // at least one segment
				}
				if cur[j] {
					reached = true
				}
				if !last {
					next[j] = reached
				}
			}
		} else {
			for j := 1; j <= len(segs); j++ {
				if cur[j-1] {
					if ok, _ := path.Match(p, segs[j-1]); ok {
						next[j] = true
					}
				}
			}
		}
		cur = next
	}
	return cur[len(segs)]
}

// translateNegatedClasses rewrites gitignore's negated character class
// "[!...]" to the "[^...]" spelling Go's matcher understands. A backslash
// escapes the next character, except on Windows where it is a separator.
func translateNegatedClasses(p string) string {
	if !strings.Contains(p, "[!") {
		return p
	}
	escapes := filepath.Separator != '\\'
	var b strings.Builder
	inClass := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case escapes && c == '\\' && i+1 < len(p):
			b.WriteByte(c)
			i++
			b.WriteByte(p[i])
			continue
		case !inClass && c == '[':
			inClass = true
			b.WriteByte(c)
			if i+1 < len(p) && p[i+1] == '!' {
				b.WriteByte('^')
				i++
			}
			continue
		case inClass && c == ']':
			inClass = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

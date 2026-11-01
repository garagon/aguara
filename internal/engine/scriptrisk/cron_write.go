package scriptrisk

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var cronOpenTokenRe = regexp.MustCompile(`\bopen\b`)

// Deliberately bounded to a direct builtin open(...).write(literal) chain.
// Dynamic paths, custom openers, handle aliases and pathlib are not resolved.
func findDirectCronWrite(codeStmts, sourceStmts []statement) (int, string, bool) {
	// An explicit binding of open makes builtin identity uncertain. Be
	// conservative across the file rather than guessing Python scope resolution.
	for _, st := range codeStmts {
		if pyDefRe.MatchString(strings.TrimSpace(st.text)) {
			if body, ok := balancedPythonCallBody(st.text, strings.IndexByte(st.text, '(')); ok {
				for _, arg := range splitPythonArgs(body) {
					name := strings.TrimSpace(strings.TrimLeft(arg, "*"))
					name, _, _ = strings.Cut(name, "=")
					name, _, _ = strings.Cut(name, ":")
					if strings.TrimSpace(name) == "open" {
						return 0, "", false
					}
				}
			}
		}
		for _, loc := range cronOpenTokenRe.FindAllStringIndex(st.text, -1) {
			before := strings.TrimSpace(st.text[:loc[0]])
			after := strings.TrimSpace(st.text[loc[1]:])
			words := strings.Fields(before)
			binding := ""
			if len(words) > 0 {
				binding = words[len(words)-1]
			}
			if strings.HasPrefix(after, "=") && !strings.HasPrefix(after, "==") || strings.HasPrefix(after, ":") ||
				binding == "def" || binding == "class" || binding == "as" || binding == "import" || binding == "for" {
				return 0, "", false
			}
		}
	}
	for _, st := range sourceStmts {
		code := maskPython(st.text, true)
		for _, loc := range cronOpenTokenRe.FindAllStringIndex(code, -1) {
			// RE2 word boundaries are ASCII; do not treat a suffix of a
			// Unicode Python identifier as the builtin open function.
			if loc[0] > 0 && code[loc[0]-1] >= 0x80 {
				continue
			}
			if strings.HasSuffix(strings.TrimSpace(code[:loc[0]]), ".") {
				continue
			}
			open := loc[1]
			for open < len(code) && isSpace(code[open]) {
				open++
			}
			if open >= len(code) || code[open] != '(' {
				continue
			}
			body, ok := balancedPythonCallBody(st.text, open)
			if !ok {
				continue
			}
			binary, ok := cronFileOpen(splitPythonArgs(body))
			if !ok {
				continue
			}
			tail := strings.TrimSpace(st.text[open+len(body)+2:])
			if !strings.HasPrefix(tail, ".") {
				continue
			}
			tail = strings.TrimSpace(tail[1:])
			if !strings.HasPrefix(tail, "write") {
				continue
			}
			tail = strings.TrimSpace(tail[len("write"):])
			if !strings.HasPrefix(tail, "(") {
				continue
			}
			data, ok := balancedPythonCallBody(tail, 0)
			if !ok {
				continue
			}
			args := splitPythonArgs(data)
			if len(args) == 2 && args[1] == "" {
				args = args[:1]
			}
			if len(args) != 1 {
				continue
			}
			expr := args[0]
			isBytes := strings.HasPrefix(expr, "b") || strings.HasPrefix(expr, "B")
			if isBytes {
				expr = expr[1:]
			}
			if isBytes != binary {
				continue
			}
			value, ok := cronLiteral(expr, binary)
			if ok && hasCronEntry(value) {
				return st.line, strings.TrimSpace(maskPython(st.text, false)), true
			}
		}
	}
	return 0, "", false
}

func cronFileOpen(args []string) (binary, ok bool) {
	values := map[string]string{}
	keyword := false
	for i, arg := range args {
		if arg == "" && i == len(args)-1 {
			continue
		}
		key, value, named := strings.Cut(arg, "=")
		if named {
			keyword = true
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		} else {
			if keyword || i > 1 {
				return false, false
			}
			key, value = "file", arg
			if i == 1 {
				key = "mode"
			}
		}
		if _, exists := values[key]; exists {
			return false, false
		}
		switch key {
		case "file", "mode":
		case "encoding", "errors":
			literal, ok := cronStringLiteral(value)
			if !ok || key == "encoding" && literal != "utf-8" || key == "errors" && literal != "strict" {
				return false, false
			}
		default:
			return false, false
		}
		values[key] = value
	}
	path, pathOK := cronStringLiteral(values["file"])
	mode, modeOK := cronStringLiteral(values["mode"])
	if !pathOK || !modeOK || !isCronFile(path) {
		return false, false
	}
	seen := map[rune]bool{}
	base := 0
	for _, c := range mode {
		if !strings.ContainsRune("rwaxbt+", c) || seen[c] {
			return false, false
		}
		seen[c] = true
		if strings.ContainsRune("rwax", c) {
			base++
		}
	}
	if base != 1 || seen['b'] && seen['t'] || seen['r'] && !seen['+'] {
		return false, false
	}
	return seen['b'], !seen['b'] || values["encoding"] == "" && values["errors"] == ""
}

func isCronFile(path string) bool {
	if path == "/etc/crontab" {
		return true
	}
	name, ok := strings.CutPrefix(path, "/etc/cron.d/")
	if !ok || name == "" {
		return false
	}
	for _, c := range name {
		if !cronNameRune(c) {
			return false
		}
	}
	return true
}

// Unlike pythonStringLiteral, require a single complete literal, not adjacent
// strings, concatenation or interpolation. Decode only unambiguous escapes.
func cronStringLiteral(expr string) (string, bool) {
	return cronLiteral(expr, false)
}

func cronLiteral(expr string, binary bool) (string, bool) {
	expr = strings.TrimSpace(expr)
	if len(expr) < 2 || expr[0] != '\'' && expr[0] != '"' {
		return "", false
	}
	quote := expr[0]
	var out strings.Builder
	for i := 1; i < len(expr); i++ {
		c := expr[i]
		if c == quote {
			return out.String(), i == len(expr)-1
		}
		if c == '\n' || c == '\r' {
			return "", false
		}
		if c == '\\' {
			i++
			if i >= len(expr) {
				return "", false
			}
			switch expr[i] {
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case '\\', '\'', '"':
				c = expr[i]
			case 'x', 'u', 'U':
				n := 2
				if expr[i] == 'u' {
					n = 4
				}
				if expr[i] == 'U' {
					n = 8
				}
				if binary && n != 2 || i+n >= len(expr) {
					return "", false
				}
				v, err := strconv.ParseUint(expr[i+1:i+1+n], 16, 32)
				if err != nil || !utf8.ValidRune(rune(v)) {
					return "", false
				}
				if binary {
					out.WriteByte(byte(v))
				} else {
					out.WriteRune(rune(v))
				}
				i += n
				continue
			default:
				if expr[i] < '0' || expr[i] > '7' {
					return "", false
				}
				end := i + 1
				for end < len(expr) && end-i < 3 && expr[end] >= '0' && expr[end] <= '7' {
					end++
				}
				v, err := strconv.ParseUint(expr[i:end], 8, 16)
				if err != nil || binary && v > 255 {
					return "", false
				}
				if binary {
					out.WriteByte(byte(v))
				} else {
					out.WriteRune(rune(v))
				}
				i = end - 1
				continue
			}
		}
		out.WriteByte(c)
	}
	return "", false
}

func hasCronEntry(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		user := 5
		if strings.HasPrefix(fields[0], "@") {
			switch fields[0] {
			case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
				user = 1
			default:
				continue
			}
		}
		if len(fields) < user+2 || strings.HasPrefix(fields[user+1], "#") {
			continue
		}
		if user == 5 {
			valid := true
			for i, bounds := range [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}} {
				if !cronScheduleField(fields[i], bounds[0], bounds[1]) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
		}
		validUser := true
		for _, c := range fields[user] {
			if !cronNameRune(c) {
				validUser = false
				break
			}
		}
		if validUser {
			return true
		}
	}
	return false
}

func cronNameRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func cronScheduleField(field string, min, max int) bool {
	for _, c := range field {
		if (c < '0' || c > '9') && !strings.ContainsRune("*,-/", c) {
			return false
		}
	}
	for _, part := range strings.Split(field, ",") {
		base, step, stepped := strings.Cut(part, "/")
		if stepped {
			n, err := strconv.Atoi(step)
			if err != nil || n <= 0 || n > max+1 {
				return false
			}
		}
		if base == "*" {
			continue
		}
		lo, hi, ranged := strings.Cut(base, "-")
		n, err := strconv.Atoi(lo)
		if err != nil || n < min || n > max {
			return false
		}
		if ranged {
			m, err := strconv.Atoi(hi)
			if err != nil || m < n || m > max {
				return false
			}
		}
	}
	return true
}

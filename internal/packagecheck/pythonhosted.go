package packagecheck

import (
	"net/url"
	"path"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// pythonHostedHost serves the files uploaded to PyPI. A direct reference
// to a file on it installs that PyPI release, so its file name carries a
// PyPI identity even though no index is consulted.
const pythonHostedHost = "files.pythonhosted.org"

// pythonHostedIdentity returns the project name and version of a wheel or
// source distribution referenced by an https URL on files.pythonhosted.org.
// ok is false for any other host, scheme or file name, and when the name
// or version does not parse; such references keep being skipped. No
// network access: only the URL is read.
func pythonHostedIdentity(raw string) (name, version string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		!strings.EqualFold(u.Host, pythonHostedHost) {
		return "", "", false
	}
	file := path.Base(u.Path)
	if file == "" || file == "." || file == "/" {
		return "", "", false
	}
	if strings.HasSuffix(file, ".whl") {
		return parseWheelFilename(file)
	}
	return parseSdistFilename(file)
}

// parseWheelFilename reads the binary distribution file name convention
// (PyPA "Binary distribution format", originally PEP 427):
// {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl.
// "-" is the separator and cannot occur inside a component, which writes
// it as "_", so the split is unambiguous. A build tag starts with a digit.
func parseWheelFilename(file string) (name, version string, ok bool) {
	parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
	switch len(parts) {
	case 5:
	case 6:
		if parts[2] == "" || parts[2][0] < '0' || parts[2][0] > '9' {
			return "", "", false
		}
	default:
		return "", "", false
	}
	return pythonFileIdentity(parts[0], parts[1])
}

// parseSdistFilename reads a source distribution file name
// ({name}-{version}.tar.gz per the PyPA "Source distribution format";
// .zip for older uploads) the way packaging.utils.parse_sdist_filename
// does: the version follows the last "-".
func parseSdistFilename(file string) (name, version string, ok bool) {
	var stem string
	switch {
	case strings.HasSuffix(file, ".tar.gz"):
		stem = strings.TrimSuffix(file, ".tar.gz")
	case strings.HasSuffix(file, ".zip"):
		stem = strings.TrimSuffix(file, ".zip")
	default:
		return "", "", false
	}
	i := strings.LastIndexByte(stem, '-')
	if i <= 0 {
		return "", "", false
	}
	return pythonFileIdentity(stem[:i], stem[i+1:])
}

// pythonFileIdentity validates a name and version taken from a file name.
func pythonFileIdentity(name, version string) (string, string, bool) {
	if !pep508Name.MatchString(name) {
		return "", "", false
	}
	if _, ok := intel.PEP440Canonical(version); !ok {
		return "", "", false
	}
	return name, version, true
}

// pythonHostedRef returns the pinned ref a direct reference to a PyPI file
// stands for, or nil when the URL is not one. When the reference also
// names the project (`name @ url`, or a lockfile entry), the file must be
// of that project; pip rejects a mismatch, so it identifies nothing.
func pythonHostedRef(declaredName, rawURL string) *PackageRef {
	name, version, ok := pythonHostedIdentity(rawURL)
	if !ok {
		return nil
	}
	if declaredName != "" && intel.PEP503Normalize(declaredName) != intel.PEP503Normalize(name) {
		return nil
	}
	if declaredName != "" {
		name = declaredName
	}
	return &PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name, Version: version}
}

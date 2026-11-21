// Package facts gathers information about the host checkmate runs on.
// Facts are collected once per run and exposed to templates, `when`
// expressions and platform-specific command variants.
package facts

import (
	"bufio"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Facts describes the current host.
type Facts struct {
	OS           string   `json:"os"`            // linux, darwin, windows, freebsd, ...
	Arch         string   `json:"arch"`          // amd64, arm64, ...
	Hostname     string   `json:"hostname"`      // short or fully qualified, as reported by the OS
	Distro       string   `json:"distro"`        // rhel, ubuntu, debian, macos, windows, ...
	DistroLike   []string `json:"distro_like"`   // related distributions, e.g. [rhel, fedora] for rocky
	DistroName   string   `json:"distro_name"`   // human readable name
	Version      string   `json:"version"`       // distribution version, e.g. 9.4
	VersionMajor int      `json:"version_major"` // leading number of Version, 0 if unknown
	Kernel       string   `json:"kernel"`        // kernel release
	IsRoot       bool     `json:"is_root"`       // effective UID 0; on Windows: running elevated
}

// Gather collects facts for the current host. It never fails; facts that
// cannot be determined are left empty.
func Gather() Facts {
	f := Facts{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	f.Hostname, _ = os.Hostname()
	f.IsRoot = os.Geteuid() == 0

	switch runtime.GOOS {
	case "linux":
		gatherLinux(&f)
	case "darwin":
		gatherDarwin(&f)
	case "windows":
		gatherWindows(&f)
	default:
		f.Distro = runtime.GOOS
		f.Kernel = commandOutput("uname", "-r")
	}
	f.VersionMajor = leadingInt(f.Version)
	return f
}

// PlatformKeys returns the keys used to select a platform-specific command
// variant, from most to least specific. "default" always comes last.
func (f Facts) PlatformKeys() []string {
	keys := make([]string, 0, len(f.DistroLike)+3)
	if f.Distro != "" {
		keys = append(keys, f.Distro)
	}
	keys = append(keys, f.DistroLike...)
	if f.OS != "" && f.OS != f.Distro {
		keys = append(keys, f.OS)
	}
	// Allow "unix" as a shared key for every non-Windows platform.
	if f.OS != "windows" {
		keys = append(keys, "unix")
	}
	return append(keys, "default")
}

// Map returns the facts as a generic map for use in templates.
func (f Facts) Map() map[string]any {
	like := make([]any, len(f.DistroLike))
	for i, d := range f.DistroLike {
		like[i] = d
	}
	return map[string]any{
		"os":            f.OS,
		"arch":          f.Arch,
		"hostname":      f.Hostname,
		"distro":        f.Distro,
		"distro_like":   like,
		"distro_name":   f.DistroName,
		"version":       f.Version,
		"version_major": f.VersionMajor,
		"kernel":        f.Kernel,
		"is_root":       f.IsRoot,
	}
}

func gatherLinux(f *Facts) {
	osRelease := readOSRelease("/etc/os-release")
	if len(osRelease) == 0 {
		osRelease = readOSRelease("/usr/lib/os-release")
	}
	f.Distro = strings.ToLower(osRelease["ID"])
	f.DistroLike = strings.Fields(strings.ToLower(osRelease["ID_LIKE"]))
	f.DistroName = osRelease["PRETTY_NAME"]
	f.Version = osRelease["VERSION_ID"]
	if f.Distro == "" {
		f.Distro = "linux"
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.Kernel = strings.TrimSpace(string(data))
	}
}

func gatherDarwin(f *Facts) {
	f.Distro = "macos"
	f.DistroName = commandOutput("sw_vers", "-productName")
	f.Version = commandOutput("sw_vers", "-productVersion")
	f.Kernel = commandOutput("uname", "-r")
}

var windowsVersionRe = regexp.MustCompile(`\d+\.\d+\.\d+(\.\d+)?`)

func gatherWindows(f *Facts) {
	f.Distro = "windows"
	f.DistroName = "Windows"
	out := commandOutput("cmd", "/c", "ver")
	f.Version = windowsVersionRe.FindString(out)
	f.Kernel = f.Version
	windowsDetails(f)
	f.IsRoot = windowsElevated()
}

// windowsProduct names the Windows product from the installation type
// ("Client", "Server", "Server Core") and the build number.
func windowsProduct(installType string, build int) string {
	if strings.HasPrefix(installType, "Server") {
		switch {
		case build >= 26100:
			return "Windows Server 2025"
		case build >= 20348:
			return "Windows Server 2022"
		case build >= 17763:
			return "Windows Server 2019"
		case build >= 14393:
			return "Windows Server 2016"
		}
		return "Windows Server"
	}
	switch {
	case build >= 22000:
		return "Windows 11"
	case build >= 10240:
		return "Windows 10"
	}
	return "Windows"
}

// readOSRelease parses an os-release(5) file into a key/value map.
func readOSRelease(path string) map[string]string {
	result := map[string]string{}
	fh, err := os.Open(path)
	if err != nil {
		return result
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else {
			value = strings.Trim(value, `"'`)
		}
		result[strings.TrimSpace(key)] = value
	}
	return result
}

func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

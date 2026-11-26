package facts

import (
	"fmt"
	"strings"
)

// RemoteScript prints what Remote needs to know about a host. It runs in
// any POSIX shell, on Linux, macOS and the BSDs.
const RemoteScript = `echo "os=$(uname -s)"
echo "arch=$(uname -m)"
echo "hostname=$(hostname 2>/dev/null || uname -n)"
echo "kernel=$(uname -r)"
echo "uid=$(id -u)"
for f in /etc/os-release /usr/lib/os-release; do
  if [ -r "$f" ]; then sed 's/^/osrelease:/' "$f"; break; fi
done
if command -v sw_vers >/dev/null 2>&1; then
  echo "product=$(sw_vers -productName)"
  echo "version=$(sw_vers -productVersion)"
fi
if command -v bash >/dev/null 2>&1; then echo "bash=yes"; fi
if timeout -k 1 5 true >/dev/null 2>&1; then echo "timeout=yes"; fi
echo "end=yes"
`

// RemoteHost is what the facts of another host say about running commands
// there.
type RemoteHost struct {
	HasBash    bool // bash is installed
	HasTimeout bool // timeout(1) with -k is available
}

// Remote builds the facts of a host from the output of RemoteScript.
func Remote(output string) (Facts, RemoteHost, error) {
	values := map[string]string{}
	var osRelease strings.Builder
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if rest, ok := strings.CutPrefix(line, "osrelease:"); ok {
			osRelease.WriteString(rest + "\n")
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	// Banners and profile scripts may print around the facts, but a cut-off
	// or foreign output must not pass for a host.
	if values["end"] != "yes" || values["os"] == "" {
		return Facts{}, RemoteHost{}, fmt.Errorf("the host did not answer the facts script as expected")
	}

	f := Facts{
		OS:       strings.ToLower(values["os"]),
		Arch:     goArch(values["arch"]),
		Hostname: values["hostname"],
		Kernel:   values["kernel"],
		IsRoot:   values["uid"] == "0",
	}
	switch f.OS {
	case "linux":
		applyOSRelease(&f, parseOSRelease(strings.NewReader(osRelease.String())))
	case "darwin":
		f.Distro = "macos"
		f.DistroName = values["product"]
		f.Version = values["version"]
	default:
		f.Distro = f.OS
	}
	f.VersionMajor = leadingInt(f.Version)
	return f, RemoteHost{HasBash: values["bash"] == "yes", HasTimeout: values["timeout"] == "yes"}, nil
}

// goArch maps `uname -m` to the names Go uses, which the local facts
// report.
func goArch(machine string) string {
	switch machine {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i686":
		return "386"
	case "armv6l", "armv7l":
		return "arm"
	}
	return machine
}

// RemoteWindowsScript is RemoteScript for Windows. It runs in Windows
// PowerShell 5.1 and PowerShell 7.
const RemoteWindowsScript = `$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"os=windows"
"arch=$env:PROCESSOR_ARCHITECTURE"
"hostname=$([System.Net.Dns]::GetHostName())"
"version=$($cv.CurrentMajorVersionNumber).$($cv.CurrentMinorVersionNumber).$($cv.CurrentBuild).$($cv.UBR)"
"build=$($cv.CurrentBuild)"
"install=$($cv.InstallationType)"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
"elevated=$((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh=yes" }
"end=yes"
`

// RemoteWindows builds the facts of a Windows host from the output of
// RemoteWindowsScript. hasPwsh says that PowerShell 7 is installed.
func RemoteWindows(output string) (f Facts, hasPwsh bool, err error) {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	if values["end"] != "yes" || values["os"] != "windows" {
		return Facts{}, false, fmt.Errorf("the host did not answer the facts script as expected")
	}
	f = Facts{
		OS:         "windows",
		Arch:       goArch(strings.ToLower(values["arch"])),
		Hostname:   values["hostname"],
		Distro:     "windows",
		DistroName: windowsProduct(values["install"], leadingInt(values["build"])),
		Version:    values["version"],
		Kernel:     values["version"],
		IsRoot:     strings.EqualFold(values["elevated"], "true"),
	}
	f.VersionMajor = leadingInt(f.Version)
	return f, values["pwsh"] == "yes", nil
}

// Device is the facts of a host without a shell, such as a switch or a
// firewall: nothing can be asked, the inventory says what it is.
func Device(name, platform string) Facts {
	return Facts{OS: platform, Distro: platform, DistroName: platform, Hostname: name}
}

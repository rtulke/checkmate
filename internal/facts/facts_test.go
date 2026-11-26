package facts

import (
	"reflect"
	"testing"
)

func TestWindowsProduct(t *testing.T) {
	cases := []struct {
		installType string
		build       int
		want        string
	}{
		{"Client", 19045, "Windows 10"},
		{"Client", 22631, "Windows 11"},
		{"Client", 26100, "Windows 11"},
		{"Server", 14393, "Windows Server 2016"},
		{"Server Core", 17763, "Windows Server 2019"},
		{"Server", 20348, "Windows Server 2022"},
		{"Server", 26100, "Windows Server 2025"},
		{"", 0, "Windows"},
	}
	for _, c := range cases {
		if got := windowsProduct(c.installType, c.build); got != c.want {
			t.Errorf("windowsProduct(%q, %d) = %q, want %q", c.installType, c.build, got, c.want)
		}
	}
}

func TestRemoteWindows(t *testing.T) {
	out := "os=windows\r\narch=AMD64\r\nhostname=WEB01\r\nversion=10.0.20348.5870\r\nbuild=20348\r\n" +
		"install=Server Core\r\nelevated=True\r\npwsh=yes\r\nend=yes\r\n"
	f, hasPwsh, err := RemoteWindows(out)
	if err != nil {
		t.Fatal(err)
	}
	want := Facts{OS: "windows", Arch: "amd64", Hostname: "WEB01", Distro: "windows", DistroName: "Windows Server 2022",
		Version: "10.0.20348.5870", VersionMajor: 10, Kernel: "10.0.20348.5870", IsRoot: true}
	if !reflect.DeepEqual(f, want) || !hasPwsh {
		t.Errorf("facts %+v, pwsh %v", f, hasPwsh)
	}
	if got := f.PlatformKeys(); !reflect.DeepEqual(got, []string{"windows", "default"}) {
		t.Errorf("platform keys %v", got)
	}
	for _, bad := range []string{"", "os=windows\n", "'sh' is not recognized as an internal or external command", "os=linux\nend=yes\n"} {
		if _, _, err := RemoteWindows(bad); err == nil {
			t.Errorf("%q was taken for a Windows host", bad)
		}
	}
}

func TestRemote(t *testing.T) {
	out := "Last login: today\nos=Linux\narch=aarch64\nhostname=db01\nkernel=6.1.0\nuid=0\n" +
		"osrelease:ID=rocky\nosrelease:ID_LIKE=\"rhel centos fedora\"\nosrelease:VERSION_ID=\"9.4\"\n" +
		"osrelease:PRETTY_NAME=\"Rocky Linux 9.4\"\nbash=yes\ntimeout=yes\nend=yes\n"
	f, host, err := Remote(out)
	if err != nil {
		t.Fatal(err)
	}
	want := Facts{OS: "linux", Arch: "arm64", Hostname: "db01", Distro: "rocky", DistroLike: []string{"rhel", "centos", "fedora"},
		DistroName: "Rocky Linux 9.4", Version: "9.4", VersionMajor: 9, Kernel: "6.1.0", IsRoot: true}
	if !reflect.DeepEqual(f, want) || !host.HasBash || !host.HasTimeout {
		t.Errorf("facts %+v, host %+v", f, host)
	}
	if _, _, err := Remote("os=Linux\nuid=0\n"); err == nil {
		t.Error("a cut-off answer was accepted")
	}
}

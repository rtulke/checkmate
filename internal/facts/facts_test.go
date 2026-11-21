package facts

import "testing"

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

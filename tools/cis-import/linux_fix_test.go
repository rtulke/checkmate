package main

import (
	"strings"
	"testing"
)

func TestChmodRemoval(t *testing.T) {
	for allowed, want := range map[int64]string{
		0o644:  "u-xs,g-wxs,o-wx,a-t",
		0o600:  "u-xs,g-rwxs,o-rwx,a-t",
		0o7777: "",
		0o1777: "u-s,g-s",
		0o750:  "u-s,g-ws,o-rwx,a-t",
	} {
		if got := chmodRemoval(^allowed & 0o7777); got != want {
			t.Errorf("%04o: got %q, want %q", allowed, got, want)
		}
	}
}

func TestFileAttrRemediation(t *testing.T) {
	got := fileAttrRemediation("/etc/crontab", "", "", []string{"root"}, []string{"root"}, ^int64(0o600)&0o7777)
	want := "Create /etc/crontab if it is missing, then set owner root and group root and remove the permissions u-xs,g-rwxs,o-rwx,a-t:\n\n" +
		"chown root:root '/etc/crontab'\nchmod u-xs,g-rwxs,o-rwx,a-t '/etc/crontab'"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestContentRemediation(t *testing.T) {
	got := contentRemediation("/etc/ssh/sshd_config", []string{
		`{ rc: "== 0" }`,
		`{ some: "~ ^Banner /etc/issue.net" }`,
		`{ none: "~ ^Banner none" }`,
		`{ any: [{ some: "~ ^a$" }, { some: "~ ^b, c$" }] }`,
		`{ not: { all: [{ some: "~ x" }, { some: "~ \"y\"" }] } }`,
	})
	for _, w := range []string{
		"or a file in /etc/ssh/sshd_config.d/",
		"- a line matches ^Banner /etc/issue.net\n",
		"- no line matches ^Banner none\n",
		"- one of: a line matches ^a$; or a line matches ^b, c$\n",
		`- not all of: a line matches x; a line matches "y"`,
	} {
		if !strings.Contains(got, w) {
			t.Errorf("%q missing in\n%s", w, got)
		}
	}
	if contentRemediation("/etc/x", []string{`{ stderr: "~ x" }`}) != "" {
		t.Error("an unknown condition must give no remediation")
	}
}

func TestMountRemediation(t *testing.T) {
	if got := mountRemediation("/dev/shm", nil, []string{"tmpfs"}); got != "Mount a tmpfs file system on /dev/shm with an entry in /etc/fstab or a systemd mount unit." {
		t.Errorf("tmpfs: %s", got)
	}
	got := mountRemediation("/var/tmp", []string{"nodev", "nosuid"}, nil)
	if !strings.Contains(got, "with the options nodev,nosuid: add them") || !strings.Contains(got, "mount -o remount '/var/tmp'") {
		t.Errorf("options: %s", got)
	}
}

func TestPackageManager(t *testing.T) {
	for key, want := range map[string]string{"rhel7": "yum install", "rhel9": "dnf install", "debian12": "apt-get install",
		"suse15": "zypper install", "amazon2": "yum install", "amazon2023": "dnf install", "rhel9-stig": "dnf install"} {
		b := benchmarks[key]
		if got, _ := packageManager(b); got != want {
			t.Errorf("%s: got %s, want %s", key, got, want)
		}
	}
}

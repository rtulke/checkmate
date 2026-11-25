package main

import (
	"regexp"
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

func TestModeFromPattern(t *testing.T) {
	for re, want := range map[string]int64{
		"^0[0-7]00$": 0o700, "^0[0246][04]0$": 0o640, "^0[0246][04][04]$": 0o644, "^0[0246]00$": 0o600,
		"^[0-7][0-7][0145]0$": 0o7750, "^[0-7][0-7]0$": 0o770,
		"^0[0-7][0-5]0$": -1, "^0[46]00$": -1, "^0644$": -1, "[0-7]00": -1,
	} {
		got, ok := modeFromPattern(re)
		if !ok {
			got = -1
		}
		if got != want {
			t.Errorf("%s: got %o, want %o", re, got, want)
		}
	}
}

func TestServiceEnabledStates(t *testing.T) {
	c := serviceChecks(check{}, "systemd-journald", map[string]any{"enabled": true})[0]
	re := regexp.MustCompile(strings.TrimPrefix(strings.Trim(c.Expect[0], `"`), "~ "))
	for state, want := range map[string]bool{
		"enabled": true, "static": true, "enabled-runtime": true,
		"disabled": false, "masked": false, "indirect": false, "": false,
	} {
		if got := re.MatchString(state); got != want {
			t.Errorf("state %q: got %v, want %v", state, got, want)
		}
	}
}

func TestUnsetVariableInPattern(t *testing.T) {
	got := patternCondition("/^pool time.nist.gov <no value>/")
	if want := `{ some: "~ ^pool time.nist.gov" }`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCommandRobustness(t *testing.T) {
	// The drop-in directory of pwquality.conf is optional.
	c := commandCheck(check{}, "password_minlen", map[string]any{
		"exec":        `grep -Psi -- '^\h*minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf`,
		"exit-status": map[string]any{"or": []any{0, 1}},
		"stdout":      []any{"/minlen/"},
	})[0]
	if want := `{ rc: "in [0, 1, 2]" }`; c.Expect[0] != want {
		t.Errorf("got %s, want %s", c.Expect[0], want)
	}
	// An empty audit log directory must not make find search the current directory.
	c = commandCheck(check{}, "audit_logfile_group", map[string]any{
		"exec":   `d=$(dirname $(grep ^log_file /etc/audit/auditd.conf | awk '{ print $NF }')); find -L $d -maxdepth 1 -type f ! -group root ! -group adm`,
		"stdout": []any{"!/./"},
	})[0]
	if strings.Contains(c.Run, "find -L $d") || !strings.Contains(c.Run, `find -L "$(dirname "$f")" -maxdepth 1 -type f ! -group root ! -group adm`) {
		t.Errorf("command was not rewritten:\n%s", c.Run)
	}
	if err := shellSyntax(c.Run); err != nil {
		t.Error(err)
	}
}

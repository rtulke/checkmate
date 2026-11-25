package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The audit log directory is read from auditd.conf when the check runs, not
// when the policy is generated.
func TestAuditLogDir(t *testing.T) {
	path := writeFile(t, t.TempDir(), "cis_6.2.4.1.yml", "{{- if $logdir := or (and (glob \"/etc/audit/auditd.conf\") "+
		"(readFile \"/etc/audit/auditd.conf\" | findStringSubmatch `(?m)^\\s*log_file\\s*=\\s*(?P<dir>\\S*)/[^/\\s]*\\s*$` | get \"dir\")) \"/var/log/audit\" }}\n"+
		"file:\n  dir_perms:\n    path: {{ $logdir }}\n    exists: true\n    mode:\n      match-regexp: '^[0-7][0-7][0145]0$'\n"+
		"command:\n  log_group:\n    exec: find -L \"{{ $logdir }}\" -maxdepth 1 -type f ! -group adm\n{{- end }}\n")
	rendered, err := render(path, map[string]any{}, "")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := decodeResources(rendered)
	if err != nil {
		t.Fatal(err)
	}
	f := fileChecks(check{}, "dir_perms", doc["file"]["dir_perms"])
	if len(f) != 1 {
		t.Fatalf("file checks: %+v", f)
	}
	c := commandCheck(check{}, "log_group", doc["command"]["log_group"])[0]
	for _, run := range []string{f[0].Run, c.Run} {
		if !strings.Contains(run, "log_file") || !strings.Contains(run, `[ -n "$d" ] || d='/var/log/audit'`) || strings.Contains(run, auditLogDirVar) {
			t.Errorf("directory is not read on the host:\n%s", run)
		}
		if err := shellSyntax(run); err != nil {
			t.Error(err)
		}
	}
	if !strings.Contains(f[0].Run, "-perm /0027") || !strings.Contains(f[0].Name, "mode 0750 or stricter") {
		t.Errorf("mode: %s\n%s", f[0].Name, f[0].Run)
	}
	if !strings.Contains(c.Run, `find -L "$d" -maxdepth 1`) || strings.Contains(c.Name, auditLogDirVar) {
		t.Errorf("command: %s\n%s", c.Name, c.Run)
	}
}

func TestMatchingGlobCount(t *testing.T) {
	path := writeFile(t, t.TempDir(), "cis_3.1.2.yml",
		"matching:\n  wireless_disabled:\n    content: {{ len (glob \"/sys/class/net/*/wireless\") }}\n    matches: 0\n")
	rendered, err := render(path, map[string]any{}, "")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := decodeResources(rendered)
	if err != nil {
		t.Fatal(err)
	}
	c := matchingCheck(check{}, "wireless_disabled", doc["matching"]["wireless_disabled"])
	if len(c) != 1 || c[0].Run != "ls -d /sys/class/net/*/wireless 2>/dev/null" || c[0].Expect[0] != "empty" {
		t.Errorf("got %+v", c)
	}
	if got := matchingCheck(check{}, "x", map[string]any{"content": "3", "matches": 3}); got != nil {
		t.Errorf("a computed value cannot be checked: %+v", got)
	}
}

// A test upstream skips when a discovered fact is absent gets an only_if.
func TestDiscoveryConditions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "syver.yml", "discovery:\n  mount:\n    /home:\n      register: home_mounted\n      exists: true\n"+
		"  package:\n    apport:\n      register: apport_installed\n      installed: true\n"+
		"  file:\n    /etc/security/opasswd:\n      register: opasswd_exists\n      exists: true\n"+
		"syverfile:\n  {{ if .Vars.section1 }}\n  section_1/*.yml: {}\n  {{ end }}\n")
	b := benchmarks["ubuntu24"]
	discovery, err := loadDiscovery(dir, b, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if discovery["home_mounted"] != "findmnt -n '/home'" || discovery["opasswd_exists"] != "test -e '/etc/security/opasswd'" ||
		!strings.Contains(discovery["apport_installed"], "dpkg-query") {
		t.Fatalf("discovery = %v", discovery)
	}
	rule := writeFile(t, dir, "cis_1.yml", "mount:\n  home_nodev:\n    mountpoint: /home\n    skip: {{ not .Discovered.home_mounted }}\n    opts:\n    - nodev\n"+
		"  home:\n    mountpoint: /home\n    exists: true\n"+
		"file:\n  optional:\n    path: /etc/x\n    skip: {{ .Vars.unset }}\n    exists: true\n")
	conds, err := discoveryConditions(rule, map[string]any{}, discovery)
	if err != nil {
		t.Fatal(err)
	}
	if got := conds[resourceKey("mount", "home_nodev")]; len(got) != 1 || got[0] != "findmnt -n '/home'" {
		t.Errorf("home_nodev: %v", got)
	}
	if len(conds) != 1 {
		t.Errorf("only the test that depends on the fact gets a condition: %v", conds)
	}
	checks := addOnlyIf([]check{{}, {OnlyIf: "findmnt -n '/home'"}}, conds[resourceKey("mount", "home_nodev")],
		dependsOn(b, map[string]any{"depends-on": []any{"package:rsyslog"}}))
	if !strings.HasPrefix(checks[0].OnlyIf, "findmnt -n '/home' && dpkg-query") || checks[1].OnlyIf != checks[0].OnlyIf {
		t.Errorf("only_if: %q, %q", checks[0].OnlyIf, checks[1].OnlyIf)
	}
}

func TestServiceMasked(t *testing.T) {
	c := serviceChecks(check{}, "nfs", map[string]any{"name": "nfs-server.service", "masked": true})
	if len(c) != 1 || !strings.Contains(c[0].Run, "-p LoadState nfs-server.service") || c[0].Expect[0] != `"~ ^(masked|not-found)$"` {
		t.Errorf("got %+v", c)
	}
}

// One file of a list upstream generates: its own ID part, the texts of the
// rule, and no failure if the host does not have the file.
func TestListedFile(t *testing.T) {
	old := textBase
	defer func() { textBase = old }()
	textBase = map[string]conceptText{"max_days__etc_login.defs": {}}
	b := benchmarks["ubuntu24"]
	c := convertResource(b, "file", "audit_tools_perms_/sbin/auditctl", map[string]any{
		"path": "/sbin/auditctl", "exists": true, "mode": map[string]any{"match-regexp": "^0[0-7][0145][0145]$"},
	}, ruleMeta{CISID: "6.2.4.8"})
	if len(c) != 1 || c[0].ID != "CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_auditctl-attrs" || c[0].TextKey != "audit_tools_perms" {
		t.Fatalf("got %+v", c)
	}
	if strings.Contains(c[0].Run, "does not exist") || !strings.HasSuffix(c[0].Name, "mode 0755 or stricter, if it exists") ||
		!strings.HasPrefix(c[0].Remediation, "If /sbin/auditctl exists, remove") {
		t.Errorf("a missing file must pass:\n%s\n%s\n%s", c[0].Name, c[0].Run, c[0].Remediation)
	}
	// A resource that already has texts under its full name keeps its ID.
	c = convertResource(b, "file", "max_days_/etc/login.defs", map[string]any{"path": "/etc/login.defs", "exists": true}, ruleMeta{CISID: "5.4.1.1"})
	if len(c) != 1 || c[0].ID != "CIS-UBUNTU24-5.4.1.1-max_days__etc_login.defs-attrs" || !strings.Contains(c[0].Run, "does not exist") {
		t.Errorf("got %+v", c)
	}
}

func TestAuditVars(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "vars"), 0o755)
	writeFile(t, filepath.Join(dir, "vars"), "CIS.yml", "rhel10cis_disruption_high: false\nubtu24cis_nfs_server: true\nother_disruption_high: false\n")
	vars, _, err := loadVars(dir)
	if err != nil {
		t.Fatal(err)
	}
	if vars["rhel10cis_disruption_high"] != true || vars["ubtu24cis_nfs_server"] != false || vars["other_disruption_high"] != false {
		t.Errorf("vars = %v", vars)
	}
	if _, ok := vars["rhel10cis_rhel_default_repo"]; ok {
		t.Error("a variable upstream does not define must not appear")
	}
}

func TestResourceFixes(t *testing.T) {
	b := benchmarks["ubuntu24"]
	m := ruleMeta{CISID: "5.2.7"}
	got := convertResource(b, "file", "sugroup_etc_group", map[string]any{
		"path": "/etc/group", "exists": true, "contents": []any{`/^nosugroup:[^:]*:[0-9]+:$/`},
	}, m)
	if len(got) != 1 || got[0].ID != "CIS-UBUNTU24-5.2.7-sugroup_etc_group" || strings.Contains(got[0].Run, "nosugroup") {
		t.Errorf("sugroup_etc_group: %+v", got)
	}
	got = convertResource(b, "file", "su_conf", map[string]any{
		"path": "/etc/pam.d/su", "contents": []any{`/^auth\s+required\s+pam_wheel.so use_uid group=nosugroup/`},
	}, m)
	if len(got) != 1 || strings.Contains(got[0].Expect[0], "nosugroup") {
		t.Fatalf("su_conf: %+v", got)
	}
	re := regexp.MustCompile(strings.Trim(suPamWheel, "/"))
	for line, want := range map[string]bool{
		"auth required pam_wheel.so use_uid group=sugroup":        true,
		"auth\trequisite\tpam_wheel.so group=wheel debug use_uid": true,
		"auth required pam_wheel.so use_uid":                      false,
		"#auth required pam_wheel.so use_uid group=sugroup":       false,
		"auth sufficient pam_wheel.so trust use_uid group=wheel":  false,
	} {
		if re.MatchString(line) != want {
			t.Errorf("%q: got %v, want %v", line, !want, want)
		}
	}
}

func TestDropSiteChoices(t *testing.T) {
	got := dropSiteChoices([]any{
		`/^\s*space_left_action\s*=\s*email\b/`,
		`/(?i)^\s*space_left_action\s*=\s*(email|exec|single|halt)\b/`,
		`/^\s*admin_space_left_action\s*=\s*halt\b/`,
		`/(?i)^\s*admin_space_left_action\s*=\s*(single|halt)\b/`,
		`/^\s*max_log_file_action\s*=\s*keep_logs\s*$/`,
	}).([]any)
	if len(got) != 3 || strings.Contains(fmt.Sprint(got[0]), "email\\b") {
		t.Errorf("got %v", got)
	}
	if covers(`/^a=(x|y)$/`, `/(?i)^a=x$/`) || covers(`/^a=(x|y)$/`, `/^a=z$/`) {
		t.Error("covers accepts a pattern that is not included")
	}
}

func TestHostVarConditions(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "cis_1.7.1.yml", `
command:
  gdm_banner:
    exec: cat /etc/dconf/db/local.d/*
    skip: {{ if (not .Vars.ubtu24cis_desktop_required) }}true{{ else }}false{{ end }}
  xorg_absent:
    exec: dpkg -l xserver-xorg
    skip: {{ if .Vars.ubtu24cis_desktop_required }}true{{ else }}false{{ end }}
  always:
    exec: "true"
`)
	b := benchmarks["ubuntu24"]
	conds, unskip, err := hostVarConditions(path, b, map[string]any{"ubtu24cis_desktop_required": true})
	if err != nil {
		t.Fatal(err)
	}
	gdm := packageQuery(b, "gdm3")
	if got := conds[resourceKey("command", "gdm_banner")]; len(got) != 1 || got[0] != gdm {
		t.Errorf("gdm_banner: %v", got)
	}
	if got := conds[resourceKey("command", "xorg_absent")]; len(got) != 1 || got[0] != "! "+gdm || !unskip[resourceKey("command", "xorg_absent")] {
		t.Errorf("xorg_absent: %v", got)
	}
	if len(conds[resourceKey("command", "always")]) != 0 {
		t.Error("a resource that does not depend on the variable got a condition")
	}
}

func TestModuleCondition(t *testing.T) {
	for want, attrs := range map[string]map[string]any{
		"modinfo dccp >/dev/null 2>&1": {"exec": `modprobe --showconfig | grep -P '\b(install|blacklist)\h+dccp\b'`},
		"":                             {"exec": "modprobe -n -v dccp"},
	} {
		got := strings.Join(moduleCondition("command", attrs), "")
		if got != want {
			t.Errorf("%v: got %q, want %q", attrs, got, want)
		}
	}
	got := moduleCondition("file", map[string]any{"contents": []any{`/^blacklist firewire[-_]core$/`}})
	if len(got) != 1 || got[0] != "modinfo firewire_core >/dev/null 2>&1" {
		t.Errorf("firewire: %v", got)
	}
	got = moduleCondition("file", map[string]any{"contents": []any{`/^install overlay(fs)? \/bin\/(true|false)/`}})
	if len(got) != 1 || got[0] != "modinfo overlay >/dev/null 2>&1" {
		t.Errorf("overlay: %v", got)
	}
	if got := moduleCondition("file", map[string]any{"contents": []any{`/^PermitRootLogin no/`}}); got != nil {
		t.Errorf("unrelated file: %v", got)
	}
}

func TestLeftOutCommands(t *testing.T) {
	for exec, left := range map[string]bool{
		`echo "Manual!! - Please check only approved services are listening"`: true,
		`echo "Manual test"`:           true,
		`/var/fs_with_cves.sh`:         true,
		`echo "scan_done"`:             false,
		`echo manual | grep -c manual`: false,
		`/usr/sbin/sshd -T`:            false,
	} {
		got := commandCheck(check{ID: "x"}, "name", map[string]any{"exec": exec})
		if (len(got) == 0) != left {
			t.Errorf("%q: left out = %v, want %v", exec, len(got) == 0, left)
		}
	}
	got := rewriteExec(`find /home/ -name "\.*" -perm /g+w,o+w | grep -v .bash_history`)
	if !strings.Contains(got, `find "$d" -xdev -name "\.*" -perm /g+w,o+w 2>/dev/null`) || !strings.HasSuffix(got, "done | grep -v .bash_history") {
		t.Errorf("home find: %s", got)
	}
}

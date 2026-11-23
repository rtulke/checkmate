package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxConcept(t *testing.T) {
	for id, want := range map[string]string{
		"CIS-RHEL9-5.1.20-sshd_permitrootlogin-content": "sshd_permitrootlogin",
		"CIS-UBUNTU18-1.1.17-home-2":                    "home",
		"CIS-RHEL9-2.4.1.1-crond-enabled":               "crond",
		"CIS-DEBIAN12-1.3.1.7-mctrans-version-3":        "mctrans",
		"CIS-RHEL9-1.5.1-address_space_random":          "address_space_random",
		"STIG-RHEL-09-211045-ctrl_alt_del":              "",
	} {
		if got := linuxConcept(id); got != want {
			t.Errorf("%s: got %q, want %q", id, got, want)
		}
	}
}

func TestApplyTexts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "texts.yml")
	os.WriteFile(path, []byte(`
crond:
  rationale: Cron runs jobs.
  remediation:
    all: generic fix
    debian: systemctl enable cron
pam_x:
  rationale:
    rhel: RHEL reason
`), 0o644)
	if err := loadTexts(path); err != nil {
		t.Fatal(err)
	}
	checks := []check{
		{ID: "CIS-DEBIAN12-2.4.1.1-crond-enabled"},
		{ID: "CIS-DEBIAN12-2.4.1.1-crond-running", Remediation: "generated"},
		{ID: "CIS-DEBIAN12-5.3-pam_x"},
		{ID: "CIS-DEBIAN12-9.9-unknown"},
	}
	missing := applyTexts(benchmarks["debian12"], checks)
	if checks[0].Rationale != "Cron runs jobs." || checks[0].Remediation != "systemctl enable cron" {
		t.Errorf("family text not used: %+v", checks[0])
	}
	if checks[1].Remediation != "generated" {
		t.Error("a generated remediation must not be replaced")
	}
	if len(missing) != 2 || !strings.Contains(missing[0], "pam_x") || !strings.Contains(missing[1], "unknown") {
		t.Errorf("missing = %v", missing)
	}
	textBase = nil
}

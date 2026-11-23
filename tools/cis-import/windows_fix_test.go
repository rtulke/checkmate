package main

import (
	"strings"
	"testing"
)

func TestSecpolRemediation(t *testing.T) {
	cases := []struct {
		key    string
		expect []string
		exec   string
		want   []string
	}{
		{"MaximumPasswordAge", nil, `if ($v -le 365 -and $v -ne 0) { 'COMPLIANT' } else { 'NONCOMPLIANT' }`,
			[]string{`"Maximum password age" (MaximumPasswordAge) to 365 or less, but not 0 days.`, "net accounts /maxpwage:365"}},
		{"LockoutBadCount", []string{`{ some: "~ ^[1-5]$" }`}, "",
			[]string{"to 1 to 5 invalid logon attempts.", "net accounts /lockoutthreshold:5", "Default Domain Policy"}},
		{"PasswordComplexity", []string{`{ some: "~ ^1$" }`}, "", []string{"to Enabled."}},
		{"EnableGuestAccount", []string{`{ some: "~ ^0$" }`}, "", []string{"to Disabled.", "next policy refresh"}},
		{"NewGuestName", []string{`{ some: "~ ^.+$" }`, `{ none: "~ ^Guest$" }`}, "", []string{"to a name other than Guest."}},
	}
	for _, c := range cases {
		got, err := secpolRemediation(c.key, c.expect, c.exec)
		if err != nil {
			t.Errorf("%s: %v", c.key, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q missing in\n%s", c.key, w, got)
			}
		}
	}
	if _, err := secpolRemediation("PasswordComplexity", []string{`{ some: "~ ^[0-9]+$" }`}, ""); err == nil {
		t.Error("an expectation that cannot be translated must be an error, not a guess")
	}
}

func TestUserRightRemediation(t *testing.T) {
	cases := []struct {
		right  string
		expect []string
		want   string
	}{
		{"SeTcbPrivilege", []string{`{ some: "~ ^NONE$" }`}, `Remove every account and group from the user right "Act as part of the operating system"`},
		{"SeNetworkLogonRight", []string{`{ some: "~ ^S-1-5-11,S-1-5-32-544$" }`},
			"to exactly Authenticated Users (S-1-5-11), Administrators (S-1-5-32-544); remove all other"},
		{"SeCreateSymbolicLinkPrivilege", []string{`{ some: "~ ^S-1-5-32-544(,S-1-5-83-0)?$" }`},
			`to exactly Administrators (S-1-5-32-544), and optionally NT VIRTUAL MACHINE\Virtual Machines (S-1-5-83-0);`},
		{"SeSecurityPrivilege", []string{`{ some: "~ ^(NAME:Exchange Servers,)?S-1-5-32-544$" }`},
			"to exactly Administrators (S-1-5-32-544), and optionally Exchange Servers;"},
		{"SeDenyNetworkLogonRight", []string{`{ some: "~ ^(.*,)?S-1-5-114(,.*)?$" }`, `{ some: "~ ^(.*,)?S-1-5-32-546(,.*)?$" }`},
			"Add Local account and member of Administrators group (S-1-5-114) and Guests (S-1-5-32-546) to the user right"},
		{"SeAuditPrivilege", []string{`{ some: "~ ^S-1-5-19,S-1-5-20,S-1-5-99-1-2$" }`},
			"LOCAL SERVICE (S-1-5-19), NETWORK SERVICE (S-1-5-20), S-1-5-99-1-2;"},
	}
	for _, c := range cases {
		got, err := userRightRemediation(c.right, c.expect)
		if err != nil {
			t.Errorf("%s: %v", c.right, err)
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q missing in\n%s", c.right, c.want, got)
		}
	}
	if _, err := userRightRemediation("SeTcbPrivilege", []string{`{ some: "~ ^S-1-5-32-5.*$" }`}); err == nil {
		t.Error("an expectation that cannot be translated must be an error, not a guess")
	}
}

func TestAuditRemediation(t *testing.T) {
	got, err := auditRemediation("Plug and Play Events", "{0CCE9248-69AE-11D9-BED3-505054503030}", []string{`{ some: "~ ^[13]$" }`})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`auditpol.exe /set "/subcategory:{0CCE9248-69AE-11D9-BED3-505054503030}" /success:enable` + "\n",
		`Audit Policies\Detailed Tracking\Audit PNP Activity`} {
		if !strings.Contains(got, w) {
			t.Errorf("%q missing in\n%s", w, got)
		}
	}
}

func TestRegistryRemediation(t *testing.T) {
	got := registryValue(`HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths`, `\\*\NETLOGON`, "REG_SZ", "RequireMutualAuthentication=1")
	want := `New-ItemProperty -LiteralPath $k -Name '\\*\NETLOGON' -PropertyType String -Value 'RequireMutualAuthentication=1' -Force`
	if !strings.Contains(got, want) {
		t.Errorf("%q missing in\n%s", want, got)
	}
	got = registryValue(`HKLM\SYSTEM\X`, "NullSessionPipes", "REG_MULTI_SZ", "")
	if !strings.Contains(got, "to an empty list (REG_MULTI_SZ)") || !strings.Contains(got, "-Value ([string[]]@())") {
		t.Errorf("empty multi-string:\n%s", got)
	}
	got = registryValue(`HKLM\SYSTEM\X`, "Name", "REG_SZ", "it's")
	if !strings.Contains(got, `-Value 'it''s'`) {
		t.Errorf("single quote not escaped:\n%s", got)
	}
}

func TestPSRequirement(t *testing.T) {
	for cond, want := range map[string]string{
		"$v -ge 24":                  "24 or more|24",
		"$v -le 365 -and $v -ne 0":   "365 or less, but not 0|365",
		"$v -gt 0":                   "more than 0|1",
		"$v -ne 0":                   "",
		"$v -ge 1 -or $v -eq 0":      "",
		"($v -ge 1) -and ($v -le 3)": "",
	} {
		r, ok := psRequirement(cond)
		got := ""
		if ok {
			got = r.text + "|" + r.example
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", cond, got, want)
		}
	}
}

package main

// Remediation of the Windows checks. Every text is generated from the data
// of the check (registry value, security policy setting, user right, audit
// subcategory, service, firewall profile): what to set, where to set it in
// Group Policy and a PowerShell command for a single computer. No benchmark
// text is used.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const gpoNote = "If a Group Policy Object manages this setting, change it there; " +
	"a value set directly on the computer is replaced at the next policy refresh."

// psPath turns HKLM\SOFTWARE\... into the PowerShell path HKLM:\SOFTWARE\...
func psPath(location string) string {
	hive, rest, _ := strings.Cut(location, `\`)
	return hive + `:\` + rest
}

var psTypes = map[string]string{
	"REG_DWORD": "DWord", "REG_QWORD": "QWord", "REG_SZ": "String",
	"REG_EXPAND_SZ": "ExpandString", "REG_MULTI_SZ": "MultiString", "REG_BINARY": "Binary",
}

// psSetValue writes a registry value; the key is created if it is missing.
func psSetValue(location, name, regType, value string) string {
	return fmt.Sprintf("$k = %s\nif (-not (Test-Path -LiteralPath $k)) { New-Item -Path $k -Force | Out-Null }\n"+
		"New-ItemProperty -LiteralPath $k -Name %s -PropertyType %s -Value %s -Force | Out-Null",
		psQuote(psPath(location)), psQuote(name), psTypes[regType], value)
}

func registryValue(location, name, regType string, value any) string {
	if psTypes[regType] == "" {
		return fmt.Sprintf("Set the registry value %s in %s to %v.\n\n%s", name, location, value, gpoNote)
	}
	text := fmt.Sprint(value)
	shown := text
	var ps string
	switch regType {
	case "REG_DWORD", "REG_QWORD":
		if _, err := strconv.ParseInt(text, 10, 64); err != nil {
			return fmt.Sprintf("Set the registry value %s in %s to %s (%s).\n\n%s", name, location, text, regType, gpoNote)
		}
		ps = text
	case "REG_MULTI_SZ":
		var items []string
		for _, l := range strings.Split(text, "\n") {
			if l != "" {
				items = append(items, l)
			}
		}
		ps = "([string[]]@(" + strings.Join(quoteAllPS(items), ", ") + "))"
		shown = strings.Join(items, ", ")
		if len(items) == 0 {
			shown = "an empty list"
		}
	default:
		ps = psQuote(text)
		shown = `"` + text + `"`
	}
	return fmt.Sprintf("Set the registry value %s in %s to %s (%s):\n\n%s\n\n%s",
		name, location, shown, regType, psSetValue(location, name, regType, ps), gpoNote)
}

func registryRemoval(location, name string) string {
	return fmt.Sprintf("Remove the registry value %s from %s:\n\n"+
		"Remove-ItemProperty -LiteralPath %s -Name %s -ErrorAction SilentlyContinue\n\n%s",
		name, location, psQuote(psPath(location)), psQuote(name), gpoNote)
}

func registryAnyValue(location, name, regType string) string {
	t := ""
	if regType != "" {
		t = " (" + regType + ")"
	}
	return fmt.Sprintf("Set the registry value %s in %s%s; the check accepts any value.\n\n%s", name, location, t, gpoNote)
}

func registryPattern(location, name, regType, re string) string {
	return fmt.Sprintf("Set the registry value %s in %s (%s) to the text your organization requires. "+
		"The check expects text matching the regular expression\n\n%s\n\n%s", name, location, regType, re, gpoNote)
}

func quoteAllPS(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = psQuote(s)
	}
	return out
}

// --- security policy (secedit) ---------------------------------------------

type secSetting struct {
	gpo      string // path below Security Settings
	unit     string // for numbers, e.g. "days"
	boolean  bool   // 1 = Enabled, 0 = Disabled
	netFlag  string // net accounts option, for account policies
	isDomain bool   // account policy: domain accounts get it from the domain
}

var secSettings = map[string]secSetting{
	"PasswordHistorySize":       {gpo: `Account Policies\Password Policy\Enforce password history`, unit: "passwords remembered", netFlag: "/uniquepw", isDomain: true},
	"MaximumPasswordAge":        {gpo: `Account Policies\Password Policy\Maximum password age`, unit: "days", netFlag: "/maxpwage", isDomain: true},
	"MinimumPasswordAge":        {gpo: `Account Policies\Password Policy\Minimum password age`, unit: "days", netFlag: "/minpwage", isDomain: true},
	"MinimumPasswordLength":     {gpo: `Account Policies\Password Policy\Minimum password length`, unit: "characters", netFlag: "/minpwlen", isDomain: true},
	"PasswordComplexity":        {gpo: `Account Policies\Password Policy\Password must meet complexity requirements`, boolean: true, isDomain: true},
	"ClearTextPassword":         {gpo: `Account Policies\Password Policy\Store passwords using reversible encryption`, boolean: true, isDomain: true},
	"LockoutDuration":           {gpo: `Account Policies\Account Lockout Policy\Account lockout duration`, unit: "minutes", netFlag: "/lockoutduration", isDomain: true},
	"LockoutBadCount":           {gpo: `Account Policies\Account Lockout Policy\Account lockout threshold`, unit: "invalid logon attempts", netFlag: "/lockoutthreshold", isDomain: true},
	"ResetLockoutCount":         {gpo: `Account Policies\Account Lockout Policy\Reset account lockout counter after`, unit: "minutes", netFlag: "/lockoutwindow", isDomain: true},
	"AllowAdministratorLockout": {gpo: `Account Policies\Account Lockout Policy\Allow Administrator account lockout`, boolean: true, isDomain: true},
	"EnableGuestAccount":        {gpo: `Local Policies\Security Options\Accounts: Guest account status`, boolean: true},
	"NewAdministratorName":      {gpo: `Local Policies\Security Options\Accounts: Rename administrator account`},
	"NewGuestName":              {gpo: `Local Policies\Security Options\Accounts: Rename guest account`},
	"LSAAnonymousNameLookup":    {gpo: `Local Policies\Security Options\Network access: Allow anonymous SID/Name translation`, boolean: true},
	"ForceLogoffWhenHourExpire": {gpo: `Local Policies\Security Options\Network security: Force logoff when logon hours expire`, boolean: true},
}

const securitySettings = `Computer Configuration\Policies\Windows Settings\Security Settings\`

// requirement is a value condition in words plus a value that meets it.
type requirement struct {
	text, example string
}

var (
	psCondition = regexp.MustCompile(`if \((\$v [^)]*)\) \{ 'COMPLIANT' \}`)
	psClause    = regexp.MustCompile(`^\$v -(ge|le|gt|lt|eq|ne) (-?\d+)$`)
	exactValue  = regexp.MustCompile(`^\^([A-Za-z0-9 _.-]+)\$$`)
	charRange   = regexp.MustCompile(`^\^\[(\d)-(\d)\]\$$`)
	choice      = regexp.MustCompile(`^\^\(([A-Za-z0-9|]+)\)\$$`)
	quotedRE    = regexp.MustCompile(`(some|none): ("(?:[^"\\]|\\.)*")`)
)

// psRequirement translates a PowerShell condition on $v such as
// "$v -le 365 -and $v -ne 0".
func psRequirement(cond string) (requirement, bool) {
	words := map[string]string{"ge": "%d or more", "le": "%d or less", "gt": "more than %d", "lt": "less than %d", "eq": "%d", "ne": "not %d"}
	var parts []string
	example := ""
	for _, clause := range strings.Split(cond, " -and ") {
		m := psClause.FindStringSubmatch(strings.TrimSpace(clause))
		if m == nil {
			return requirement{}, false
		}
		n, _ := strconv.Atoi(m[2])
		parts = append(parts, fmt.Sprintf(words[m[1]], n))
		if example == "" && m[1] != "ne" {
			switch m[1] {
			case "gt":
				n++
			case "lt":
				n--
			}
			example = strconv.Itoa(n)
		}
	}
	if example == "" {
		return requirement{}, false
	}
	return requirement{text: strings.Join(parts, ", but "), example: example}, true
}

// expectations returns the regular expressions of "some" and "none"
// conditions of a check.
func expectations(expect []string) (some, none []string) {
	for _, e := range expect {
		for _, m := range quotedRE.FindAllStringSubmatch(e, -1) {
			var s string
			if json.Unmarshal([]byte(m[2]), &s) != nil || !strings.HasPrefix(s, "~ ") {
				continue
			}
			if m[1] == "some" {
				some = append(some, s[2:])
			} else {
				none = append(none, s[2:])
			}
		}
	}
	return some, none
}

// regexRequirement translates simple anchored patterns: ^1$, ^[1-5]$,
// ^(a|b)$.
func regexRequirement(re string) (requirement, bool) {
	if m := exactValue.FindStringSubmatch(re); m != nil {
		return requirement{m[1], m[1]}, true
	}
	if m := charRange.FindStringSubmatch(re); m != nil {
		return requirement{m[1] + " to " + m[2], m[2]}, true
	}
	if m := choice.FindStringSubmatch(re); m != nil {
		alts := strings.Split(m[1], "|")
		return requirement{strings.Join(alts, " or "), alts[0]}, true
	}
	return requirement{}, false
}

func secpolRemediation(key string, expect []string, exec string) (string, error) {
	s, ok := secSettings[key]
	if !ok {
		return "", fmt.Errorf("no Group Policy path for security setting %s", key)
	}
	var req requirement
	some, none := expectations(expect)
	switch {
	case exec != "":
		m := psCondition.FindStringSubmatch(exec)
		if m == nil {
			return "", fmt.Errorf("%s: no condition found in the command", key)
		}
		if req, ok = psRequirement(m[1]); !ok {
			return "", fmt.Errorf("%s: cannot translate condition %q", key, m[1])
		}
	case len(some) == 1 && some[0] == "^.+$" && len(none) == 1:
		r, ok := regexRequirement(none[0])
		if !ok {
			return "", fmt.Errorf("%s: cannot translate %q", key, none[0])
		}
		req = requirement{text: "a name other than " + r.text}
	case len(some) == 1 && len(none) == 0:
		if req, ok = regexRequirement(some[0]); !ok {
			return "", fmt.Errorf("%s: cannot translate %q", key, some[0])
		}
	default:
		return "", fmt.Errorf("%s: unsupported expectation %v", key, expect)
	}
	value := req.text
	switch {
	case s.boolean && req.text == "1":
		value = "Enabled"
	case s.boolean && req.text == "0":
		value = "Disabled"
	case s.boolean:
		return "", fmt.Errorf("%s: boolean setting with value %q", key, req.text)
	case s.unit != "":
		value += " " + s.unit
	}
	name := s.gpo[strings.LastIndex(s.gpo, `\`)+1:]
	var b strings.Builder
	fmt.Fprintf(&b, "Set the security policy setting %q (%s) to %s.\n\n", name, key, value)
	fmt.Fprintf(&b, "Group Policy: %s%s\nOn a single computer: Local Security Policy (secpol.msc).", securitySettings, s.gpo)
	if s.netFlag != "" && req.example != "" {
		fmt.Fprintf(&b, " Or in PowerShell:\n\nnet accounts %s:%s", s.netFlag, req.example)
	}
	if s.isDomain {
		b.WriteString("\n\nFor domain accounts this policy comes from the Group Policy Object linked to the domain (usually the Default Domain Policy); local settings apply only to local accounts.")
	} else {
		b.WriteString("\n\n" + gpoNote)
	}
	return b.String(), nil
}

// --- user rights -------------------------------------------------------------

var userRights = map[string]string{
	"SeTrustedCredManAccessPrivilege":   "Access Credential Manager as a trusted caller",
	"SeNetworkLogonRight":               "Access this computer from the network",
	"SeTcbPrivilege":                    "Act as part of the operating system",
	"SeMachineAccountPrivilege":         "Add workstations to domain",
	"SeIncreaseQuotaPrivilege":          "Adjust memory quotas for a process",
	"SeInteractiveLogonRight":           "Allow log on locally",
	"SeRemoteInteractiveLogonRight":     "Allow log on through Remote Desktop Services",
	"SeBackupPrivilege":                 "Back up files and directories",
	"SeSystemTimePrivilege":             "Change the system time",
	"SeTimeZonePrivilege":               "Change the time zone",
	"SeCreatePagefilePrivilege":         "Create a pagefile",
	"SeCreateTokenPrivilege":            "Create a token object",
	"SeCreateGlobalPrivilege":           "Create global objects",
	"SeCreatePermanentPrivilege":        "Create permanent shared objects",
	"SeCreateSymbolicLinkPrivilege":     "Create symbolic links",
	"SeDebugPrivilege":                  "Debug programs",
	"SeDenyNetworkLogonRight":           "Deny access to this computer from the network",
	"SeDenyBatchLogonRight":             "Deny log on as a batch job",
	"SeDenyServiceLogonRight":           "Deny log on as a service",
	"SeDenyInteractiveLogonRight":       "Deny log on locally",
	"SeDenyRemoteInteractiveLogonRight": "Deny log on through Remote Desktop Services",
	"SeEnableDelegationPrivilege":       "Enable computer and user accounts to be trusted for delegation",
	"SeRemoteShutdownPrivilege":         "Force shutdown from a remote system",
	"SeAuditPrivilege":                  "Generate security audits",
	"SeImpersonatePrivilege":            "Impersonate a client after authentication",
	"SeIncreaseBasePriorityPrivilege":   "Increase scheduling priority",
	"SeLoadDriverPrivilege":             "Load and unload device drivers",
	"SeLockMemoryPrivilege":             "Lock pages in memory",
	"SeBatchLogonRight":                 "Log on as a batch job",
	"SeServiceLogonRight":               "Log on as a service",
	"SeSecurityPrivilege":               "Manage auditing and security log",
	"SeRelabelPrivilege":                "Modify an object label",
	"SeSystemEnvironmentPrivilege":      "Modify firmware environment values",
	"SeManageVolumePrivilege":           "Perform volume maintenance tasks",
	"SeProfileSingleProcessPrivilege":   "Profile single process",
	"SeSystemProfilePrivilege":          "Profile system performance",
	"SeAssignPrimaryTokenPrivilege":     "Replace a process level token",
	"SeRestorePrivilege":                "Restore files and directories",
	"SeShutdownPrivilege":               "Shut down the system",
	"SeSyncAgentPrivilege":              "Synchronize directory service data",
	"SeTakeOwnershipPrivilege":          "Take ownership of files or other objects",
}

// wellKnownSIDs names the SIDs used by the benchmarks.
var wellKnownSIDs = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-6":      "SERVICE",
	"S-1-5-9":      "ENTERPRISE DOMAIN CONTROLLERS",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-19":     "LOCAL SERVICE",
	"S-1-5-20":     "NETWORK SERVICE",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-551": "Backup Operators",
	"S-1-5-32-555": "Remote Desktop Users",
	"S-1-5-32-568": "IIS_IUSRS",
	"S-1-5-83-0":   `NT VIRTUAL MACHINE\Virtual Machines`,
	"S-1-5-90-0":   `Window Manager\Window Manager Group`,
	"S-1-5-113":    "Local account",
	"S-1-5-114":    "Local account and member of Administrators group",
	"S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420": `NT SERVICE\WdiServiceHost`,
}

var (
	principalRE = regexp.MustCompile(`^(S-1-[0-9-]+|NAME:[A-Za-z0-9 ._-]+)$`)
	containsRE  = regexp.MustCompile(`^\^\(\.\*,\)\?(S-1-[0-9-]+)\(,\.\*\)\?\$$`)
	optionalRE  = regexp.MustCompile(`\((,?)(S-1-[0-9-]+|NAME:[A-Za-z0-9 ._-]+)(,?)\)\?`)
)

func principal(p string) string {
	if strings.HasPrefix(p, "NAME:") {
		return p[5:]
	}
	if name, ok := wellKnownSIDs[p]; ok {
		return name + " (" + p + ")"
	}
	return p
}

func userRightRemediation(right string, expect []string) (string, error) {
	title, ok := userRights[right]
	if !ok && strings.EqualFold(right, "SeReLabelPrivilege") {
		title, ok = userRights["SeRelabelPrivilege"]
	}
	if !ok {
		return "", fmt.Errorf("no Group Policy name for user right %s", right)
	}
	some, none := expectations(expect)
	if len(some) == 0 || len(none) > 0 {
		return "", fmt.Errorf("%s: unsupported expectation %v", right, expect)
	}
	var what string
	switch {
	case len(some) == 1 && some[0] == "^NONE$":
		what = "Remove every account and group from the user right %q (%s); no one may hold it."
	case containsRE.MatchString(some[0]):
		var names []string
		for _, re := range some {
			m := containsRE.FindStringSubmatch(re)
			if m == nil {
				return "", fmt.Errorf("%s: cannot translate %q", right, re)
			}
			names = append(names, principal(m[1]))
		}
		what = "Add " + strings.Join(names, " and ") + " to the user right %q (%s); other accounts and groups may hold it as well."
	case len(some) == 1:
		re := strings.TrimSuffix(strings.TrimPrefix(some[0], "^"), "$")
		var optional []string
		for _, m := range optionalRE.FindAllStringSubmatch(re, -1) {
			optional = append(optional, principal(m[2]))
		}
		var required []string
		for _, p := range strings.Split(optionalRE.ReplaceAllString(re, ""), ",") {
			if !principalRE.MatchString(p) {
				return "", fmt.Errorf("%s: cannot translate %q", right, some[0])
			}
			required = append(required, principal(p))
		}
		what = "Assign the user right %q (%s) to exactly " + strings.Join(required, ", ")
		if len(optional) > 0 {
			what += ", and optionally " + strings.Join(optional, ", ")
		}
		what += "; remove all other accounts and groups."
	default:
		return "", fmt.Errorf("%s: unsupported expectation %v", right, expect)
	}
	return fmt.Sprintf(what, title, right) + "\n\nGroup Policy: " + securitySettings + `Local Policies\User Rights Assignment\` + title +
		"\nOn a single computer: Local Security Policy (secpol.msc).\n\n" + gpoNote, nil
}

// --- audit policy -------------------------------------------------------------

var auditCategories = map[string]string{
	"Credential Validation": "Account Logon", "Kerberos Authentication Service": "Account Logon",
	"Kerberos Service Ticket Operations": "Account Logon",
	"Application Group Management":       "Account Management", "Computer Account Management": "Account Management",
	"Distribution Group Management": "Account Management", "Other Account Management Events": "Account Management",
	"Security Group Management": "Account Management", "User Account Management": "Account Management",
	"Plug and Play Events": "Detailed Tracking", "Process Creation": "Detailed Tracking",
	"Directory Service Access": "DS Access", "Directory Service Changes": "DS Access",
	"Account Lockout": "Logon/Logoff", "Group Membership": "Logon/Logoff", "Logoff": "Logon/Logoff",
	"Logon": "Logon/Logoff", "Other Logon/Logoff Events": "Logon/Logoff", "Special Logon": "Logon/Logoff",
	"Detailed File Share": "Object Access", "File Share": "Object Access",
	"Other Object Access Events": "Object Access", "Removable Storage": "Object Access",
	"Audit Policy Change": "Policy Change", "Authentication Policy Change": "Policy Change",
	"Authorization Policy Change": "Policy Change", "MPSSVC Rule-Level Policy Change": "Policy Change",
	"Other Policy Change Events": "Policy Change",
	"Sensitive Privilege Use":    "Privilege Use",
	"IPsec Driver":               "System", "Other System Events": "System", "Security State Change": "System",
	"Security System Extension": "System", "System Integrity": "System",
}

func auditRemediation(subcategory, guid string, expect []string) (string, error) {
	category, ok := auditCategories[subcategory]
	if !ok {
		return "", fmt.Errorf("no audit category for %s", subcategory)
	}
	some, none := expectations(expect)
	if len(some) != 1 || len(none) > 0 {
		return "", fmt.Errorf("%s: unsupported expectation %v", subcategory, expect)
	}
	var setting, flags string
	switch some[0] {
	case "^3$":
		setting, flags = "Success and Failure", "/success:enable /failure:enable"
	case "^[13]$":
		setting, flags = "Success (auditing Failure as well is allowed)", "/success:enable"
	case "^[23]$":
		setting, flags = "Failure (auditing Success as well is allowed)", "/failure:enable"
	case "^1$":
		setting, flags = "Success only", "/success:enable /failure:disable"
	case "^2$":
		setting, flags = "Failure only", "/success:disable /failure:enable"
	case "^0$":
		setting, flags = "No Auditing", "/success:disable /failure:disable"
	default:
		return "", fmt.Errorf("%s: cannot translate %q", subcategory, some[0])
	}
	gpoName := "Audit " + subcategory
	if subcategory == "Plug and Play Events" {
		gpoName = "Audit PNP Activity"
	}
	return fmt.Sprintf("Audit %s for the subcategory %q:\n\nauditpol.exe /set \"/subcategory:%s\" %s\n\n"+
		"Group Policy: %sAdvanced Audit Policy Configuration\\Audit Policies\\%s\\%s\n"+
		"The advanced audit policy only takes effect when \"Audit: Force audit policy subcategory settings to override audit policy category settings\" is enabled.\n\n%s",
		setting, subcategory, guid, flags, securitySettings, category, gpoName, gpoNote), nil
}

// --- services, firewall, per-user policies ---------------------------------------

func serviceRemediation(name string, expect []string) (string, error) {
	some, _ := expectations(expect)
	if len(some) != 1 || some[0] != "^(Disabled|NotInstalled)$" {
		return "", fmt.Errorf("service %s: unsupported expectation %v", name, expect)
	}
	return fmt.Sprintf("Disable the service %s, or remove the feature or application that installs it:\n\n"+
		"Stop-Service -Name %s -Force -ErrorAction SilentlyContinue\nSet-Service -Name %s -StartupType Disabled\n\n"+
		"Group Policy: %sSystem Services, the service %s (listed by its display name) with startup mode Disabled.\n\n%s",
		name, psQuote(name), psQuote(name), securitySettings, name, gpoNote), nil
}

func firewallRemediation(profile, property string, expect []string) (string, error) {
	some, _ := expectations(expect)
	if len(some) != 1 {
		return "", fmt.Errorf("firewall %s.%s: unsupported expectation %v", profile, property, expect)
	}
	req, ok := regexRequirement(some[0])
	if !ok || strings.Contains(req.text, " ") {
		return "", fmt.Errorf("firewall %s.%s: cannot translate %q", profile, property, some[0])
	}
	return fmt.Sprintf("Set %s of the %s firewall profile to %s:\n\nSet-NetFirewallProfile -Profile %s -%s %s\n\n"+
		"Group Policy: %sWindows Defender Firewall with Advanced Security, properties of the %s profile.\n\n%s",
		property, profile, req.text, profile, property, req.text, securitySettings, profile, gpoNote), nil
}

func perUserRemediation(subpath, name string, data any) (string, error) {
	var ps, shown string
	switch v := data.(type) {
	case float64: // collector_targets.json is decoded with encoding/json
		if v != float64(int64(v)) {
			return "", fmt.Errorf("per-user value %s: %v is not an integer", name, v)
		}
		shown = strconv.FormatInt(int64(v), 10)
		ps = psSetValue(`HKCU\`+subpath, name, "REG_DWORD", shown)
		shown += " (REG_DWORD)"
	default:
		return "", fmt.Errorf("per-user value %s: unsupported data %v", name, data)
	}
	return fmt.Sprintf("Set the per-user registry value %s in HKCU\\%s to %s for every user, "+
		"preferably with a Group Policy Object (User Configuration). For the user who runs the command:\n\n%s\n\n"+
		"The check inspects the profiles of all users that are loaded.", name, subpath, shown, ps), nil
}

// winRemediation describes how to fix a check that collects the snapshot
// value key; exec is the upstream command for command checks.
func winRemediation(key string, expect []string, exec string) (string, error) {
	kind, rest, _ := strings.Cut(key, ".")
	switch kind {
	case "SystemAccess":
		return secpolRemediation(rest, expect, exec)
	case "PrivilegeRights":
		return userRightRemediation(rest, expect)
	case "AuditPolicy":
		for _, t := range winTargets.AuditPol {
			if t.Rule == rest {
				guid, sub := auditSubcategory(t.Subcategory, t.GUID)
				return auditRemediation(sub, guid, expect)
			}
		}
	case "Service":
		return serviceRemediation(rest, expect)
	case "Firewall":
		profile, property, _ := strings.Cut(rest, ".")
		return firewallRemediation(profile, property, expect)
	case "HKU":
		for _, t := range winTargets.HKU {
			if t.Rule == rest {
				return perUserRemediation(t.Subpath, t.Name, t.Data)
			}
		}
	}
	return "", fmt.Errorf("no remediation for %s", key)
}

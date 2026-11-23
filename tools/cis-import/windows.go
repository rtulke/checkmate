package main

// Windows benchmarks. The ansible-lockdown Windows audits read most values
// from one shared snapshot (a single secedit export, a single auditpol call,
// ...) that run_audit.ps1 writes before goss runs. checkmate checks stay
// independent of each other, so every generated check collects exactly the
// value it needs itself, with the same logic as the upstream collector.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// snapshotSentinel replaces the snapshot directory variable while rendering,
// so references to snapshot files can be found and rewritten.
const snapshotSentinel = "CHECKMATE_SNAPSHOT"

// windowsTargets mirrors collector_targets.json.
type windowsTargets struct {
	AuditPol []struct {
		Rule        string `json:"rule"`
		Subcategory string `json:"subcategory"`
		GUID        string `json:"guid"`
	} `json:"auditpol"`
	HKU []struct {
		Rule    string `json:"rule"`
		Subpath string `json:"subpath"`
		Name    string `json:"name"`
		Data    any    `json:"data"`
	} `json:"hku"`
}

var winTargets windowsTargets

// auditSubcategories maps audit subcategory names to their GUIDs (taken from
// the collector targets of the server audits). auditpol is called with the
// GUID: it does not depend on the display language, and some upstream names
// are wrong ("PNP Activity" is "Plug and Play Events").
var auditSubcategories = map[string]string{
	"Account Lockout":                    "{0CCE9217-69AE-11D9-BED3-505054503030}",
	"Application Group Management":       "{0CCE9239-69AE-11D9-BED3-505054503030}",
	"Audit Policy Change":                "{0CCE922F-69AE-11D9-BED3-505054503030}",
	"Authentication Policy Change":       "{0CCE9230-69AE-11D9-BED3-505054503030}",
	"Authorization Policy Change":        "{0CCE9231-69AE-11D9-BED3-505054503030}",
	"Computer Account Management":        "{0CCE9236-69AE-11D9-BED3-505054503030}",
	"Credential Validation":              "{0CCE923F-69AE-11D9-BED3-505054503030}",
	"Detailed File Share":                "{0CCE9244-69AE-11D9-BED3-505054503030}",
	"Directory Service Access":           "{0CCE923B-69AE-11D9-BED3-505054503030}",
	"Directory Service Changes":          "{0CCE923C-69AE-11D9-BED3-505054503030}",
	"Distribution Group Management":      "{0CCE9238-69AE-11D9-BED3-505054503030}",
	"File Share":                         "{0CCE9224-69AE-11D9-BED3-505054503030}",
	"Group Membership":                   "{0CCE9249-69AE-11D9-BED3-505054503030}",
	"IPsec Driver":                       "{0CCE9213-69AE-11D9-BED3-505054503030}",
	"Kerberos Authentication Service":    "{0CCE9242-69AE-11D9-BED3-505054503030}",
	"Kerberos Service Ticket Operations": "{0CCE9240-69AE-11D9-BED3-505054503030}",
	"Logoff":                             "{0CCE9216-69AE-11D9-BED3-505054503030}",
	"Logon":                              "{0CCE9215-69AE-11D9-BED3-505054503030}",
	"MPSSVC Rule-Level Policy Change":    "{0CCE9232-69AE-11D9-BED3-505054503030}",
	"Other Account Management Events":    "{0CCE923A-69AE-11D9-BED3-505054503030}",
	"Other Logon/Logoff Events":          "{0CCE921C-69AE-11D9-BED3-505054503030}",
	"Other Object Access Events":         "{0CCE9227-69AE-11D9-BED3-505054503030}",
	"Other Policy Change Events":         "{0CCE9234-69AE-11D9-BED3-505054503030}",
	"Other System Events":                "{0CCE9214-69AE-11D9-BED3-505054503030}",
	"Plug and Play Events":               "{0CCE9248-69AE-11D9-BED3-505054503030}",
	"Process Creation":                   "{0CCE922B-69AE-11D9-BED3-505054503030}",
	"Removable Storage":                  "{0CCE9245-69AE-11D9-BED3-505054503030}",
	"Security Group Management":          "{0CCE9237-69AE-11D9-BED3-505054503030}",
	"Security State Change":              "{0CCE9210-69AE-11D9-BED3-505054503030}",
	"Security System Extension":          "{0CCE9211-69AE-11D9-BED3-505054503030}",
	"Sensitive Privilege Use":            "{0CCE9228-69AE-11D9-BED3-505054503030}",
	"Special Logon":                      "{0CCE921B-69AE-11D9-BED3-505054503030}",
	"System Integrity":                   "{0CCE9212-69AE-11D9-BED3-505054503030}",
	"User Account Management":            "{0CCE9235-69AE-11D9-BED3-505054503030}",
}

var guidPattern = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)

// auditSubcategory returns the GUID to query and a display name.
func auditSubcategory(name, guid string) (string, string) {
	if guidPattern.MatchString(name) {
		guid, name = name, ""
	}
	if name == "PNP Activity" {
		name = "Plug and Play Events"
	}
	if guid == "" {
		guid = auditSubcategories[name]
	}
	guid = strings.ToUpper(guid)
	if name == "" {
		for n, g := range auditSubcategories {
			if strings.EqualFold(g, guid) {
				name = n
			}
		}
	}
	if name == "" {
		name = guid
	}
	return guid, name
}

func (b benchmark) windows() bool { return b.Package == "windows" }

func loadWindowsTargets(src string) error {
	winTargets = windowsTargets{}
	data, err := os.ReadFile(filepath.Join(src, "collector_targets.json"))
	if err != nil {
		return fmt.Errorf("collector_targets.json: %w", err)
	}
	return json.Unmarshal(data, &winTargets)
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

var hives = map[string]string{
	"HKLM": "HKEY_LOCAL_MACHINE", "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
	"HKU": "HKEY_USERS", "HKEY_USERS": "HKEY_USERS",
	"HKCU": "HKEY_CURRENT_USER", "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
}

var shortHives = map[string]string{"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_USERS": "HKU", "HKEY_CURRENT_USER": "HKCU"}

// winTextKey is the key in texts/windows.yml of a snapshot value.
func winTextKey(key string) string {
	kind, rest, _ := strings.Cut(key, ".")
	switch kind {
	case "AuditPolicy":
		for _, t := range winTargets.AuditPol {
			if t.Rule == rest {
				_, sub := auditSubcategory(t.Subcategory, t.GUID)
				return "AuditPolicy." + sub
			}
		}
	case "HKU":
		for _, t := range winTargets.HKU {
			if t.Rule == rest {
				return `HKU\` + t.Subpath + `\` + t.Name
			}
		}
	}
	return key
}

var regKinds = map[string]string{
	"REG_DWORD": "DWord", "REG_QWORD": "QWord", "REG_SZ": "String",
	"REG_EXPAND_SZ": "ExpandString", "REG_MULTI_SZ": "MultiString", "REG_BINARY": "Binary",
}

// winRegistryCheck checks one registry value. The command prints ABSENT or
// "<kind>=<value>" (multi-string values joined with |).
func winRegistryCheck(c check, name string, attrs map[string]any) []check {
	if strings.HasSuffix(name, `\`) {
		return winRegistryKeyCheck(c, strings.TrimSuffix(name, `\`), attrs)
	}
	i := strings.LastIndex(name, `\`)
	if i < 0 {
		return nil
	}
	keyPath, valueName := name[:i], name[i+1:]
	// "KEY::NAME" separates a value name that contains backslashes, such
	// as the hardened UNC path \\*\NETLOGON.
	if j := strings.Index(name, "::"); j >= 0 {
		keyPath, valueName = name[:j], name[j+2:]
	}
	hive := keyPath
	rest := ""
	if j := strings.Index(keyPath, `\`); j >= 0 {
		hive, rest = keyPath[:j], keyPath[j+1:]
	}
	full, ok := hives[strings.ToUpper(hive)]
	if !ok {
		return nil
	}
	c.Run = fmt.Sprintf(`$k = Get-Item -LiteralPath %s -ErrorAction SilentlyContinue
$n = %s
if ($null -eq $k -or $null -eq $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')) { 'ABSENT' }
else { '{0}={1}' -f $k.GetValueKind($n), (@($k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')) -join '|') }`,
		psQuote(`Registry::`+full+`\`+rest), psQuote(valueName))

	location := strings.ToUpper(hive) + `\` + rest
	c.TextKey = shortHives[full] + `\` + rest + `\` + valueName
	regType := strings.ToUpper(str(attrs["type"]))
	if exists, ok := attrs["exists"].(bool); ok && !exists {
		c.Name = firstLine(fmt.Sprintf("Registry value %s is not set (%s)", valueName, location), 120)
		c.Expect = []string{yamlString("== ABSENT")}
		c.Remediation = registryRemoval(location, valueName)
		return []check{c}
	}
	value, hasValue := attrs["value"]
	if !hasValue {
		c.Name = firstLine(fmt.Sprintf("Registry value %s is set (%s)", valueName, location), 120)
		c.Expect = []string{yamlString("!= ABSENT")}
		c.Remediation = registryAnyValue(location, valueName, regType)
		return []check{c}
	}
	kind := regKinds[regType]
	// A value given as {match-regexp: RE} must match RE.
	if m, ok := value.(map[string]any); ok {
		re := str(m["match-regexp"])
		if re == "" {
			fmt.Fprintf(os.Stderr, "  skipped %s: unsupported registry value matcher %v\n", c.ID, m)
			return nil
		}
		prefix := "[A-Za-z]+"
		if kind != "" {
			prefix = kind
		}
		c.Name = firstLine(fmt.Sprintf("Registry value %s matches %s (%s)", valueName, displayValue(re), location), 120)
		if strings.HasPrefix(re, "^") {
			re = re[1:]
		} else {
			re = ".*" + re
		}
		c.Expect = []string{yamlString("~ ^" + prefix + "=" + re)}
		c.Remediation = registryPattern(location, valueName, regType, str(m["match-regexp"]))
		return []check{c}
	}
	text := strings.ReplaceAll(fmt.Sprint(value), "\n", "|")
	c.Name = firstLine(fmt.Sprintf("Registry value %s is %s (%s)", valueName, displayValue(text), location), 120)
	if kind == "" {
		c.Expect = []string{yamlString("~ ^[A-Za-z]+=" + regexp.QuoteMeta(text) + "$")}
	} else {
		c.Expect = []string{yamlString("== " + kind + "=" + text)}
	}
	c.Remediation = registryValue(location, valueName, regType, value)
	return []check{c}
}

// winRegistryKeyCheck checks whether a registry key exists.
func winRegistryKeyCheck(c check, key string, attrs map[string]any) []check {
	hive, rest, _ := strings.Cut(key, `\`)
	full, ok := hives[strings.ToUpper(hive)]
	if !ok || rest == "" {
		return nil
	}
	location := strings.ToUpper(hive) + `\` + rest
	c.TextKey = shortHives[full] + `\` + rest + `\`
	c.Run = fmt.Sprintf(`if (Test-Path -LiteralPath %s) { 'PRESENT' } else { 'ABSENT' }`, psQuote(`Registry::`+full+`\`+rest))
	if exists, ok := attrs["exists"].(bool); ok && !exists {
		c.Name = firstLine(fmt.Sprintf("Registry key %s does not exist", location), 120)
		c.Expect = []string{yamlString("== ABSENT")}
		c.Remediation = fmt.Sprintf("Remove the registry key %s:\n\nRemove-Item -LiteralPath %s -Recurse\n\n%s",
			location, psQuote(psPath(location)), gpoNote)
		return []check{c}
	}
	c.Name = firstLine(fmt.Sprintf("Registry key %s exists", location), 120)
	c.Expect = []string{yamlString("== PRESENT")}
	c.Remediation = fmt.Sprintf("Create the registry key %s:\n\nNew-Item -Path %s -Force | Out-Null\n\n%s",
		location, psQuote(psPath(location)), gpoNote)
	return []check{c}
}

func displayValue(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 40 {
		return s[:37] + "…"
	}
	return s
}

var snapshotPath = regexp.MustCompile(snapshotSentinel + `[\\/]+([A-Za-z0-9_.-]+)`)

// winFileCheck turns a check of a snapshot file into a check that collects
// the value itself and matches the same patterns against it.
func winFileCheck(c check, attrs map[string]any) []check {
	m := snapshotPath.FindStringSubmatch(str(attrs["path"]))
	if m == nil {
		return nil
	}
	key := m[1]
	collector, what, err := winCollector(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  skipped %s: %v\n", c.ID, err)
		return nil
	}
	c.Run = collector
	c.Name = what
	c.Expect = patternConditions(attrs["contents"])
	if len(c.Expect) == 0 {
		c.Expect = []string{yamlString("!empty")}
	}
	c.Remediation = remediationOrWarn(c.ID, key, c.Expect, "")
	c.TextKey = winTextKey(key)
	return []check{c}
}

var innerCommand = regexp.MustCompile(`(?s)^\s*powershell(\.exe)?\s+(-\w+\s+)*-Command\s+"(.*)"\s*$`)
var snapshotJoin = regexp.MustCompile(`'` + snapshotSentinel + `'`)

// winCommandCheck runs the PowerShell of an upstream command check directly
// and collects the snapshot values it reads into a private directory first.
func winCommandCheck(c check, name string, attrs map[string]any) []check {
	exec := strings.TrimSpace(str(attrs["exec"]))
	if m := innerCommand.FindStringSubmatch(exec); m != nil {
		exec = m[3]
	}
	keys := map[string]bool{}
	for _, m := range regexp.MustCompile(`'`+snapshotSentinel+`'\s*'([^']+)'`).FindAllStringSubmatch(exec, -1) {
		keys[m[1]] = true
	}
	var b strings.Builder
	what := humanize(name)
	if len(keys) > 0 {
		b.WriteString("$snap = Join-Path $env:TEMP ('checkmate-' + [guid]::NewGuid().ToString())\n")
		b.WriteString("New-Item -ItemType Directory -Path $snap | Out-Null\ntry {\n")
		for _, key := range sortedKeys(keys) {
			collector, desc, err := winCollector(key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  skipped %s: %v\n", c.ID, err)
				return nil
			}
			what = desc
			fmt.Fprintf(&b, "  $value = & {\n%s\n  }\n", indent(collector, "    "))
			fmt.Fprintf(&b, "  [IO.File]::WriteAllText((Join-Path $snap %s), ((@($value) -join \"`n\")))\n", psQuote(key))
		}
		b.WriteString(indent(snapshotJoin.ReplaceAllString(exec, "$$snap"), "  "))
		b.WriteString("\n} finally {\n  Remove-Item -LiteralPath $snap -Recurse -Force -ErrorAction SilentlyContinue\n}")
	} else {
		b.WriteString(exec)
	}
	c.Run = b.String()
	c.Name = what
	if len(keys) == 1 {
		c.Remediation = remediationOrWarn(c.ID, sortedKeys(keys)[0], nil, exec)
		c.TextKey = winTextKey(sortedKeys(keys)[0])
	} else {
		fmt.Fprintf(os.Stderr, "  %s: no remediation, the command reads %d values\n", c.ID, len(keys))
	}
	c.AllowAnyRC = true
	c.Expect = append([]string{rcCondition(exitCodes(attrs["exit-status"]))}, patternConditions(attrs["stdout"])...)
	return []check{c}
}

// remediationOrWarn reports checks the remediation generator cannot
// describe, so a gap is noticed when the upstream content changes.
func remediationOrWarn(id, key string, expect []string, exec string) string {
	r, err := winRemediation(key, expect, exec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s: no remediation: %v\n", id, err)
	}
	return r
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

// secedit exports one area to a private file and prints the lines.
const seceditExport = `$inf = Join-Path $env:TEMP ('checkmate-' + [guid]::NewGuid().ToString() + '.inf')
try {
  & secedit.exe /export /areas %s /cfg $inf /quiet | Out-Null
  if (-not (Test-Path -LiteralPath $inf)) { throw 'secedit /export failed; checkmate must run as administrator' }
  $lines = Get-Content -LiteralPath $inf
} finally {
  Remove-Item -LiteralPath $inf -Force -ErrorAction SilentlyContinue
}`

// winCollector returns PowerShell that prints the value upstream stores in
// the snapshot file key, plus a check name.
func winCollector(key string) (string, string, error) {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unknown snapshot key %q", key)
	}
	kind, rest := parts[0], parts[1]
	switch kind {
	case "SystemAccess":
		return fmt.Sprintf(seceditExport, "SECURITYPOLICY") + fmt.Sprintf(`
$v = 'ABSENT'
foreach ($line in $lines) { if ($line -match '^\s*%s\s*=\s*(.*)$') { $v = $Matches[1].Trim().Trim('"') } }
$v`, regexp.QuoteMeta(rest)), fmt.Sprintf("Security policy setting %s", rest), nil

	case "PrivilegeRights":
		return fmt.Sprintf(seceditExport, "USER_RIGHTS") + fmt.Sprintf(`
$members = @()
foreach ($line in $lines) {
  if ($line -match '^\s*%s\s*=\s*(.*)$') {
    $members = @($Matches[1].Split(',') | Where-Object { $_.Trim() -ne '' } | ForEach-Object {
      $t = $_.Trim().TrimStart('*')
      if ($t -like 'S-1-*') { $t } else {
        try { (New-Object System.Security.Principal.NTAccount($t)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { "UNRESOLVED=$t" }
      }
    } | Sort-Object -Unique)
  }
}
if ($members.Count -eq 0) { 'NONE' } else { $members -join ',' }`, regexp.QuoteMeta(rest)), fmt.Sprintf("User right %s is assigned only as required", rest), nil

	case "AuditPolicy":
		sub, guid := "", ""
		for _, t := range winTargets.AuditPol {
			if t.Rule == rest {
				sub, guid = t.Subcategory, t.GUID
			}
		}
		if sub == "" {
			return "", "", fmt.Errorf("no audit subcategory for rule %s", rest)
		}
		guid, sub = auditSubcategory(sub, guid)
		query := guid
		if query == "" {
			query = sub
		}
		return fmt.Sprintf(`$rows = @(& auditpol.exe /get ('/subcategory:' + %s) /r 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'auditpol failed; checkmate must run as administrator' }
$map = @{ 'No Auditing' = 0; 'Success' = 1; 'Failure' = 2; 'Success and Failure' = 3 }
$v = 'ABSENT'
foreach ($row in $rows) {
  $f = $row.Split(',')
  if ($f.Count -ge 5 -and $f[2].Trim() -ne 'Subcategory' -and $f[2].Trim() -ne '') {
    $i = $f[4].Trim()
    if ($map.ContainsKey($i)) { $v = $map[$i] } else { $v = 'UNKNOWN=' + $i }
  }
}
$v`, psQuote(query)), fmt.Sprintf("Audit policy %s is configured", sub), nil

	case "Service":
		return fmt.Sprintf(`$s = Get-Service -Name %s -ErrorAction SilentlyContinue
if ($null -eq $s) { 'NotInstalled' } else { $s.StartType.ToString() }`, psQuote(rest)),
			fmt.Sprintf("Service %s is disabled or not installed", rest), nil

	case "Firewall":
		p := strings.SplitN(rest, ".", 2)
		if len(p) != 2 {
			return "", "", fmt.Errorf("unknown firewall key %q", key)
		}
		return fmt.Sprintf(`$p = Get-NetFirewallProfile -PolicyStore ActiveStore -Name %s -ErrorAction SilentlyContinue
if ($null -eq $p) { 'ABSENT' } else { $p.%s.ToString() }`, psQuote(p[0]), p[1]),
			fmt.Sprintf("Windows Firewall %s profile: %s is in force", p[0], p[1]), nil

	case "HKU":
		for _, t := range winTargets.HKU {
			if t.Rule != rest {
				continue
			}
			return fmt.Sprintf(`$sids = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
  Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
  Select-Object -ExpandProperty PSChildName)
if ($sids.Count -eq 0) { 'NONCOMPLIANT no_user_hives_loaded'; return }
$bad = @()
foreach ($sid in $sids) {
  $actual = (Get-ItemProperty -LiteralPath ('Registry::HKEY_USERS\' + $sid + '\' + %s) -Name %s -ErrorAction SilentlyContinue).%s
  if ($null -eq $actual) { $bad += "$sid=absent" } elseif ("$actual" -ne %s) { $bad += "$sid=$actual" }
}
if ($bad.Count -eq 0) { "COMPLIANT profiles=$($sids.Count)" } else { 'NONCOMPLIANT ' + ($bad -join ' ') }`,
					psQuote(t.Subpath), psQuote(t.Name), t.Name, psQuote(fmt.Sprint(t.Data))),
				fmt.Sprintf("Per-user policy %s is set in every loaded profile", t.Name), nil
		}
		return "", "", fmt.Errorf("no per-user target for rule %s", rest)
	}
	return "", "", fmt.Errorf("unknown snapshot key %q", key)
}

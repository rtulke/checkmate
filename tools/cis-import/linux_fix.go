package main

// Remediation of the Linux checks, generated from the goss resource a check
// was converted from: package, service, kernel parameter, mount, file
// attributes and content, user or group. Command checks run arbitrary
// upstream commands; what fixes them cannot be derived from the command, so
// they get no remediation. No benchmark text is used.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// packageManager returns the install and remove commands of a benchmark.
func packageManager(b benchmark) (install, remove string) {
	switch {
	case b.Package == "dpkg":
		return "apt-get install", "apt-get purge"
	case strings.HasPrefix(b.platform(), "suse"):
		return "zypper install", "zypper remove"
	case b.platform() == "rhel7" || b.platform() == "amazon2":
		return "yum install", "yum remove"
	}
	return "dnf install", "dnf remove"
}

func packageRemediation(b benchmark, pkg string, installed bool) string {
	install, remove := packageManager(b)
	if installed {
		return fmt.Sprintf("Install the package %s:\n\n%s %s", pkg, install, pkg)
	}
	return fmt.Sprintf("Remove the package %s, unless the system needs it:\n\n%s %s", pkg, remove, pkg)
}

func packageVersionRemediation(b benchmark, pkg, op, version string) string {
	install, _ := packageManager(b)
	update := strings.Replace(install, " install", " upgrade", 1)
	if strings.HasPrefix(install, "apt-get") {
		update = "apt-get install --only-upgrade"
	}
	if strings.HasPrefix(install, "zypper") {
		update = "zypper update"
	}
	return fmt.Sprintf("Update the package %s to a version %s %s:\n\n%s %s", pkg, op, version, update, pkg)
}

func unitRemediation(name, state string) string {
	switch state {
	case "enabled":
		return fmt.Sprintf("Enable the service %s:\n\nsystemctl enable %s", name, name)
	case "not enabled":
		return fmt.Sprintf("Disable the service %s, unless the system needs it:\n\nsystemctl disable %s\n\n"+
			"To keep other units from starting it, mask it instead: systemctl mask %s", name, name, name)
	case "running":
		return fmt.Sprintf("Start the service %s:\n\nsystemctl start %s", name, name)
	}
	return fmt.Sprintf("Stop the service %s, unless the system needs it:\n\nsystemctl stop %s", name, name)
}

func sysctlRemediation(name, value string) string {
	return fmt.Sprintf("Set the kernel parameter %s to %s, now and at boot:\n\n"+
		"sysctl -w %s\nprintf '%%s\\n' %s >> /etc/sysctl.d/60-hardening.conf\n\n"+
		"Remove other settings of %s from /etc/sysctl.conf and /etc/sysctl.d/: the file read last wins.",
		name, value, shellQuote(name+"="+value), shellQuote(name+" = "+value), name)
}

func mountRemediation(mp string, opts, fs []string) string {
	tmpfs := len(fs) == 1 && fs[0] == "tmpfs"
	var b strings.Builder
	switch {
	case len(opts) > 0:
		word := "options"
		if len(opts) == 1 {
			word = "option"
		}
		fmt.Fprintf(&b, "Mount %s with the %s %s: add %s to the options of %s in /etc/fstab (or its systemd mount unit), then apply:\n\nmount -o remount %s",
			mp, word, strings.Join(opts, ","), map[bool]string{true: "it", false: "them"}[len(opts) == 1], mp, shellQuote(mp))
		b.WriteString("\n\nIf " + mp + " is not a separate file system yet, create one first.")
	case tmpfs:
		fmt.Fprintf(&b, "Mount a tmpfs file system on %s with an entry in /etc/fstab or a systemd mount unit.", mp)
	default:
		fmt.Fprintf(&b, "Put %s on a separate file system (partition or logical volume) and mount it there with an entry in /etc/fstab or a systemd mount unit. This needs a new file system and moving the existing data.", mp)
		if mp == "/tmp" {
			b.WriteString(" A tmpfs mount on /tmp, e.g. with systemd's tmp.mount, counts as well.")
		}
	}
	if len(fs) > 0 && !(tmpfs && len(opts) == 0) {
		fmt.Fprintf(&b, "\n\nAllowed file system types: %s.", strings.Join(fs, ", "))
	}
	return b.String()
}

// chmodRemoval returns a symbolic chmod mode that removes exactly the
// permission bits in mask, e.g. "g-w,o-rwx". It never adds a permission.
// The sticky bit is removed with "a-t": busybox ignores "o-t".
func chmodRemoval(mask int64) string {
	var parts []string
	classes := []struct {
		who     string
		shift   uint
		special int64
	}{{"u", 6, 0o4000}, {"g", 3, 0o2000}, {"o", 0, 0}}
	for _, c := range classes {
		bits := ""
		for i, r := range "rwx" {
			if mask&(1<<(c.shift+2-uint(i))) != 0 {
				bits += string(r)
			}
		}
		if c.special != 0 && mask&c.special != 0 {
			bits += "s"
		}
		if bits != "" {
			parts = append(parts, c.who+"-"+bits)
		}
	}
	if mask&0o1000 != 0 {
		parts = append(parts, "a-t")
	}
	return strings.Join(parts, ",")
}

// fileAttrRemediation describes how to give a file the expected type,
// link target, owner, group and mode.
func fileAttrRemediation(path, filetype, target string, owners, groups []string, mask int64) string {
	q := shellQuote(path)
	var steps, cmds []string
	switch {
	case target != "":
		steps = append(steps, "point the link to "+target)
		cmds = append(cmds, fmt.Sprintf("ln -sfn %s %s", shellQuote(target), q))
	case filetype != "":
		steps = append(steps, "make it a "+filetype)
	}
	switch {
	case len(owners) > 0 && len(groups) > 0:
		steps = append(steps, fmt.Sprintf("set owner %s and group %s", strings.Join(owners, " or "), strings.Join(groups, " or ")))
		cmds = append(cmds, fmt.Sprintf("chown %s:%s %s", owners[0], groups[0], q))
	case len(owners) > 0:
		steps = append(steps, "set owner "+strings.Join(owners, " or "))
		cmds = append(cmds, fmt.Sprintf("chown %s %s", owners[0], q))
	case len(groups) > 0:
		steps = append(steps, "set group "+strings.Join(groups, " or "))
		cmds = append(cmds, fmt.Sprintf("chgrp %s %s", groups[0], q))
	}
	// chmod comes last: chown clears the setuid and setgid bits.
	if m := chmodRemoval(mask); m != "" {
		steps = append(steps, "remove the permissions "+m)
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", m, q))
	}
	if len(steps) == 0 {
		return fmt.Sprintf("Create %s.", path)
	}
	list := steps[0]
	if n := len(steps); n > 1 {
		list = strings.Join(steps[:n-1], ", ") + " and " + steps[n-1]
	}
	text := fmt.Sprintf("Create %s if it is missing, then %s", path, list)
	if len(cmds) == 0 {
		return text + "."
	}
	return text + ":\n\n" + strings.Join(cmds, "\n")
}

func fileAbsentRemediation(path string) string {
	return fmt.Sprintf("Remove %s, unless the system needs it:\n\nrm %s", path, shellQuote(path))
}

// contentRemediation lists the conditions on the lines of a file. It
// returns "" if a condition cannot be described.
func contentRemediation(path string, expect []string) string {
	var conds []string
	for _, e := range expect {
		d, ok := describeCondition(e)
		if !ok {
			return ""
		}
		if d != "" {
			conds = append(conds, "- "+d)
		}
	}
	if len(conds) == 0 {
		return ""
	}
	where := path
	if path == "/etc/ssh/sshd_config" {
		where = "/etc/ssh/sshd_config or a file in /etc/ssh/sshd_config.d/ (the first value of a setting wins)"
	}
	return fmt.Sprintf("Edit %s so that its lines meet these conditions (regular expressions):\n\n%s",
		where, strings.Join(conds, "\n"))
}

// describeCondition turns one expectation of a content check into words.
// The rc condition needs no description; it returns "" for it.
func describeCondition(e string) (string, bool) {
	e = strings.TrimSpace(e)
	if strings.HasPrefix(e, "{ rc:") {
		return "", true
	}
	if inner, ok := strings.CutPrefix(e, "{ any: ["); ok && strings.HasSuffix(inner, "] }") {
		var alts []string
		for _, part := range splitConditions(strings.TrimSuffix(inner, "] }")) {
			d, ok := describeCondition(part)
			if !ok || d == "" {
				return "", false
			}
			alts = append(alts, d)
		}
		return "one of: " + strings.Join(alts, "; or "), true
	}
	if inner, ok := strings.CutPrefix(e, "{ not: { all: ["); ok && strings.HasSuffix(inner, "] } }") {
		var all []string
		for _, part := range splitConditions(strings.TrimSuffix(inner, "] } }")) {
			d, ok := describeCondition(part)
			if !ok || d == "" {
				return "", false
			}
			all = append(all, d)
		}
		return "not all of: " + strings.Join(all, "; "), true
	}
	for _, kind := range []string{"some", "none"} {
		inner, ok := strings.CutPrefix(e, "{ "+kind+": ")
		if !ok || !strings.HasSuffix(inner, " }") {
			continue
		}
		var s string
		if json.Unmarshal([]byte(strings.TrimSuffix(inner, " }")), &s) != nil || !strings.HasPrefix(s, "~ ") {
			return "", false
		}
		if kind == "some" {
			return "a line matches " + s[2:], true
		}
		return "no line matches " + s[2:], true
	}
	return "", false
}

// splitConditions splits "{ ... }, { ... }" at the top level.
func splitConditions(s string) []string {
	var out []string
	depth, start := 0, 0
	inString, escaped := false, false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inString:
			escaped = true
		case r == '"':
			inString = !inString
		case inString:
		case r == '{':
			depth++
		case r == '}':
			depth--
		case r == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if rest := strings.TrimSpace(s[start:]); rest != "" {
		out = append(out, rest)
	}
	return out
}

func accountRemediation(kind, name string, exists bool) string {
	switch {
	case kind == "group" && exists:
		return fmt.Sprintf("Create the group %s:\n\ngroupadd %s", name, name)
	case kind == "group":
		return fmt.Sprintf("Remove the group %s, unless the system needs it:\n\ngroupdel %s", name, name)
	case exists:
		return fmt.Sprintf("Create the user %s:\n\nuseradd %s", name, name)
	}
	return fmt.Sprintf("Remove the user %s, unless the system needs it:\n\nuserdel %s", name, name)
}

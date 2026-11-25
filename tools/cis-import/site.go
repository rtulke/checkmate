package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Upstream audits a host that its own Ansible role has hardened, so some
// tests look for the values of that role: a group name, a user name, the
// file the role writes. The benchmark leaves these to the site. The fixes
// below test what the benchmark asks for instead.

// resourceFix replaces the test of an upstream resource, by its name.
type resourceFix struct {
	why   string
	names []string
	// rewrite changes the attributes; the resource is then converted as
	// usual. Without it the resource becomes the command check below.
	rewrite     func(attrs map[string]any)
	name        string
	run         string
	expect      []string
	remediation string
}

// suPamWheel matches a pam_wheel line that restricts su to a group, whatever
// the group is called.
const suPamWheel = `/^\s*auth\s+(required|requisite)\s+pam_wheel\.so\s+(\S+\s+)*(use_uid\s+(\S+\s+)*group=\S+|group=\S+\s+(\S+\s+)*use_uid)(\s|$)/`

var resourceFixes = []resourceFix{
	{
		why:   "upstream looks for the users of its test setup (vagrant, nobody) or for the file its role writes",
		names: []string{"sshd_access_limited"},
		name:  "SSH access is limited with AllowUsers, AllowGroups, DenyUsers or DenyGroups",
		run:   `sshd -T 2>/dev/null | grep -Ei '^(allow|deny)(users|groups) +[^ ]'`,
		expect: []string{
			`{ some: "~ ." }`,
		},
		remediation: "Restrict SSH logins to the users or groups that need them with AllowUsers, AllowGroups, DenyUsers or DenyGroups, according to site policy. " +
			"Set the directive in the global section of the sshd configuration (in /etc/ssh/sshd_config before any Match block, or in a file in /etc/ssh/sshd_config.d/ where the distribution includes that directory), then validate and reload the SSH service.\n\n" +
			"echo 'AllowGroups GROUP' > /etc/ssh/sshd_config.d/10-access.conf\nsshd -t\n\n" +
			"When both AllowUsers and AllowGroups are set, a user must match both lists. Make sure your own administrative account is allowed before reloading.",
	},
	{
		why:   "the group that may use su has any name; upstream looks for the name its role uses",
		names: []string{"su_conf", "restrict_su"},
		rewrite: func(attrs map[string]any) {
			for _, key := range []string{"contents", "contains"} {
				list, ok := attrs[key].([]any)
				if !ok {
					continue
				}
				for i, p := range list {
					if strings.Contains(fmt.Sprint(p), "pam_wheel") {
						list[i] = suPamWheel
					}
				}
			}
		},
	},
	{
		why:   "the group that may use su has any name; upstream looks for the name its role uses",
		names: []string{"sugroup_etc_group"},
		name:  "The group that pam_wheel allows to use su has no members",
		run: `g=$(sed -nE 's/^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so[[:space:]](.*[[:space:]])?group=([^[:space:]]+).*/\3/p' /etc/pam.d/su 2>/dev/null | head -n 1)
if [ -z "$g" ]; then echo "pam_wheel in /etc/pam.d/su names no group"; exit 0; fi
e=$(getent group "$g")
if [ -z "$e" ]; then echo "group $g does not exist"; exit 0; fi
echo "$e" | awk -F: '$4 != "" {print "group " $1 " has members: " $4}'`,
		expect: []string{"empty"},
		remediation: "Create a group without members and restrict su to it with pam_wheel in /etc/pam.d/su. The group can have any name; sugroup is an example.\n\n" +
			"groupadd sugroup\ngpasswd -M '' sugroup\n" +
			`grep -Eq '^\s*auth\s+(required|requisite)\s+pam_wheel\.so\s.*group=' /etc/pam.d/su || sed -i '/^auth\s\+sufficient\s\+pam_rootok.so/a auth required pam_wheel.so use_uid group=sugroup' /etc/pam.d/su` +
			"\n\nIf pam_wheel already names a group, remove its members instead: gpasswd -M '' GROUP.",
	},
	{
		why:   "upstream looks for the file, user and placeholder hash of its role; the benchmark reads the generated grub.cfg",
		names: []string{"bootloader_password_set"},
		name:  "The boot loader has a superuser and a PBKDF2 password",
		run: `f=/boot/grub/grub.cfg
if [ ! -e "$f" ]; then echo "$f does not exist"; exit 0; fi
grep -Eq '^[[:space:]]*set superusers=' "$f" || echo "no superuser is set in $f"
grep -Eq '^[[:space:]]*password_pbkdf2[[:space:]]+[^[:space:]]+[[:space:]]+grub\.pbkdf2\.sha512\.' "$f" || echo "no PBKDF2 password is set in $f"`,
		expect: []string{"empty"},
		remediation: "Create a password hash, add a superuser with this hash in a file in /etc/grub.d/ and regenerate grub.cfg.\n\n" +
			"grub-mkpasswd-pbkdf2\n\n" +
			"Put these lines, with the hash the command printed, into /etc/grub.d/01_users, make the file executable and run update-grub:\n\n" +
			"#!/bin/sh\ncat <<EOF\nset superusers=\"USER\"\npassword_pbkdf2 USER HASH\nEOF\n\n" +
			"chmod 0700 /etc/grub.d/01_users\nupdate-grub\n\n" +
			"With a superuser set, every boot entry asks for the password unless it has --unrestricted; add that option to CLASS in /etc/grub.d/10_linux if the system has to boot unattended.",
	},
}

// fixResource returns the fix for a resource, if there is one.
func fixResource(name string) *resourceFix {
	name = duplicateSuffix.ReplaceAllString(name, "")
	for i := range resourceFixes {
		for _, n := range resourceFixes[i].names {
			if n == name {
				return &resourceFixes[i]
			}
		}
	}
	return nil
}

// check is the command check that replaces the resource.
func (f *resourceFix) check(c check) []check {
	c.Name = f.name
	c.Run = f.run
	c.AllowAnyRC = true
	c.Expect = f.expect
	c.Remediation = f.remediation
	return []check{c}
}

var alternation = regexp.MustCompile(`\(([A-Za-z0-9_-]+(\|[A-Za-z0-9_-]+)+)\)`)

// dropSiteChoices removes a pattern that asks for one value where another
// pattern of the same resource accepts a list of values that includes it:
// upstream tests the value its role sets next to the values the benchmark
// allows.
func dropSiteChoices(v any) any {
	list, ok := v.([]any)
	if !ok {
		return v
	}
	var out []any
	for i, p := range list {
		covered := false
		for j, q := range list {
			if i != j && covers(fmt.Sprint(q), fmt.Sprint(p)) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// covers reports whether the pattern general is specific with a list of
// alternatives in place of one of them.
func covers(general, specific string) bool {
	if strings.Contains(specific, "(?i)") && !strings.Contains(general, "(?i)") {
		return false
	}
	general = strings.Replace(general, "(?i)", "", 1)
	specific = strings.Replace(specific, "(?i)", "", 1)
	loc := alternation.FindStringSubmatchIndex(general)
	if loc == nil {
		return false
	}
	for _, alt := range strings.Split(general[loc[2]:loc[3]], "|") {
		if general[:loc[0]]+alt+general[loc[1]:] == specific {
			return true
		}
	}
	return false
}

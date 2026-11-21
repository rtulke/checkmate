# Users and groups

Account hygiene on Linux: privileged accounts, password hashes, duplicate IDs, login shells of system accounts and home directory permissions. Checks that read /etc/shadow need root.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/users.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/users.yml)
- :material-format-list-checks: **Checks**  
  13 from 10 definitions, 1 with loops
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/users.yml

# Run the checks
checkmate run examples/system/users.yml

# Override a variable from the command line
checkmate run examples/system/users.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `USR-001` | root is the only account with UID 0 | <span class="sev sev-critical">critical</span> | system, users |
| `USR-002` | No account has an empty password | <span class="sev sev-critical">critical</span> | system, users, passwords |
| `USR-003` | No password uses DES or MD5 hashing | <span class="sev sev-high">high</span> | system, users, passwords |
| `USR-DUP-USER` | No duplicate user names in /etc/passwd | <span class="sev sev-high">high</span> | system, users |
| `USR-DUP-UID` | No duplicate UIDs in /etc/passwd | <span class="sev sev-high">high</span> | system, users |
| `USR-DUP-GROUP` | No duplicate group names in /etc/group | <span class="sev sev-high">high</span> | system, users |
| `USR-DUP-GID` | No duplicate GIDs in /etc/group | <span class="sev sev-high">high</span> | system, users |
| `USR-004` | System accounts cannot log in | <span class="sev sev-medium">medium</span> | system, users |
| `USR-005` | The root group has no additional members | <span class="sev sev-medium">medium</span> | system, users |
| `USR-006` | Home directories are not accessible by others | <span class="sev sev-medium">medium</span> | system, users, files |
| `USR-007` | Passwords expire after at most 365 days | <span class="sev sev-medium">medium</span> | system, users, passwords |
| `USR-008` | root's PATH contains no empty or relative entries | <span class="sev sev-medium">medium</span> | system, users |
| `USR-009` | Default umask is 027 or stricter | <span class="sev sev-low">low</span> | system, users |

## Policy

```yaml title="examples/system/users.yml" linenums="1"
name: Users and groups
version: 1.0.0
description: >
  Account hygiene on Linux: privileged accounts, password hashes, duplicate
  IDs, login shells of system accounts and home directory permissions.
  Checks that read /etc/shadow need root.

vars:
  uid_min: 1000
  max_password_age_days: 365

checks:
  - id: USR-001
    name: root is the only account with UID 0
    tags: [system, users]
    severity: critical
    run: |
      awk -F: '$3 == 0 {print $1}' /etc/passwd
    expect: "== root"

  - id: USR-002
    name: No account has an empty password
    tags: [system, users, passwords]
    severity: critical
    when: facts.os == "linux" and facts.is_root
    run: |
      awk -F: '$2 == "" {print $1}' /etc/shadow
    expect: empty
    remediation: Lock the listed accounts with `passwd -l <user>`.

  - id: USR-003
    name: No password uses DES or MD5 hashing
    tags: [system, users, passwords]
    severity: high
    when: facts.os == "linux" and facts.is_root
    # Locked (! or *) and empty fields are ignored; DES hashes have no $id$ prefix.
    run: |
      awk -F: '$2 ~ /^\$1\$/ || ($2 != "" && $2 !~ /^[!*$]/) {print $1}' /etc/shadow
    expect: empty

  - id: "USR-DUP-{{ item.key | upper }}"
    name: "No duplicate {{ item.value }}"
    tags: [system, users]
    severity: high
    loop:
      user: user names in /etc/passwd
      uid: UIDs in /etc/passwd
      group: group names in /etc/group
      gid: GIDs in /etc/group
    run: |
      file=/etc/{{ "passwd" if item.key in ["user", "uid"] else "group" }}
      field={{ 1 if item.key in ["user", "group"] else 3 }}
      cut -d: -f"$field" "$file" | sort | uniq -d
    expect: empty

  - id: USR-004
    name: System accounts cannot log in
    tags: [system, users]
    when: facts.os == "linux"
    run: |
      awk -F: -v min={{ uid_min }} '$3 < min && $1 !~ /^(root|sync|shutdown|halt)$/ && $7 !~ /(nologin|false)$/ {print $1 " (" $7 ")"}' /etc/passwd
    expect: empty
    remediation: usermod -s /usr/sbin/nologin <account>

  - id: USR-005
    name: The root group has no additional members
    tags: [system, users]
    run: |
      getent group root 2>/dev/null | cut -d: -f4 || awk -F: '$1 == "root" {print $4}' /etc/group
    expect: empty

  - id: USR-006
    name: Home directories are not accessible by others
    tags: [system, users, files]
    when: facts.os == "linux"
    run: |
      awk -F: -v min={{ uid_min }} '$3 >= min && $3 != 65534 {print $6}' /etc/passwd |
        while read -r home; do
          if [ -d "$home" ]; then find "$home" -maxdepth 0 -perm /o+rwx; fi
        done
    expect: empty
    remediation: chmod 750 <home>

  - id: USR-007
    name: "Passwords expire after at most {{ max_password_age_days }} days"
    tags: [system, users, passwords]
    when: facts.os == "linux"
    run: |
      cat /etc/login.defs 2>/dev/null | awk '$1 == "PASS_MAX_DAYS" {print $2}'
    allow_rc: [0, 1]
    expect: ["!empty", "<= {{ max_password_age_days }}"]

  - id: USR-008
    name: root's PATH contains no empty or relative entries
    tags: [system, users]
    when: facts.os == "linux" and facts.is_root
    run: su - root -c 'printf %s "$PATH"'
    expect: '!~ (^|:)\.?(:|$)'

  - id: USR-009
    name: Default umask is 027 or stricter
    tags: [system, users]
    severity: low
    when: facts.os == "linux"
    run: |
      cat /etc/login.defs 2>/dev/null | awk '$1 == "UMASK" {print $2}'
    as: string
    allow_rc: [0, 1]
    expect: "in ['027', '077', '0027', '0077']"
```

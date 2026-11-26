# Users and groups

Account hygiene on Linux: privileged accounts, password hashes, duplicate IDs, login shells of system accounts and home directory permissions. Checks that read /etc/shadow need root.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/users.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/users.yml)
- :material-format-list-checks: **Checks**  
  14 from 11 definitions, 1 with loops
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
| `USR-KEYS-{item}` | authorized_keys of {item} is writable only by its owner | <span class="sev sev-high">high</span> | system, users, ssh |
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
    rationale: Every account with UID 0 has full root rights under a name that nobody watches.
    remediation: Remove the additional account or give it another UID with `usermod -u <uid> <user>`.

  - id: USR-002
    name: No account has an empty password
    tags: [system, users, passwords]
    severity: critical
    when: facts.os == "linux" and facts.is_root
    run: |
      awk -F: '$2 == "" {print $1}' /etc/shadow
    expect: empty
    rationale: An account with an empty password field can be used without any credential.
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
    rationale: DES and MD5 password hashes are cracked quickly on current hardware.
    remediation: Set ENCRYPT_METHOD SHA512 in /etc/login.defs and have the listed users set a new password.

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
    rationale: "Duplicate {{ item.value }} make it unclear which account or group owns a file or caused a log entry."
    remediation: "Rename or renumber the listed entries so that all {{ item.value }} are unique."

  - id: USR-004
    name: System accounts cannot log in
    tags: [system, users]
    when: facts.os == "linux"
    run: |
      awk -F: -v min={{ uid_min }} '$3 < min && $1 !~ /^(root|sync|shutdown|halt)$/ && $7 !~ /(nologin|false)$/ {print $1 " (" $7 ")"}' /etc/passwd
    expect: empty
    rationale: A system account with a login shell allows interactive access as soon as it gets a password or key.
    remediation: usermod -s /usr/sbin/nologin <account>

  - id: USR-005
    name: The root group has no additional members
    tags: [system, users]
    run: |
      getent group root 2>/dev/null | cut -d: -f4 || awk -F: '$1 == "root" {print $4}' /etc/group
    expect: empty
    rationale: Members of the root group can access files that are readable or writable for that group.
    remediation: Remove the listed users with `gpasswd -d <user> root`.

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
    rationale: Home directories open to others expose private files such as shell history and configuration with credentials.
    remediation: chmod 750 <home>

  - id: "USR-KEYS-{{ item }}"
    name: "authorized_keys of {{ item }} is writable only by its owner"
    tags: [system, users, ssh]
    severity: high
    when: facts.os == "linux" and facts.is_root
    # One check per account with a login shell. The account name reaches the
    # command in $CHECKMATE_ITEM, never as part of the command text.
    loop_run: |
      awk -F: '!/^#/ && NF >= 7 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd
    run: |
      home=$(awk -F: -v user="$CHECKMATE_ITEM" '$1 == user {print $6}' /etc/passwd)
      if [ -f "$home/.ssh/authorized_keys" ]; then
        ls -ln "$home/.ssh/authorized_keys" | cut -c6,9
      else
        echo --
      fi
    expect: "--"
    rationale: "Whoever can write the authorized_keys file of {{ item }} can add a key and log in as that account."
    remediation: chmod 600 ~<account>/.ssh/authorized_keys

  - id: USR-007
    name: "Passwords expire after at most {{ max_password_age_days }} days"
    tags: [system, users, passwords]
    when: facts.os == "linux"
    run: |
      cat /etc/login.defs 2>/dev/null | awk '$1 == "PASS_MAX_DAYS" {print $2}'
    allow_rc: [0, 1]
    expect: ["!empty", "<= {{ max_password_age_days }}"]
    rationale: A password that never expires stays usable for an unlimited time after a leak.
    remediation: "Set PASS_MAX_DAYS {{ max_password_age_days }} in /etc/login.defs and apply it to existing accounts with `chage -M {{ max_password_age_days }} <user>`."

  - id: USR-008
    name: root's PATH contains no empty or relative entries
    tags: [system, users]
    when: facts.os == "linux" and facts.is_root
    # Login scripts may print banners; only the PATH= line is used.
    run: su - root -c 'printf "PATH=%s\\n" "$PATH"' 2>/dev/null | sed -n 's/^PATH=//p' | tail -1
    expect: '!~ (^|:)\.?(:|$)'
    rationale: An empty or relative PATH entry makes root run programs from the current directory, where another user may have placed them.
    remediation: Remove empty entries, `.` and relative directories from PATH in root's shell startup files.

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
    rationale: A lax umask makes new files readable by every local user.
    remediation: Set UMASK 027 in /etc/login.defs.
```

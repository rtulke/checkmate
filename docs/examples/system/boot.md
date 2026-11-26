# Boot security

Bootloader configuration permissions and password, Secure Boot and authentication for rescue and emergency mode.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/boot.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/boot.yml)
- :material-format-list-checks: **Checks**  
  5 from 4 definitions, 1 with loops
- :material-monitor: **Platforms**  
  debian, linux, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/boot.yml

# Run the checks
checkmate run examples/system/boot.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `BOOT-001` | Bootloader configuration is not readable by others | <span class="sev sev-high">high</span> | system, boot, files |
| `BOOT-002` | A bootloader password is set | <span class="sev sev-high">high</span> | system, boot |
| `BOOT-003` | Secure Boot is enabled | <span class="sev sev-medium">medium</span> | system, boot |
| `BOOT-AUTH-RESCUE` | rescue mode requires the root password | <span class="sev sev-high">high</span> | system, boot |
| `BOOT-AUTH-EMERGENCY` | emergency mode requires the root password | <span class="sev sev-high">high</span> | system, boot |

## Policy

```yaml title="examples/system/boot.yml" linenums="1"
name: Boot security
version: 1.0.0
description: >
  Bootloader configuration permissions and password, Secure Boot and
  authentication for rescue and emergency mode.

checks:
  - id: BOOT-001
    name: Bootloader configuration is not readable by others
    tags: [system, boot, files]
    severity: high
    run:
      rhel: find /boot/grub2/grub.cfg /boot/grub2/user.cfg -perm /go+rwx 2>/dev/null
      debian: find /boot/grub/grub.cfg -perm /go+rwx 2>/dev/null
      suse: find /boot/grub2/grub.cfg -perm /go+rwx 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: The bootloader configuration can contain the password hash and shows local users how the system boots.
    remediation: chmod 600 /boot/grub*/grub.cfg

  - id: BOOT-002
    name: A bootloader password is set
    tags: [system, boot]
    severity: high
    when: facts.is_root
    run:
      # cat | grep -c prints 0 even if the file does not exist.
      rhel: cat /boot/grub2/user.cfg 2>/dev/null | grep -c '^GRUB2_PASSWORD='
      debian: cat /boot/grub/grub.cfg 2>/dev/null | grep -cE '^[[:space:]]*password(_pbkdf2)?[[:space:]]'
      suse: cat /boot/grub2/grub.cfg 2>/dev/null | grep -cE '^[[:space:]]*password(_pbkdf2)?[[:space:]]'
    allow_rc: [0, 1, 2]
    expect: ">= 1"
    rationale: Without a bootloader password anyone with console access can edit the kernel command line and boot into a root shell.
    remediation: grub2-setpassword (RHEL) or grub-mkpasswd-pbkdf2 (Debian)

  - id: BOOT-003
    name: Secure Boot is enabled
    tags: [system, boot]
    only_if: command -v mokutil
    run: mokutil --sb-state 2>&1
    allow_rc: [0, 1]
    expect: "~ SecureBoot enabled"
    rationale: Without Secure Boot the firmware starts any bootloader or kernel, including a tampered one.
    remediation: Enable Secure Boot in the UEFI firmware setup.

  - id: "BOOT-AUTH-{{ item | upper }}"
    name: "{{ item }} mode requires the root password"
    tags: [system, boot]
    severity: high
    when: facts.os == "linux"
    loop: [rescue, emergency]
    # `systemctl cat` shows the effective unit including drop-in overrides.
    run: |
      systemctl cat {{ item }}.service 2>/dev/null | grep -E '^ExecStart=.*(sulogin|systemd-sulogin-shell)'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: "Without sulogin, booting into {{ item }} mode gives a root shell to anyone at the console."
    remediation: "Remove the drop-in that replaces ExecStart of {{ item }}.service so that the unit starts systemd-sulogin-shell again."
```

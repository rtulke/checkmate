# Kernel hardening

Kernel parameters (sysctl), unused kernel modules and the running kernel version. The sysctl map shows how an operator can be part of the value.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/kernel.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/kernel.yml)
- :material-format-list-checks: **Checks**  
  23 from 5 definitions, 2 with loops
- :material-monitor: **Platforms**  
  alpine, debian, linux, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/kernel.yml

# Run the checks
checkmate run examples/system/kernel.yml

# Override a variable from the command line
checkmate run examples/system/kernel.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `KRN-SYSCTL-fs.protected_hardlinks` | sysctl fs.protected_hardlinks == 1 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-fs.protected_symlinks` | sysctl fs.protected_symlinks == 1 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-fs.suid_dumpable` | sysctl fs.suid_dumpable == 0 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-kernel.dmesg_restrict` | sysctl kernel.dmesg_restrict == 1 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-kernel.kptr_restrict` | sysctl kernel.kptr_restrict >= 1 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-kernel.randomize_va_space` | sysctl kernel.randomize_va_space == 2 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-kernel.sysrq` | sysctl kernel.sysrq == 0 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-kernel.unprivileged_bpf_disabled` | sysctl kernel.unprivileged_bpf_disabled >= 1 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-SYSCTL-kernel.yama.ptrace_scope` | sysctl kernel.yama.ptrace_scope >= 1 | <span class="sev sev-medium">medium</span> | system, kernel, sysctl |
| `KRN-MOD-cramfs` | Kernel module cramfs cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-freevxfs` | Kernel module freevxfs cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-hfs` | Kernel module hfs cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-hfsplus` | Kernel module hfsplus cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-jffs2` | Kernel module jffs2 cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-udf` | Kernel module udf cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-usb-storage` | Kernel module usb-storage cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-dccp` | Kernel module dccp cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-sctp` | Kernel module sctp cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-rds` | Kernel module rds cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-MOD-tipc` | Kernel module tipc cannot be loaded | <span class="sev sev-low">low</span> | system, kernel, modules |
| `KRN-001` | Core dumps of setuid programs are disabled | <span class="sev sev-medium">medium</span> | system, kernel |
| `KRN-002` | Kernel lockdown or Secure Boot is active | <span class="sev sev-low">low</span> | system, kernel, boot |
| `KRN-003` | Running kernel matches the newest installed kernel | <span class="sev sev-medium">medium</span> | system, kernel, updates |

## Policy

```yaml title="examples/system/kernel.yml" linenums="1"
name: Kernel hardening
version: 1.0.0
description: >
  Kernel parameters (sysctl), unused kernel modules and the running kernel
  version. The sysctl map shows how an operator can be part of the value.

vars:
  # Each value is a complete condition, so ranges are possible.
  sysctl_hardening:
    kernel.randomize_va_space: "== 2"
    kernel.kptr_restrict: ">= 1"
    kernel.dmesg_restrict: "== 1"
    kernel.yama.ptrace_scope: ">= 1"
    kernel.unprivileged_bpf_disabled: ">= 1"
    kernel.sysrq: "== 0"
    fs.protected_hardlinks: "== 1"
    fs.protected_symlinks: "== 1"
    fs.suid_dumpable: "== 0"
  disabled_modules: [cramfs, freevxfs, hfs, hfsplus, jffs2, udf, usb-storage, dccp, sctp, rds, tipc]

checks:
  - id: "KRN-SYSCTL-{{ item.key }}"
    name: "sysctl {{ item.key }} {{ item.value }}"
    tags: [system, kernel, sysctl]
    when: facts.os == "linux"
    loop: "{{ sysctl_hardening }}"
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
    remediation: "Set {{ item.key }} in /etc/sysctl.d/99-hardening.conf and run sysctl --system."

  - id: "KRN-MOD-{{ item }}"
    name: "Kernel module {{ item }} cannot be loaded"
    tags: [system, kernel, modules]
    severity: low
    when: facts.os == "linux" and facts.is_root
    loop: "{{ disabled_modules }}"
    # A disabled module resolves to "install /bin/true" (or /bin/false);
    # a module that does not exist at all is fine, too. busybox modprobe
    # (Alpine) has no dry-run, so the configuration is read instead.
    run:
      alpine: grep -rhE '^install[[:space:]]+{{ item }}[[:space:]]' /etc/modprobe.d /lib/modprobe.d 2>/dev/null
      linux: modprobe -n -v {{ item }} 2>&1
    allow_rc: [0, 1, 2]
    expect: { any: ["~ install( {{ item }})? /(usr/)?bin/(true|false)", "~ (?i)not found"] }
    remediation: "echo 'install {{ item }} /bin/false' >> /etc/modprobe.d/disabled.conf"

  - id: KRN-001
    name: Core dumps of setuid programs are disabled
    tags: [system, kernel]
    when: facts.os == "linux"
    run: sysctl -n fs.suid_dumpable
    expect: "== 0"

  - id: KRN-002
    name: Kernel lockdown or Secure Boot is active
    tags: [system, kernel, boot]
    severity: low
    when: facts.os == "linux"
    run: |
      cat /sys/kernel/security/lockdown 2>/dev/null || echo "[none]"
    expect: "!~ \\[none\\]"

  - id: KRN-003
    name: Running kernel matches the newest installed kernel
    tags: [system, kernel, updates]
    run:
      rhel: |
        newest=$(rpm -q --last kernel-core kernel 2>/dev/null | sed -n 1p | awk '{print $1}' | sed -E 's/^kernel(-core)?-//')
        [ "$newest" = "$(uname -r)" ]
      debian: test ! -f /var/run/reboot-required
      suse: zypper needs-rebooting >/dev/null
    expect: true
```

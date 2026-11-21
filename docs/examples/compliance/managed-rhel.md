# Managed RHEL baseline

A complete managed-OS baseline for RHEL 8/9, ported from the module-based checkmate 1.x. Tags keep the old selection model: one of compliance, quality or itslc plus full or limited, e.g. `--tags compliance+full`. Unlike 1.x, every check is read-only, errors count as non-compliant, sudoers files are compared by exact checksum, SGID files and file capabilities are covered, and all installed packages are signature-checked.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/compliance/managed-rhel.yml`](https://github.com/rtulke/checkmate/blob/main/examples/compliance/managed-rhel.yml)
- :material-format-list-checks: **Checks**  
  79 from 49 definitions, 6 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/compliance/managed-rhel.yml

# Run the checks
checkmate run examples/compliance/managed-rhel.yml

# Override a variable from the command line
checkmate run examples/compliance/managed-rhel.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `MRH-RHEL-VERSION` | Supported RHEL release (8 or newer) | <span class="sev sev-critical">critical</span> | compliance, full, limited |
| `MRH-REPOS` | Package repositories are reachable | <span class="sev sev-medium">medium</span> | quality, full, limited |
| `MRH-REBOOT` | No reboot pending | <span class="sev sev-medium">medium</span> | quality, full, limited |
| `MRH-KERNEL-AGE` | Running kernel was installed less than 90 days ago | <span class="sev sev-high">high</span> | compliance, full |
| `MRH-SUBSCRIPTION` | Registered to an approved Satellite or capsule | <span class="sev sev-high">high</span> | quality, full, limited |
| `MRH-PKG-SIGNATURES` | Every installed package is signed with a trusted key | <span class="sev sev-critical">critical</span> | compliance, full, limited |
| `MRH-PKG-INTEGRITY` | Package-owned binaries are unmodified | <span class="sev sev-critical">critical</span> | compliance, full, limited |
| `MRH-DNF-EXCLUDES` | Critical packages are not excluded from updates | <span class="sev sev-high">high</span> | compliance, full |
| `MRH-GPGCHECK` | GPG checks are enabled for all repositories | <span class="sev sev-high">high</span> | itslc, full |
| `MRH-FORBIDDEN-AV-avg` | Third-party antivirus avg is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-CAV_LINUX` | Third-party antivirus CAV_LINUX is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-esets` | Third-party antivirus esets is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-f-prot` | Third-party antivirus f-prot is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-kav4fs` | Third-party antivirus kav4fs is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-sav-protect` | Third-party antivirus sav-protect is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-mcafee-ens` | Third-party antivirus mcafee-ens is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FORBIDDEN-AV-drweb` | Third-party antivirus drweb is not installed | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-AUTOFS` | autofs is not installed | <span class="sev sev-medium">medium</span> | compliance, itslc, full |
| `MRH-AGENT-ds_agent` | Endpoint protection agent is installed and running | <span class="sev sev-medium">medium</span> | itslc, quality, full |
| `MRH-AGENT-epops-agent` | Monitoring agent is installed and running | <span class="sev sev-medium">medium</span> | itslc, quality, full |
| `MRH-AGENT-splunkforwarder` | Log forwarder is installed and running | <span class="sev sev-medium">medium</span> | itslc, quality, full |
| `MRH-PUPPET-SERVER` | Puppet points to an approved server | <span class="sev sev-medium">medium</span> | quality, full, limited |
| `MRH-PUPPET-ENABLED` | The Puppet agent is not disabled | <span class="sev sev-medium">medium</span> | quality, full, limited |
| `MRH-PUPPET-LASTRUN` | The last Puppet run succeeded less than 2 hours ago | <span class="sev sev-medium">medium</span> | quality, full, limited |
| `MRH-VGS` | Only approved volume groups exist | <span class="sev sev-medium">medium</span> | compliance, full |
| `MRH-OS-LVS` | Only approved logical volumes on vrhvg | <span class="sev sev-medium">medium</span> | compliance, full |
| `MRH-LVM-MISSING` | No LVM physical volume is missing | <span class="sev sev-high">high</span> | compliance, full |
| `MRH-FSTAB-MOUNTED` | Every filesystem in /etc/fstab is mounted | <span class="sev sev-medium">medium</span> | compliance, full |
| `MRH-FSTYPES` | Only approved filesystem types are in use | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-FS-CONTENT-_` | / contains only OS directories | <span class="sev sev-medium">medium</span> | compliance, full |
| `MRH-FS-CONTENT-_opt` | /opt contains only OS directories | <span class="sev sev-medium">medium</span> | compliance, full |
| `MRH-SPACE-_` | / has at least 1024 MB free | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-SPACE-_boot` | /boot has at least 100 MB free | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-SPACE-_opt` | /opt has at least 50 MB free | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-SPACE-_tmp` | /tmp has at least 500 MB free | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-SPACE-_var_log` | /var/log has at least 200 MB free | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-SPACE-_var_log_audit` | /var/log/audit has at least 100 MB free | <span class="sev sev-medium">medium</span> | compliance, full, limited |
| `MRH-UID0` | root is the only account with UID 0 | <span class="sev sev-critical">critical</span> | compliance, quality, full |
| `MRH-GID0` | Only approved accounts have GID 0 | <span class="sev sev-high">high</span> | compliance, quality, full |
| `MRH-RESERVED-IDS` | Reserved and AD-managed IDs are not used locally | <span class="sev sev-high">high</span> | compliance, quality, full |
| `MRH-DUPLICATES` | No duplicate user or group names and IDs | <span class="sev sev-high">high</span> | compliance, quality, full |
| `MRH-ROOT-GROUP` | The root group has no members | <span class="sev sev-medium">medium</span> | compliance, quality, full |
| `MRH-SUDOERS` | Only approved sudoers files (exact checksum) | <span class="sev sev-critical">critical</span> | compliance, full |
| `MRH-SUDO-PROCESSES` | No sudo processes are left running | <span class="sev sev-medium">medium</span> | itslc, full, limited |
| `MRH-ROOT-KEYS` | root has only approved SSH keys | <span class="sev sev-critical">critical</span> | compliance, full |
| `MRH-PAM` | PAM configuration matches approved checksums | <span class="sev sev-high">high</span> | full |
| `MRH-ROOT-PROCESSES` | Every root process runs a package-owned, existing binary | <span class="sev sev-critical">critical</span> | compliance, full |
| `MRH-SUID` | SUID/SGID files and file capabilities come from packages | <span class="sev sev-critical">critical</span> | compliance, itslc, full |
| `MRH-HOSTNAME` | Host name is consistent across all sources | <span class="sev sev-medium">medium</span> | full |
| `MRH-HOSTS-FILE` | /etc/hosts is owned by root, readable and maps localhost | <span class="sev sev-medium">medium</span> | compliance, quality, full, limited |
| `MRH-SELINUX` | SELinux is enforcing (runtime and configuration) | <span class="sev sev-high">high</span> | compliance, full |
| `MRH-SNMP` | SNMP agent has no write access configured | <span class="sev sev-high">high</span> | compliance, full |
| `MRH-CRON` | No unapproved root cron jobs | <span class="sev sev-high">high</span> | compliance, full |
| `MRH-SSH-BANNER` | sshd banner == /etc/issue | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-CIPHERS` | sshd ciphers !~ (cbc\|arcfour\|3des) | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-MACS` | sshd macs !~ (md5\|-96) | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-PERMITEMPTYPASSWORDS` | sshd permitemptypasswords == no | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-PERMITROOTLOGIN` | sshd permitrootlogin in [no, prohibit-password, without-password] | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-PORT` | sshd port == 22 | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-PRINTLASTLOG` | sshd printlastlog == yes | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-STRICTMODES` | sshd strictmodes == yes | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-SYSLOGFACILITY` | sshd syslogfacility == AUTHPRIV | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-SSH-USEPAM` | sshd usepam == yes | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-ITSLC-BANNER` | The login banner is the approved text | <span class="sev sev-medium">medium</span> | itslc, full, limited |
| `MRH-ITSLC-TMOUT` | Idle shells time out after at most 30 minutes | <span class="sev sev-medium">medium</span> | itslc, full, limited |
| `MRH-ITSLC-PASSWORD-HASHES` | No password uses DES or MD5 | <span class="sev sev-high">high</span> | itslc, full, limited |
| `MRH-ITSLC-FAILLOCK` | Accounts lock after 5 failed logins | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.conf.all.accept_redirects` | sysctl net.ipv4.conf.all.accept_redirects = 0 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.conf.all.log_martians` | sysctl net.ipv4.conf.all.log_martians = 1 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.conf.all.send_redirects` | sysctl net.ipv4.conf.all.send_redirects = 0 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.conf.default.accept_redirects` | sysctl net.ipv4.conf.default.accept_redirects = 0 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.icmp_echo_ignore_broadcasts` | sysctl net.ipv4.icmp_echo_ignore_broadcasts = 1 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.ip_forward` | sysctl net.ipv4.ip_forward = 0 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-SYSCTL-net.ipv4.tcp_syncookies` | sysctl net.ipv4.tcp_syncookies = 1 | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-EMERGENCY` | Rescue and emergency mode require the root password | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-AUDIT` | auditd and rsyslog are running | <span class="sev sev-medium">medium</span> | itslc, full |
| `MRH-ITSLC-FIREWALL` | The host firewall is active | <span class="sev sev-medium">medium</span> | itslc, full, limited |
| `MRH-ITSLC-TIME` | Time is synchronised | <span class="sev sev-medium">medium</span> | itslc, full, limited |
| `MRH-ITSLC-ROOT-PATH` | root's PATH has no empty or relative entries | <span class="sev sev-medium">medium</span> | itslc, full, limited |

## Variables: `vars/managed-rhel.yml`

```yaml
# Site-specific values for managed-rhel.yml. Replace the example values
# with your own; everything here is data, the checks stay unchanged.

doc_base_url: https://docs.example.net/managed-os/technical-description.html
min_rhel_major: 8
max_kernel_age_days: 90

# Satellite servers or capsules a host may be registered to.
satellite_hosts: [satellite.example.net, capsule-1.example.net, capsule-2.example.net]

# Puppet servers a host may point to.
puppet_servers: [puppet.example.net, puppet-1.example.net, puppet-2.example.net]

# Red Hat release keys (see https://access.redhat.com/security/team/key).
# Add the key IDs of your own repositories and, on rebuilds, of the
# distribution (e.g. Rocky Linux or AlmaLinux release keys).
trusted_gpg_key_ids: [199e2f91fd431d51, 5326810137017186]

# Packages that must never be excluded from updates.
critical_packages:
  [coreutils, dracut, firewalld, grub2, iptables, kernel, openssl, pam, passwd,
   puppet, sudo, systemd, glibc, openssh, checkmate]

forbidden_av_packages: [avg, CAV_LINUX, esets, f-prot, kav4fs, sav-protect, mcafee-ens, drweb]

required_agents:
  - { label: Endpoint protection agent, package: ds_agent, service: ds_agent }
  - { label: Monitoring agent, package: epops-agent, service: epops-agent }
  - { label: Log forwarder, package: splunkforwarder, service: SplunkForwarder }

# Storage layout of the OS volume group.
os_vg: vrhvg
allowed_vg_pattern: "(vrhvg|datavg[0-9]*)"
allowed_os_lvs:
  [deepsecuritylv, homelv, logaudlv, optlv, slashlv, optsplunkforwarderlv,
   swaplv01, tmplv, usrloclv, varlv, varloglv, vmwarelv]

allowed_fstypes:
  [ext4, xfs, swap, tmpfs, devtmpfs, proc, sysfs, cgroup2, devpts, mqueue, securityfs,
   debugfs, tracefs, pstore, bpf, hugetlbfs, configfs, fusectl, autofs, binfmt_misc,
   rpc_pipefs, nfs, nfs4, cifs, efivarfs, selinuxfs, nsfs, fuse.vmware-vmblock]

# Directories allowed directly below these paths (others must be mount points).
allowed_fs_content:
  /: [afs, bin, boot, dev, etc, home, lib, lib64, media, mnt, opt, proc, root, run, sbin, srv, sys, tmp, usr, var, lost+found]
  /opt: [rh, puppetlabs, splunkforwarder, ds_agent, vmware, lost+found]

min_free_mb:
  /: 1024
  /opt: 50
  /tmp: 500
  /var/log: 200
  /var/log/audit: 100
  /boot: 100

accounts_with_gid_zero: [sync, shutdown, halt, operator]
reserved_gid: 20001
max_local_id: 99999999
ad_group_prefix: dl_example-access

trusted_root_keys:
  - "SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT"

# Executables that may run as root without belonging to a package.
trusted_root_binaries: [/usr/sbin/checkmate, /opt/ds_agent/ds_agent]

# Expected sshd -T values; each value is a complete condition.
sshd_expected:
  port: "== 22"
  permitrootlogin: "in [no, prohibit-password, without-password]"
  strictmodes: "== yes"
  permitemptypasswords: "== no"
  banner: "== /etc/issue"
  syslogfacility: "== AUTHPRIV"
  usepam: "== yes"
  printlastlog: "== yes"
  ciphers: "!~ (cbc|arcfour|3des)"
  macs: "!~ (md5|-96)"

itslc_sysctl:
  net.ipv4.tcp_syncookies: 1
  net.ipv4.icmp_echo_ignore_broadcasts: 1
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.log_martians: 1
  net.ipv4.ip_forward: 0

# SHA-256 of the approved /etc/issue.
issue_sha256: REPLACE_WITH_SHA256_OF_YOUR_ISSUE_FILE
```

## Policy

```yaml title="examples/compliance/managed-rhel.yml" linenums="1"
name: Managed RHEL baseline
version: 2.0.0
description: >
  A complete managed-OS baseline for RHEL 8/9, ported from the module-based
  checkmate 1.x. Tags keep the old selection model: one of compliance,
  quality or itslc plus full or limited, e.g. `--tags compliance+full`.
  Unlike 1.x, every check is read-only, errors count as non-compliant,
  sudoers files are compared by exact checksum, SGID files and file
  capabilities are covered, and all installed packages are signature-checked.

vars_files: [vars/managed-rhel.yml]

defaults:
  # Applies to every check: the policy is meant for the RHEL family only.
  when: facts.distro == "rhel" or "rhel" in facts.distro_like

snippets:
  pkg_installed: rpm -q --quiet {{ arg }}

checks:
  # --- Platform ---------------------------------------------------------------
  - id: MRH-RHEL-VERSION
    name: "Supported RHEL release ({{ min_rhel_major }} or newer)"
    tags: [compliance, full, limited]
    severity: critical
    run: rpm -E %rhel
    expect: ">= {{ min_rhel_major }}"
    reference: "{{ doc_base_url }}#check_rhel_version"

  - id: MRH-REPOS
    name: Package repositories are reachable
    tags: [quality, full, limited]
    timeout: 3m
    # dnf check-update: 0 = no updates, 100 = updates available, 1 = error.
    run: dnf -q check-update >/dev/null 2>&1
    expect: { rc: "in [0, 100]" }
    reference: "{{ doc_base_url }}#check_repos"

  - id: MRH-REBOOT
    name: No reboot pending
    tags: [quality, full, limited]
    run: needs-restarting -r >/dev/null
    expect: true
    remediation: Reboot the system.
    reference: "{{ doc_base_url }}#check_reboot"

  - id: MRH-KERNEL-AGE
    name: "Running kernel was installed less than {{ max_kernel_age_days }} days ago"
    tags: [compliance, full]
    severity: high
    run: |
      installed=$(rpm -q --qf '%{INSTALLTIME}' "kernel-core-$(uname -r)" 2>/dev/null) ||
        installed=$(rpm -q --qf '%{INSTALLTIME}' "kernel-$(uname -r)" 2>/dev/null) ||
        { echo "no package provides the running kernel $(uname -r)" >&2; exit 1; }
      echo $(( ($(date +%s) - installed) / 86400 ))
    expect: "< {{ max_kernel_age_days }}"
    remediation: dnf -y upgrade && reboot
    reference: "{{ doc_base_url }}#check_update_age"

  - id: MRH-SUBSCRIPTION
    name: Registered to an approved Satellite or capsule
    tags: [quality, full, limited]
    severity: high
    run: |
      cat /etc/rhsm/rhsm.conf 2>/dev/null | awk -F= '/^hostname[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}'
    allow_rc: [0, 1]
    expect: "in {{ satellite_hosts }}"
    reference: "{{ doc_base_url }}#check_satellite"

  - id: MRH-PKG-SIGNATURES
    name: Every installed package is signed with a trusted key
    tags: [compliance, full, limited]
    severity: critical
    timeout: 5m
    run: |
      rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}%{RSAHEADER:pgpsig}\n' |
        grep -v '^gpg-pubkey-' |
        grep -viE 'Key ID ({{ trusted_gpg_key_ids | join("|") }})' | awk '{print $1}'
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_rpm"

  - id: MRH-PKG-INTEGRITY
    name: Package-owned binaries are unmodified
    tags: [compliance, full, limited]
    severity: critical
    timeout: 20m
    run: |
      rpm -Va --noconfig --nomtime 2>/dev/null | awk 'substr($1, 3, 1) == "5" {print $NF}'
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_rpm"

  - id: MRH-DNF-EXCLUDES
    name: Critical packages are not excluded from updates
    tags: [compliance, full]
    severity: high
    run: |
      grep -hiE '^[[:space:]]*exclude(pkgs)?[[:space:]]*=' /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/*.repo 2>/dev/null |
        cut -d= -f2- | tr ', ' '\n\n' | grep -v '^$' |
        grep -iE '^(\*|{{ critical_packages | join("|") }})'
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_yum_conf"

  - id: MRH-GPGCHECK
    name: GPG checks are enabled for all repositories
    tags: [itslc, full]
    severity: high
    run: |
      grep -HEi '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*(0|false|no)' /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo
    allow_rc: [0, 1, 2]
    expect: empty

  - id: "MRH-FORBIDDEN-AV-{{ item }}"
    name: "Third-party antivirus {{ item }} is not installed"
    tags: [compliance, full, limited]
    loop: "{{ forbidden_av_packages }}"
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: false
    reference: "{{ doc_base_url }}#check_malware"

  - id: MRH-AUTOFS
    name: autofs is not installed
    tags: [compliance, itslc, full]
    run: { use: pkg_installed, arg: autofs }
    expect: false
    remediation: dnf remove autofs
    reference: "{{ doc_base_url }}#check_autofs"

  # --- Agents -----------------------------------------------------------------
  - id: "MRH-AGENT-{{ item.package }}"
    name: "{{ item.label }} is installed and running"
    tags: [itslc, quality, full]
    loop: "{{ required_agents }}"
    run: |
      rpm -q --quiet {{ item.package }} && systemctl is-active --quiet {{ item.service }}
    expect: true

  - id: MRH-PUPPET-SERVER
    name: Puppet points to an approved server
    tags: [quality, full, limited]
    only_if: test -x /opt/puppetlabs/bin/puppet
    run: /opt/puppetlabs/bin/puppet config print server --section agent
    expect: "in {{ puppet_servers }}"
    reference: "{{ doc_base_url }}#check_scs_puppet"

  - id: MRH-PUPPET-ENABLED
    name: The Puppet agent is not disabled
    tags: [quality, full, limited]
    only_if: test -x /opt/puppetlabs/bin/puppet
    run: test ! -f /opt/puppetlabs/puppet/cache/state/agent_disabled.lock
    expect: true
    remediation: puppet agent --enable

  - id: MRH-PUPPET-LASTRUN
    name: The last Puppet run succeeded less than 2 hours ago
    tags: [quality, full, limited]
    only_if: test -f /opt/puppetlabs/puppet/cache/state/last_run_summary.yaml
    # Read-only: the summary file is evaluated instead of running the agent.
    run: |
      summary=/opt/puppetlabs/puppet/cache/state/last_run_summary.yaml
      last=$(awk '$1 == "last_run:" {print $2}' "$summary")
      failed=$(awk '/^events:/ {e = 1} e && $1 == "failure:" {print $2; exit}' "$summary")
      age=$(( $(date +%s) - last ))
      if [ "$age" -lt 7200 ] && [ "${failed:-0}" -eq 0 ]; then echo ok; else echo "age=${age}s failures=${failed}"; fi
    expect: "== ok"

  # --- Filesystems and storage --------------------------------------------------
  - id: MRH-VGS
    name: Only approved volume groups exist
    tags: [compliance, full]
    when: facts.is_root
    run: |
      vgs --noheadings -o vg_name 2>/dev/null | tr -d ' ' | grep -vxE '{{ allowed_vg_pattern }}'
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_fslayout"

  - id: MRH-OS-LVS
    name: "Only approved logical volumes on {{ os_vg }}"
    tags: [compliance, full]
    when: facts.is_root
    run: |
      lvs --noheadings -o lv_name {{ os_vg }} 2>/dev/null | tr -d ' ' |
        grep -vxF {% for lv in allowed_os_lvs %}-e {{ lv }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_fslayout"

  - id: MRH-LVM-MISSING
    name: No LVM physical volume is missing
    tags: [compliance, full]
    severity: high
    when: facts.is_root
    run: |
      pvs --noheadings -o pv_name,pv_attr 2>/dev/null | awk 'substr($2, 3, 1) == "m" {print $1}'
    expect: empty
    remediation: vgreduce --removemissing <vg>
    reference: "{{ doc_base_url }}#check_lvm"

  - id: MRH-FSTAB-MOUNTED
    name: Every filesystem in /etc/fstab is mounted
    tags: [compliance, full]
    run: |
      findmnt --fstab -rn -o TARGET,FSTYPE | awk '$2 != "swap" {print $1}' |
        while read -r target; do
          if ! findmnt -n "$target" >/dev/null; then echo "$target"; fi
        done
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_fstab"

  - id: MRH-FSTYPES
    name: Only approved filesystem types are in use
    tags: [compliance, full, limited]
    run: |
      findmnt -rn -o FSTYPE | sort -u | grep -vxF {% for t in allowed_fstypes %}-e {{ t }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_fstypes"

  - id: "MRH-FS-CONTENT-{{ item.key | replace('/', '_') }}"
    name: "{{ item.key }} contains only OS directories"
    tags: [compliance, full]
    loop: "{{ allowed_fs_content }}"
    # Entries that are mount points of their own are allowed.
    run: |
      dir="{{ item.key }}"
      for entry in "${dir%/}"/*; do
        [ -e "$entry" ] || continue   # empty directory: the glob stays unexpanded
        [ -L "$entry" ] && continue
        name=${entry##*/}
        case " {{ item.value | join(' ') }} " in *" $name "*) continue ;; esac
        findmnt -n "$entry" >/dev/null || echo "$entry"
      done
    expect: empty
    remediation: Move customer data to a partition on a data volume group.
    reference: "{{ doc_base_url }}#check_fs_content"

  - id: "MRH-SPACE-{{ item.key | replace('/', '_') }}"
    name: "{{ item.key }} has at least {{ item.value }} MB free"
    tags: [compliance, full, limited]
    loop: "{{ min_free_mb }}"
    only_if: findmnt -n {{ item.key }} >/dev/null || test {{ item.key }} = /
    run: |
      df -Pm {{ item.key }} | awk 'NR == 2 {print $4}'
    expect: ">= {{ item.value }}"
    reference: "{{ doc_base_url }}#check_space"

  # --- Accounts and privileges ----------------------------------------------------
  - id: MRH-UID0
    name: root is the only account with UID 0
    tags: [compliance, quality, full]
    severity: critical
    run: |
      awk -F: '$3 == 0 {print $1}' /etc/passwd
    expect: "== root"
    reference: "{{ doc_base_url }}#check_local_users"

  - id: MRH-GID0
    name: Only approved accounts have GID 0
    tags: [compliance, quality, full]
    severity: high
    run: |
      awk -F: '$4 == 0 {print $1}' /etc/passwd | grep -vxF -e root {% for a in accounts_with_gid_zero %}-e {{ a }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty

  - id: MRH-RESERVED-IDS
    name: Reserved and AD-managed IDs are not used locally
    tags: [compliance, quality, full]
    severity: high
    run: |
      awk -F: -v r={{ reserved_gid }} -v max={{ max_local_id }} '$4 == r || $3 > max || $4 > max {print "user " $1}' /etc/passwd
      awk -F: -v r={{ reserved_gid }} -v max={{ max_local_id }} '$3 == r || $3 > max {print "group " $1}' /etc/group
      awk -F: -v p='{{ ad_group_prefix }}' 'index(tolower($1), p) == 1 {print "group " $1}' /etc/group
    expect: empty

  - id: MRH-DUPLICATES
    name: No duplicate user or group names and IDs
    tags: [compliance, quality, full]
    severity: high
    run: |
      { cut -d: -f1 /etc/passwd | sort | uniq -d
        cut -d: -f3 /etc/passwd | sort | uniq -d
        cut -d: -f1 /etc/group | sort | uniq -d
        cut -d: -f3 /etc/group | sort | uniq -d; }
    expect: empty

  - id: MRH-ROOT-GROUP
    name: The root group has no members
    tags: [compliance, quality, full]
    run: |
      awk -F: '$1 == "root" {print $4}' /etc/group
    expect: empty

  - id: MRH-SUDOERS
    name: Only approved sudoers files (exact checksum)
    tags: [compliance, full]
    severity: critical
    when: facts.is_root
    run: |
      sha256sum /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vxFf vars/trusted-sudoers.sha256
    allow_rc: [0, 1]
    expect: empty
    remediation: Request approval for the listed sudoers files.
    reference: "{{ doc_base_url }}#check_sudoers"

  - id: MRH-SUDO-PROCESSES
    name: No sudo processes are left running
    tags: [itslc, full, limited]
    run: |
      ps -eo user=,pid=,comm= | awk '$1 == "root" && $3 == "sudo" {print $2}'
    expect: empty
    reference: "{{ doc_base_url }}#check_sudo_processes"

  - id: MRH-ROOT-KEYS
    name: root has only approved SSH keys
    tags: [compliance, full]
    severity: critical
    when: facts.is_root
    only_if: test -s /root/.ssh/authorized_keys
    run: |
      ssh-keygen -lf /root/.ssh/authorized_keys | awk '{print $2}' |
        grep -vxF {% for k in trusted_root_keys %}-e '{{ k }}' {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_ssh_keys"

  - id: MRH-PAM
    name: PAM configuration matches approved checksums
    tags: [full]
    severity: high
    when: facts.is_root
    run: |
      find /etc/pam.d -type f -exec sha256sum {} + | grep -vxFf vars/trusted-pam.sha256
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_pam_config"

  # --- Processes and binaries -------------------------------------------------------
  - id: MRH-ROOT-PROCESSES
    name: Every root process runs a package-owned, existing binary
    tags: [compliance, full]
    severity: critical
    when: facts.is_root
    # Deleted binaries show up as "/path (deleted)" and are reported, too.
    run: |
      ps -eo euid=,pid= | awk '$1 == 0 {print $2}' |
        while read -r pid; do readlink "/proc/$pid/exe" 2>/dev/null; done | sort -u |
        while read -r exe; do
          case "$exe" in *" (deleted)") echo "$exe"; continue ;; esac
          rpm -qf "$exe" >/dev/null 2>&1 || echo "$exe"
        done |
        grep -vxF {% for b in trusted_root_binaries %}-e {{ b }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_root_processes"

  - id: MRH-SUID
    name: SUID/SGID files and file capabilities come from packages
    tags: [compliance, itslc, full]
    severity: critical
    timeout: 10m
    run: |
      {
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
        getcap -r / 2>/dev/null | awk '{print $1}'
      } | sort -u | while read -r f; do rpm -qf "$f" >/dev/null 2>&1 || echo "$f"; done
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_suid"

  # --- Configuration ----------------------------------------------------------------
  - id: MRH-HOSTNAME
    name: Host name is consistent across all sources
    tags: [full]
    run: |
      fqdn=$(hostname -f | tr 'A-Z' 'a-z')
      static=$(hostnamectl --static 2>/dev/null | tr 'A-Z' 'a-z')
      file=$(tr 'A-Z' 'a-z' < /etc/hostname)
      grep -qiw "$fqdn" /etc/hosts || echo "missing in /etc/hosts: $fqdn"
      [ "$static" = "$fqdn" ] || [ "$static" = "${fqdn%%.*}" ] || echo "hostnamectl: $static"
      [ "$file" = "$fqdn" ] || [ "$file" = "${fqdn%%.*}" ] || echo "/etc/hostname: $file"
    expect: empty
    reference: "{{ doc_base_url }}#check_hostname"

  - id: MRH-HOSTS-FILE
    name: /etc/hosts is owned by root, readable and maps localhost
    tags: [compliance, quality, full, limited]
    run: |
      stat -c '%U:%G %a' /etc/hosts
      grep -cE '^127\.0\.0\.1[[:space:]].*localhost' /etc/hosts
    allow_rc: [0, 1]
    expect: ["~ ^root:root 6[0-4]4$", "~ ^[1-9][0-9]*$"]
    reference: "{{ doc_base_url }}#check_hosts_file"

  - id: MRH-SELINUX
    name: SELinux is enforcing (runtime and configuration)
    tags: [compliance, full]
    severity: high
    run: |
      echo "$(getenforce) $(awk -F= '$1 == "SELINUX" {print $2}' /etc/selinux/config)"
    expect: "== Enforcing enforcing"
    reference: "{{ doc_base_url }}#check_selinux"

  - id: MRH-SNMP
    name: SNMP agent has no write access configured
    tags: [compliance, full]
    severity: high
    only_if: test -f /etc/snmp/snmpd.conf
    run: |
      grep -hiE '^[[:space:]]*(rwuser|rwcommunity6?|authcommunity[[:space:]]+[^[:space:]]*write|authuser[[:space:]]+[^[:space:]]*write|setaccess.*write)' \
        /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.d/*.conf 2>/dev/null
    allow_rc: [0, 1, 2]
    expect: empty
    reference: "{{ doc_base_url }}#check_snmp"

  - id: MRH-CRON
    name: No unapproved root cron jobs
    tags: [compliance, full]
    severity: high
    when: facts.is_root
    run: |
      {
        sha256sum /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null
        [ -s /var/spool/cron/root ] && sha256sum /var/spool/cron/root
      } | grep -vxFf vars/trusted-cron.sha256
    allow_rc: [0, 1]
    expect: empty
    reference: "{{ doc_base_url }}#check_cron"

  # --- sshd (effective configuration) ---------------------------------------------
  - id: "MRH-SSH-{{ item.key | upper }}"
    name: "sshd {{ item.key }} {{ item.value }}"
    tags: [itslc, full, limited]
    severity: high
    when: facts.is_root
    loop: "{{ sshd_expected }}"
    run: |
      sshd -T 2>/dev/null | awk -v key={{ item.key }} '$1 == key {print substr($0, length(key) + 2)}'
    expect: "{{ item.value }}"
    reference: "{{ doc_base_url }}#check_ssh"

  # --- ITSLC hardening ------------------------------------------------------------------
  - id: MRH-ITSLC-BANNER
    name: The login banner is the approved text
    tags: [itslc, full, limited]
    run: sha256sum /etc/issue | cut -d' ' -f1
    expect: "== {{ issue_sha256 }}"

  - id: MRH-ITSLC-TMOUT
    name: Idle shells time out after at most 30 minutes
    tags: [itslc, full, limited]
    run: |
      grep -rhE '^[[:space:]]*(readonly[[:space:]]+|declare[[:space:]]+-r[[:space:]]+)?TMOUT=' /etc/profile /etc/profile.d/ 2>/dev/null |
        sed -E 's/.*TMOUT=([0-9]+).*/\1/' | sort -n | sed -n 1p
    allow_rc: [0, 1]
    expect: ["!empty", "> 0", "<= 1800"]

  - id: MRH-ITSLC-PASSWORD-HASHES
    name: No password uses DES or MD5
    tags: [itslc, full, limited]
    severity: high
    when: facts.is_root
    run: |
      awk -F: '$2 ~ /^\$1\$/ || ($2 != "" && $2 !~ /^[!*$]/) {print $1}' /etc/shadow
    expect: empty

  - id: MRH-ITSLC-FAILLOCK
    name: Accounts lock after 5 failed logins
    tags: [itslc, full]
    run: |
      authselect current 2>/dev/null | grep -c with-faillock
      awk -F= '/^[[:space:]]*deny[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print "deny=" $2}' /etc/security/faillock.conf
    allow_rc: [0, 1]
    expect: ["~ ^1$", "~ deny=[1-5]$"]

  - id: "MRH-ITSLC-SYSCTL-{{ item.key }}"
    name: "sysctl {{ item.key }} = {{ item.value }}"
    tags: [itslc, full]
    loop: "{{ itslc_sysctl }}"
    run: sysctl -n {{ item.key }}
    expect: "== {{ item.value }}"

  - id: MRH-ITSLC-EMERGENCY
    name: Rescue and emergency mode require the root password
    tags: [itslc, full]
    run: |
      for unit in rescue emergency; do
        systemctl cat "$unit.service" 2>/dev/null | grep -qE '^ExecStart=.*(sulogin|systemd-sulogin-shell)' || echo "$unit"
      done
    expect: empty

  - id: MRH-ITSLC-AUDIT
    name: auditd and rsyslog are running
    tags: [itslc, full]
    run: systemctl is-active auditd rsyslog | sort -u
    allow_rc: [0, 3]
    expect: "== active"

  - id: MRH-ITSLC-FIREWALL
    name: The host firewall is active
    tags: [itslc, full, limited]
    run: systemctl is-active firewalld nftables iptables 2>/dev/null | grep -c '^active$'
    allow_rc: [0, 1, 3]
    expect: ">= 1"

  - id: MRH-ITSLC-TIME
    name: Time is synchronised
    tags: [itslc, full, limited]
    run: timedatectl show -p NTPSynchronized --value
    expect: "== yes"

  - id: MRH-ITSLC-ROOT-PATH
    name: root's PATH has no empty or relative entries
    tags: [itslc, full, limited]
    when: facts.is_root
    # Login scripts may print banners; only the PATH= line is used.
    run: su - root -c 'printf "PATH=%s\\n" "$PATH"' 2>/dev/null | sed -n 's/^PATH=//p' | tail -1
    expect: '!~ (^|:)\.?(:|$)'
```

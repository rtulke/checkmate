# Linux hardening baseline

A broad server hardening baseline for current Linux distributions, structured like the public hardening guides of the SCAP Security Guide (OpenSCAP) and the CIS benchmarks: file systems, services, network parameters, auditing, logging, access control, accounts, file permissions, boot and maintenance. Check IDs and wording are our own; the thresholds are common defaults and can be tuned in `vars`. Select sections with tags, e.g. `--tags network` or `--tags audit`.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/compliance/linux-hardening.yml`](https://github.com/rtulke/checkmate/blob/main/examples/compliance/linux-hardening.yml)
- :material-format-list-checks: **Checks**  
  324 from 113 definitions, 22 with loops
- :material-monitor: **Platforms**  
  alpine, debian, linux, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/compliance/linux-hardening.yml

# Run the checks
checkmate run examples/compliance/linux-hardening.yml

# Override a variable from the command line
checkmate run examples/compliance/linux-hardening.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `HRD-FS-MOD-cramfs` | Kernel module cramfs is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-freevxfs` | Kernel module freevxfs is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-hfs` | Kernel module hfs is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-hfsplus` | Kernel module hfsplus is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-jffs2` | Kernel module jffs2 is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-udf` | Kernel module udf is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-usb-storage` | Kernel module usb-storage is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-dccp` | Kernel module dccp is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-sctp` | Kernel module sctp is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-rds` | Kernel module rds is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-tipc` | Kernel module tipc is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-firewire-core` | Kernel module firewire-core is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-MOD-bluetooth` | Kernel module bluetooth is disabled | <span class="sev sev-low">low</span> | hardening, filesystems, modules |
| `HRD-FS-OPT-_tmp-nodev` | /tmp is mounted with nodev | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_tmp-nosuid` | /tmp is mounted with nosuid | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_tmp-noexec` | /tmp is mounted with noexec | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_dev_shm-nodev` | /dev/shm is mounted with nodev | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_dev_shm-nosuid` | /dev/shm is mounted with nosuid | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_dev_shm-noexec` | /dev/shm is mounted with noexec | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_tmp-nodev` | /var/tmp is mounted with nodev | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_tmp-nosuid` | /var/tmp is mounted with nosuid | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_tmp-noexec` | /var/tmp is mounted with noexec | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_home-nodev` | /home is mounted with nodev | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_home-nosuid` | /home is mounted with nosuid | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_log-nodev` | /var/log is mounted with nodev | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_log-nosuid` | /var/log is mounted with nosuid | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_log-noexec` | /var/log is mounted with noexec | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_log_audit-nodev` | /var/log/audit is mounted with nodev | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_log_audit-nosuid` | /var/log/audit is mounted with nosuid | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-OPT-_var_log_audit-noexec` | /var/log/audit is mounted with noexec | <span class="sev sev-medium">medium</span> | hardening, filesystems |
| `HRD-FS-STICKY` | All world-writable directories have the sticky bit | <span class="sev sev-high">high</span> | hardening, filesystems, permissions |
| `HRD-FS-AUTOMOUNT` | Automounting of removable media is disabled | <span class="sev sev-low">low</span> | hardening, filesystems |
| `HRD-SVC-avahi-daemon` | Service avahi-daemon is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-cups` | Service cups is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-dhcpd` | Service dhcpd is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-dhcpd6` | Service dhcpd6 is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-slapd` | Service slapd is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-nfs-server` | Service nfs-server is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-rpcbind` | Service rpcbind is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-named` | Service named is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-vsftpd` | Service vsftpd is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-dovecot` | Service dovecot is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-smb` | Service smb is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-squid` | Service squid is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-snmpd` | Service snmpd is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-ypserv` | Service ypserv is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-rsyncd` | Service rsyncd is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-telnet.socket` | Service telnet.socket is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-tftp.socket` | Service tftp.socket is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-xinetd` | Service xinetd is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-SVC-autofs` | Service autofs is neither running nor enabled | <span class="sev sev-medium">medium</span> | hardening, services |
| `HRD-PKG-RPM-ypbind` | Legacy package ypbind is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-rsh` | Legacy package rsh is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-talk` | Legacy package talk is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-telnet` | Legacy package telnet is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-tftp` | Legacy package tftp is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-xinetd` | Legacy package xinetd is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-ypserv` | Legacy package ypserv is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-rsh-server` | Legacy package rsh-server is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-telnet-server` | Legacy package telnet-server is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-RPM-tftp-server` | Legacy package tftp-server is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-nis` | Legacy package nis is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-rsh-client` | Legacy package rsh-client is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-talk` | Legacy package talk is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-telnet` | Legacy package telnet is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-tftp` | Legacy package tftp is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-xinetd` | Legacy package xinetd is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-rsh-server` | Legacy package rsh-server is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-telnetd` | Legacy package telnetd is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-PKG-DEB-tftpd` | Legacy package tftpd is not installed | <span class="sev sev-medium">medium</span> | hardening, services, packages |
| `HRD-SVC-MTA-LOCAL` | The mail transfer agent only listens on loopback | <span class="sev sev-medium">medium</span> | hardening, services, network |
| `HRD-SVC-TIME-SOURCES` | The time service has servers configured | <span class="sev sev-medium">medium</span> | hardening, services, time |
| `HRD-NET-net.ipv4.conf.all.accept_redirects` | net.ipv4.conf.all.accept_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.all.accept_source_route` | net.ipv4.conf.all.accept_source_route == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.all.log_martians` | net.ipv4.conf.all.log_martians == 1 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.all.rp_filter` | net.ipv4.conf.all.rp_filter in [1, 2] | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.all.secure_redirects` | net.ipv4.conf.all.secure_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.all.send_redirects` | net.ipv4.conf.all.send_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.default.accept_redirects` | net.ipv4.conf.default.accept_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.default.accept_source_route` | net.ipv4.conf.default.accept_source_route == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.default.log_martians` | net.ipv4.conf.default.log_martians == 1 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.default.rp_filter` | net.ipv4.conf.default.rp_filter in [1, 2] | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.default.secure_redirects` | net.ipv4.conf.default.secure_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.conf.default.send_redirects` | net.ipv4.conf.default.send_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.icmp_echo_ignore_broadcasts` | net.ipv4.icmp_echo_ignore_broadcasts == 1 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.icmp_ignore_bogus_error_responses` | net.ipv4.icmp_ignore_bogus_error_responses == 1 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.ip_forward` | net.ipv4.ip_forward == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET-net.ipv4.tcp_syncookies` | net.ipv4.tcp_syncookies == 1 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl |
| `HRD-NET6-net.ipv6.conf.all.accept_ra` | net.ipv6.conf.all.accept_ra == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET6-net.ipv6.conf.all.accept_redirects` | net.ipv6.conf.all.accept_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET6-net.ipv6.conf.all.accept_source_route` | net.ipv6.conf.all.accept_source_route == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET6-net.ipv6.conf.all.forwarding` | net.ipv6.conf.all.forwarding == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET6-net.ipv6.conf.default.accept_ra` | net.ipv6.conf.default.accept_ra == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET6-net.ipv6.conf.default.accept_redirects` | net.ipv6.conf.default.accept_redirects == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET6-net.ipv6.conf.default.accept_source_route` | net.ipv6.conf.default.accept_source_route == 0 | <span class="sev sev-medium">medium</span> | hardening, network, sysctl, ipv6 |
| `HRD-NET-FIREWALL` | A host firewall is active | <span class="sev sev-high">high</span> | hardening, network, firewall |
| `HRD-NET-WIRELESS` | Wireless interfaces are disabled | <span class="sev sev-low">low</span> | hardening, network |
| `HRD-KRN-dev.tty.ldisc_autoload` | dev.tty.ldisc_autoload == 0 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-fs.protected_fifos` | fs.protected_fifos >= 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-fs.protected_hardlinks` | fs.protected_hardlinks == 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-fs.protected_regular` | fs.protected_regular >= 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-fs.protected_symlinks` | fs.protected_symlinks == 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-fs.suid_dumpable` | fs.suid_dumpable == 0 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.dmesg_restrict` | kernel.dmesg_restrict == 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.kptr_restrict` | kernel.kptr_restrict >= 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.perf_event_paranoid` | kernel.perf_event_paranoid >= 2 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.randomize_va_space` | kernel.randomize_va_space == 2 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.sysrq` | kernel.sysrq == 0 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.unprivileged_bpf_disabled` | kernel.unprivileged_bpf_disabled >= 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-kernel.yama.ptrace_scope` | kernel.yama.ptrace_scope >= 1 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-net.core.bpf_jit_harden` | net.core.bpf_jit_harden == 2 | <span class="sev sev-medium">medium</span> | hardening, kernel, sysctl |
| `HRD-KRN-CORE-LIMITS` | Core dumps are restricted by limits | <span class="sev sev-low">low</span> | hardening, kernel |
| `HRD-KRN-COREDUMP-STORAGE` | systemd-coredump does not store dumps | <span class="sev sev-low">low</span> | hardening, kernel |
| `HRD-KRN-AUDIT-BOOT` | Auditing starts with the kernel (audit=1) | <span class="sev sev-medium">medium</span> | hardening, kernel, audit |
| `HRD-KRN-AUDIT-BACKLOG` | The kernel audit backlog holds at least 8192 events | <span class="sev sev-low">low</span> | hardening, kernel, audit |
| `HRD-MAC-ACTIVE` | SELinux or AppArmor is enforcing | <span class="sev sev-high">high</span> | hardening, mac |
| `HRD-MAC-CMDLINE` | The MAC system is not disabled at boot | <span class="sev sev-high">high</span> | hardening, mac, boot |
| `HRD-AUD-SERVICE` | auditd is running and enabled | <span class="sev sev-high">high</span> | hardening, audit |
| `HRD-AUD-RULE-TIME` | Audit rules cover changes to the system time | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-LOCALTIME` | Audit rules cover changes to /etc/localtime | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-PASSWD` | Audit rules cover changes to /etc/passwd | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-GROUP` | Audit rules cover changes to /etc/group | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-SHADOW` | Audit rules cover changes to /etc/shadow | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-GSHADOW` | Audit rules cover changes to /etc/gshadow | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-OPASSWD` | Audit rules cover changes to /etc/security/opasswd | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-HOSTNAME` | Audit rules cover changes to the host name | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-ISSUE` | Audit rules cover changes to the login banners | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-HOSTS` | Audit rules cover changes to /etc/hosts | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-MACPOLICY` | Audit rules cover changes to the MAC policy | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-LOGINS` | Audit rules cover login records | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-SESSION` | Audit rules cover session records | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-PERMMOD` | Audit rules cover permission changes | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-ACCESS` | Audit rules cover denied file access | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-MOUNTS` | Audit rules cover mounts | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-DELETE` | Audit rules cover file deletions by users | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-SUDOERS` | Audit rules cover changes to sudoers | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-MODULES` | Audit rules cover kernel module loading | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-IMMUTABLE` | The audit configuration is immutable until reboot | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-CONF-max_log_file_action` | auditd.conf: max_log_file_action ~ (?i)^(keep_logs\|rotate)$ | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-CONF-space_left_action` | auditd.conf: space_left_action ~ (?i)^(email\|exec\|single\|halt)$ | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-CONF-admin_space_left_action` | auditd.conf: admin_space_left_action ~ (?i)^(single\|halt)$ | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-CONF-disk_full_action` | auditd.conf: disk_full_action ~ (?i)^(single\|halt)$ | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-CONF-disk_error_action` | auditd.conf: disk_error_action ~ (?i)^(syslog\|single\|halt)$ | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-LOG-JOURNAL-PERSISTENT` | journald keeps logs on disk | <span class="sev sev-medium">medium</span> | hardening, logging |
| `HRD-LOG-JOURNAL-COMPRESS` | journald compresses large entries | <span class="sev sev-low">low</span> | hardening, logging |
| `HRD-LOG-FILES` | Log files are not readable by others | <span class="sev sev-medium">medium</span> | hardening, logging, permissions |
| `HRD-SSH-ALLOWTCPFORWARDING` | sshd: allowtcpforwarding == no | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-BANNER` | sshd: banner != none | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-CIPHERS` | sshd: ciphers !~ (cbc\|arcfour\|3des\|blowfish) | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-CLIENTALIVECOUNTMAX` | sshd: clientalivecountmax <= 3 | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-HOSTBASEDAUTHENTICATION` | sshd: hostbasedauthentication == no | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-IGNORERHOSTS` | sshd: ignorerhosts == yes | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-KEXALGORITHMS` | sshd: kexalgorithms !~ (group1-\|group14-sha1\|group-exchange-sha1) | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-LOGINGRACETIME` | sshd: logingracetime <= 60 | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-LOGLEVEL` | sshd: loglevel in [INFO, VERBOSE] | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-MACS` | sshd: macs !~ (md5\|-96\|umac-64[@-]\|hmac-sha1($\|,\|-etm)) | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-MAXAUTHTRIES` | sshd: maxauthtries <= 4 | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-MAXSESSIONS` | sshd: maxsessions <= 10 | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-PERMITEMPTYPASSWORDS` | sshd: permitemptypasswords == no | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-PERMITROOTLOGIN` | sshd: permitrootlogin == no | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-PERMITUSERENVIRONMENT` | sshd: permituserenvironment == no | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-USEPAM` | sshd: usepam == yes | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-X11FORWARDING` | sshd: x11forwarding == no | <span class="sev sev-high">high</span> | hardening, access, ssh |
| `HRD-SSH-CLIENTALIVE` | sshd: idle sessions are disconnected within 15 minutes | <span class="sev sev-medium">medium</span> | hardening, access, ssh |
| `HRD-SUDO-PTY` | sudo uses a pseudo terminal | <span class="sev sev-medium">medium</span> | hardening, access, sudo |
| `HRD-SUDO-LOG` | sudo writes a log file | <span class="sev sev-medium">medium</span> | hardening, access, sudo |
| `HRD-SUDO-TIMEOUT` | sudo authentication expires within 15 minutes | <span class="sev sev-low">low</span> | hardening, access, sudo |
| `HRD-SUDO-NOAUTH` | No sudo rule disables authentication | <span class="sev sev-high">high</span> | hardening, access, sudo |
| `HRD-SU-WHEEL` | su is restricted to a group (pam_wheel) | <span class="sev sev-medium">medium</span> | hardening, access |
| `HRD-CRON-ALLOW` | cron and at are restricted to allowed users | <span class="sev sev-low">low</span> | hardening, access, cron |
| `HRD-PAM-FAILLOCK` | Accounts lock after at most 5 failed logins | <span class="sev sev-high">high</span> | hardening, authentication, pam |
| `HRD-PAM-UNLOCK` | Locked accounts unlock after at least 15 minutes (or manually) | <span class="sev sev-medium">medium</span> | hardening, authentication, pam |
| `HRD-PWQ-minlen` | Password quality: minlen >= 14 | <span class="sev sev-medium">medium</span> | hardening, authentication, passwords |
| `HRD-PWQ-minclass` | Password quality: minclass >= 4 | <span class="sev sev-medium">medium</span> | hardening, authentication, passwords |
| `HRD-PWQ-maxrepeat` | Password quality: maxrepeat in [1, 2, 3] | <span class="sev sev-medium">medium</span> | hardening, authentication, passwords |
| `HRD-PWQ-maxsequence` | Password quality: maxsequence in [1, 2, 3] | <span class="sev sev-medium">medium</span> | hardening, authentication, passwords |
| `HRD-PWQ-difok` | Password quality: difok >= 2 | <span class="sev sev-medium">medium</span> | hardening, authentication, passwords |
| `HRD-PWHISTORY` | The last 5 passwords cannot be reused | <span class="sev sev-medium">medium</span> | hardening, authentication, passwords |
| `HRD-PW-HASH` | New passwords are hashed with SHA-512 or yescrypt | <span class="sev sev-high">high</span> | hardening, authentication, passwords |
| `HRD-ACC-DEFS-PASS_MAX_DAYS` | login.defs: PASS_MAX_DAYS <= 365 | <span class="sev sev-medium">medium</span> | hardening, accounts, passwords |
| `HRD-ACC-DEFS-PASS_MIN_DAYS` | login.defs: PASS_MIN_DAYS >= 1 | <span class="sev sev-medium">medium</span> | hardening, accounts, passwords |
| `HRD-ACC-DEFS-PASS_WARN_AGE` | login.defs: PASS_WARN_AGE >= 7 | <span class="sev sev-medium">medium</span> | hardening, accounts, passwords |
| `HRD-ACC-INACTIVE` | Accounts are disabled 45 days after password expiry | <span class="sev sev-low">low</span> | hardening, accounts, passwords |
| `HRD-ACC-SHADOWED` | All accounts use shadowed passwords | <span class="sev sev-high">high</span> | hardening, accounts |
| `HRD-ACC-EMPTY` | No account has an empty password | <span class="sev sev-critical">critical</span> | hardening, accounts |
| `HRD-ACC-UID0` | root is the only account with UID 0 | <span class="sev sev-critical">critical</span> | hardening, accounts |
| `HRD-ACC-ROOT-GID` | root's primary group is GID 0 | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-LEGACY` | No legacy "+" NIS entries in account files | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-SYSTEM-LOCKED` | System accounts are locked | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-PW-CHANGED` | No password change date lies in the future | <span class="sev sev-low">low</span> | hardening, accounts |
| `HRD-ACC-MAXDAYS` | Every user password expires within 365 days | <span class="sev sev-medium">medium</span> | hardening, accounts, passwords |
| `HRD-ACC-GROUPS-EXIST` | Every primary group of an account exists | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-SHADOW-GROUP` | The shadow group has no members | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-DUPLICATES` | No duplicate user names, UIDs, group names or GIDs | <span class="sev sev-high">high</span> | hardening, accounts |
| `HRD-ACC-HOMES` | Interactive users have an existing home directory they own | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-DOTFILES` | Dot files in home directories are not writable by group or others | <span class="sev sev-medium">medium</span> | hardening, accounts, permissions |
| `HRD-ACC-FORWARD` | No .forward, .netrc or .rhosts files | <span class="sev sev-high">high</span> | hardening, accounts |
| `HRD-ACC-TMOUT` | Idle shells time out after at most 15 minutes | <span class="sev sev-low">low</span> | hardening, accounts |
| `HRD-ACC-UMASK` | The default umask is 027 or stricter | <span class="sev sev-low">low</span> | hardening, accounts |
| `HRD-PERM-_etc_passwd` | /etc/passwd is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_passwd-` | /etc/passwd- is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_group` | /etc/group is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_group-` | /etc/group- is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_shadow` | /etc/shadow is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_shadow-` | /etc/shadow- is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_gshadow` | /etc/gshadow is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_gshadow-` | /etc/gshadow- is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_shells` | /etc/shells is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_security_opasswd` | /etc/security/opasswd is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_ssh_sshd_config` | /etc/ssh/sshd_config is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_crontab` | /etc/crontab is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_cron.hourly` | /etc/cron.hourly is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_cron.daily` | /etc/cron.daily is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_cron.weekly` | /etc/cron.weekly is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_cron.monthly` | /etc/cron.monthly is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_cron.d` | /etc/cron.d is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_issue` | /etc/issue is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_issue.net` | /etc/issue.net is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-_etc_motd` | /etc/motd is owned by root and not too permissive | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-WORLD-WRITABLE` | No world-writable files | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-UNOWNED` | No files without an owner or group | <span class="sev sev-medium">medium</span> | hardening, permissions |
| `HRD-BOOT-CFG` | The bootloader configuration is only readable by root | <span class="sev sev-high">high</span> | hardening, boot |
| `HRD-BOOT-PASSWORD` | The bootloader is protected by a password | <span class="sev sev-high">high</span> | hardening, boot |
| `HRD-BOOT-RESCUE` | Rescue and emergency mode require authentication | <span class="sev sev-high">high</span> | hardening, boot |
| `HRD-MNT-AIDE` | A file integrity checker is installed and scheduled | <span class="sev sev-medium">medium</span> | hardening, maintenance, integrity |
| `HRD-MNT-GPGCHECK` | Package signatures are checked for every repository | <span class="sev sev-high">high</span> | hardening, maintenance, packages |
| `HRD-MNT-UPDATES` | No security updates are pending | <span class="sev sev-high">high</span> | hardening, maintenance, updates |
| `HRD-AUD-PRIVILEGED` | Every SUID/SGID program is covered by an audit rule | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-ACL` | Audit rules cover ACL changes | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-SELINUX-TOOLS` | Audit rules cover SELinux management commands | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-USERMOD` | Audit rules cover account management commands | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-SUDO-LOG` | Audit rules cover the sudo log | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-CRON` | Audit rules cover changes to cron configuration | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-RULE-SSHD-CONFIG` | Audit rules cover changes to the sshd configuration | <span class="sev sev-medium">medium</span> | hardening, audit |
| `HRD-AUD-KEEP-action_mail_acct` | auditd.conf: action_mail_acct == root | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-KEEP-flush` | auditd.conf: flush ~ (?i)^(incremental_async\|data\|sync)$ | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-KEEP-local_events` | auditd.conf: local_events ~ (?i)^yes$ | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-KEEP-log_group` | auditd.conf: log_group ~ ^(root\|0)$ | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-KEEP-max_log_file` | auditd.conf: max_log_file >= 8 | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-KEEP-num_logs` | auditd.conf: num_logs >= 5 | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-KEEP-write_logs` | auditd.conf: write_logs ~ (?i)^yes$ | <span class="sev sev-low">low</span> | hardening, audit |
| `HRD-AUD-LOG-PERMS` | Audit logs are only accessible by root | <span class="sev sev-high">high</span> | hardening, audit, permissions |
| `HRD-AUD-CONF-PERMS` | Audit configuration is only writable by root | <span class="sev sev-medium">medium</span> | hardening, audit, permissions |
| `HRD-AUD-TOOL-auditctl` | Audit tool auditctl is owned by root and not writable by others | <span class="sev sev-low">low</span> | hardening, audit, permissions |
| `HRD-AUD-TOOL-auditd` | Audit tool auditd is owned by root and not writable by others | <span class="sev sev-low">low</span> | hardening, audit, permissions |
| `HRD-AUD-TOOL-ausearch` | Audit tool ausearch is owned by root and not writable by others | <span class="sev sev-low">low</span> | hardening, audit, permissions |
| `HRD-AUD-TOOL-aureport` | Audit tool aureport is owned by root and not writable by others | <span class="sev sev-low">low</span> | hardening, audit, permissions |
| `HRD-AUD-TOOL-autrace` | Audit tool autrace is owned by root and not writable by others | <span class="sev sev-low">low</span> | hardening, audit, permissions |
| `HRD-AUD-TOOL-augenrules` | Audit tool augenrules is owned by root and not writable by others | <span class="sev sev-low">low</span> | hardening, audit, permissions |
| `HRD-KCFG-CONFIG_BUG_ON_DATA_CORRUPTION` | Kernel built with CONFIG_BUG_ON_DATA_CORRUPTION=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_COMPAT_BRK` | Kernel built with CONFIG_COMPAT_BRK=n | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_DEVMEM` | Kernel built with CONFIG_DEVMEM=n | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_FORTIFY_SOURCE` | Kernel built with CONFIG_FORTIFY_SOURCE=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_HARDENED_USERCOPY` | Kernel built with CONFIG_HARDENED_USERCOPY=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_LEGACY_PTYS` | Kernel built with CONFIG_LEGACY_PTYS=n | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_MODULE_SIG` | Kernel built with CONFIG_MODULE_SIG=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_PROC_KCORE` | Kernel built with CONFIG_PROC_KCORE=n | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_RANDOMIZE_BASE` | Kernel built with CONFIG_RANDOMIZE_BASE=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_SCHED_STACK_END_CHECK` | Kernel built with CONFIG_SCHED_STACK_END_CHECK=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_SECCOMP` | Kernel built with CONFIG_SECCOMP=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_SECCOMP_FILTER` | Kernel built with CONFIG_SECCOMP_FILTER=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_SECURITY_YAMA` | Kernel built with CONFIG_SECURITY_YAMA=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_STACKPROTECTOR_STRONG` | Kernel built with CONFIG_STACKPROTECTOR_STRONG=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_STRICT_KERNEL_RWX` | Kernel built with CONFIG_STRICT_KERNEL_RWX=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KCFG-CONFIG_STRICT_MODULE_RWX` | Kernel built with CONFIG_STRICT_MODULE_RWX=y | <span class="sev sev-low">low</span> | hardening, kernel, kernel-config |
| `HRD-KRN-CPU-VULNERABILITIES` | The kernel mitigates all known CPU vulnerabilities | <span class="sev sev-high">high</span> | hardening, kernel |
| `HRD-KRN-NX` | The CPU's no-execute (NX) protection is active | <span class="sev sev-medium">medium</span> | hardening, kernel |
| `HRD-BOOTPARAM-init_on_free-1` | Kernel command line contains init_on_free=1 | <span class="sev sev-low">low</span> | hardening, kernel, boot |
| `HRD-BOOTPARAM-page_alloc.shuffle-1` | Kernel command line contains page_alloc.shuffle=1 | <span class="sev sev-low">low</span> | hardening, kernel, boot |
| `HRD-BOOTPARAM-slab_nomerge` | Kernel command line contains slab_nomerge | <span class="sev sev-low">low</span> | hardening, kernel, boot |
| `HRD-BOOTPARAM-vsyscall-none` | Kernel command line contains vsyscall=none | <span class="sev sev-low">low</span> | hardening, kernel, boot |
| `HRD-BOOTPARAM-pti-on` | Kernel command line contains pti=on | <span class="sev sev-low">low</span> | hardening, kernel, boot |
| `HRD-KRN-STRICT-kernel.kexec_load_disabled` | kernel.kexec_load_disabled == 1 (strict, may affect kdump or containers) | <span class="sev sev-low">low</span> | hardening, kernel, sysctl, strict |
| `HRD-KRN-STRICT-user.max_user_namespaces` | user.max_user_namespaces == 0 (strict, may affect kdump or containers) | <span class="sev sev-low">low</span> | hardening, kernel, sysctl, strict |
| `HRD-PAM-NULLOK` | PAM does not accept empty passwords (no nullok) | <span class="sev sev-high">high</span> | hardening, authentication, pam |
| `HRD-PAM-FAILLOCK-ROOT` | Failed logins also lock the root account | <span class="sev sev-low">low</span> | hardening, authentication, pam |
| `HRD-PAM-FAIL-INTERVAL` | Failed logins are counted over at least 15 minutes | <span class="sev sev-low">low</span> | hardening, authentication, pam |
| `HRD-PWQ-ROOT` | Password quality rules apply to root as well | <span class="sev sev-low">low</span> | hardening, authentication, passwords |
| `HRD-PWQ-RETRY` | Password changes allow at most 3 retries | <span class="sev sev-low">low</span> | hardening, authentication, passwords |
| `HRD-PAM-HASH-ROUNDS` | pam_unix hashes passwords with at least 5000 rounds | <span class="sev sev-low">low</span> | hardening, authentication, passwords |
| `HRD-ACC-SYSTEM-SHELL` | System accounts have no login shell | <span class="sev sev-medium">medium</span> | hardening, accounts |
| `HRD-ACC-HOME-MODE` | Home directories are mode 750 or stricter | <span class="sev sev-medium">medium</span> | hardening, accounts, permissions |
| `HRD-ACC-SHELL-UMASK` | Every umask set in shell start files is 027 or stricter | <span class="sev sev-low">low</span> | hardening, accounts |
| `HRD-ACC-BANNER-OSINFO` | Login banners do not reveal the operating system | <span class="sev sev-low">low</span> | hardening, accounts, banners |
| `HRD-ACC-BANNER-PRESENT` | A login banner is configured | <span class="sev sev-low">low</span> | hardening, accounts, banners |
| `HRD-SUDO-INCLUDES` | sudo only includes the standard drop-in directory | <span class="sev sev-medium">medium</span> | hardening, access, sudo |
| `HRD-SUDO-REAUTH` | sudo does not ask for the target user's or root's password | <span class="sev sev-low">low</span> | hardening, access, sudo |
| `HRD-SUDO-VISIBLEPW` | sudo never echoes passwords | <span class="sev sev-low">low</span> | hardening, access, sudo |
| `HRD-PERM-BINARIES` | System programs are owned by root and not writable by others | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-LIBRARIES` | System libraries are owned by root and not writable by others | <span class="sev sev-high">high</span> | hardening, permissions |
| `HRD-PERM-SSH-PUBKEYS` | Public SSH host keys are not writable by others | <span class="sev sev-low">low</span> | hardening, permissions, ssh |
| `HRD-PERM-VAR-LOG` | /var/log is owned by root and not writable by others | <span class="sev sev-medium">medium</span> | hardening, permissions, logging |
| `HRD-PERM-KEYTABS` | Kerberos keytabs are only readable by their owner | <span class="sev sev-high">high</span> | hardening, permissions, kerberos |
| `HRD-SEBOOL-deny_execmem` | SELinux boolean deny_execmem is on | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-ftpd_anon_write` | SELinux boolean ftpd_anon_write is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-httpd_enable_homedirs` | SELinux boolean httpd_enable_homedirs is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-httpd_execmem` | SELinux boolean httpd_execmem is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-mount_anyfile` | SELinux boolean mount_anyfile is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-polyinstantiation_enabled` | SELinux boolean polyinstantiation_enabled is on | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-selinuxuser_execmod` | SELinux boolean selinuxuser_execmod is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-selinuxuser_execstack` | SELinux boolean selinuxuser_execstack is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-ssh_sysadm_login` | SELinux boolean ssh_sysadm_login is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-SEBOOL-tftp_anon_write` | SELinux boolean tftp_anon_write is off | <span class="sev sev-low">low</span> | hardening, mac, selinux |
| `HRD-LOG-RSYSLOG-NO-REMOTE-INPUT` | rsyslog does not accept remote messages | <span class="sev sev-medium">medium</span> | hardening, logging |
| `HRD-LOG-RSYSLOG-FILEMODE` | rsyslog creates log files with mode 0640 or stricter | <span class="sev sev-low">low</span> | hardening, logging, permissions |
| `HRD-LOG-JOURNAL-FORWARD` | journald forwards to rsyslog when rsyslog is used | <span class="sev sev-low">low</span> | hardening, logging |
| `HRD-SVC-POSTFIX-LOCAL` | Postfix only listens on loopback | <span class="sev sev-medium">medium</span> | hardening, services, mail |
| `HRD-SVC-NFS-EXPORTS` | NFS exports neither disable root squashing nor allow insecure ports | <span class="sev sev-high">high</span> | hardening, services, nfs |
| `HRD-SVC-SSSD-TLS` | SSSD verifies LDAP server certificates | <span class="sev sev-high">high</span> | hardening, services, sssd |
| `HRD-SVC-CHRONY-USER` | chronyd runs as an unprivileged user | <span class="sev sev-low">low</span> | hardening, services, time |
| `HRD-SVC-CHRONY-CMDPORT` | chronyd does not accept commands from the network | <span class="sev sev-low">low</span> | hardening, services, time |
| `HRD-SVC-VSFTPD-ANON` | vsftpd does not allow anonymous logins | <span class="sev sev-high">high</span> | hardening, services, ftp |
| `HRD-SVC-USBGUARD` | USBGuard controls USB devices | <span class="sev sev-low">low</span> | hardening, services, usb |
| `HRD-SW-UNWANTED-prelink` | prelink is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-UNWANTED-mcstrans` | mcstrans is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-UNWANTED-setroubleshoot` | setroubleshoot is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-UNWANTED-xorg-x11-server-Xorg` | xorg-x11-server-Xorg is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-UNWANTED-xserver-xorg-core` | xserver-xorg-core is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-UNWANTED-gdm` | gdm is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-UNWANTED-gdm3` | gdm3 is not installed | <span class="sev sev-low">low</span> | hardening, packages |
| `HRD-SW-REQUIRED` | Packages a hardened server needs are installed | <span class="sev sev-medium">medium</span> | hardening, packages |
| `HRD-SW-LOCALPKG-GPG` | Locally installed packages are signature-checked | <span class="sev sev-low">low</span> | hardening, maintenance, packages |
| `HRD-SW-AIDE-ACLS` | AIDE also checks ACLs and extended attributes | <span class="sev sev-low">low</span> | hardening, maintenance, integrity |
| `HRD-SW-FIPS` | The kernel runs in FIPS mode (informational) | <span class="sev sev-info">info</span> | hardening, crypto |

## Policy

```yaml title="examples/compliance/linux-hardening.yml" linenums="1"
name: Linux hardening baseline
version: 1.0.0
description: >
  A broad server hardening baseline for current Linux distributions,
  structured like the public hardening guides of the SCAP Security Guide
  (OpenSCAP) and the CIS benchmarks: file systems, services, network
  parameters, auditing, logging, access control, accounts, file
  permissions, boot and maintenance. Check IDs and wording are our own; the
  thresholds are common defaults and can be tuned in `vars`. Select
  sections with tags, e.g. `--tags network` or `--tags audit`.

defaults:
  when: facts.os == "linux"

vars:
  uid_min: 1000
  disabled_kernel_modules: [cramfs, freevxfs, hfs, hfsplus, jffs2, udf, usb-storage, dccp, sctp, rds, tipc, firewire-core, bluetooth]

  # path, option: mount options for separate partitions (checked if mounted)
  mount_options:
    - { path: /tmp, option: nodev }
    - { path: /tmp, option: nosuid }
    - { path: /tmp, option: noexec }
    - { path: /dev/shm, option: nodev }
    - { path: /dev/shm, option: nosuid }
    - { path: /dev/shm, option: noexec }
    - { path: /var/tmp, option: nodev }
    - { path: /var/tmp, option: nosuid }
    - { path: /var/tmp, option: noexec }
    - { path: /home, option: nodev }
    - { path: /home, option: nosuid }
    - { path: /var/log, option: nodev }
    - { path: /var/log, option: nosuid }
    - { path: /var/log, option: noexec }
    - { path: /var/log/audit, option: nodev }
    - { path: /var/log/audit, option: nosuid }
    - { path: /var/log/audit, option: noexec }

  forbidden_services:
    [avahi-daemon, cups, dhcpd, dhcpd6, slapd, nfs-server, rpcbind, named, vsftpd, dovecot, smb,
     squid, snmpd, ypserv, rsyncd, telnet.socket, tftp.socket, xinetd, autofs]

  forbidden_rpm_packages: [ypbind, rsh, talk, telnet, tftp, xinetd, ypserv, rsh-server, telnet-server, tftp-server]
  forbidden_deb_packages: [nis, rsh-client, talk, telnet, tftp, xinetd, rsh-server, telnetd, tftpd]

  # Every value is a complete condition.
  sysctl_ipv4:
    net.ipv4.ip_forward: "== 0"
    net.ipv4.conf.all.send_redirects: "== 0"
    net.ipv4.conf.default.send_redirects: "== 0"
    net.ipv4.conf.all.accept_source_route: "== 0"
    net.ipv4.conf.default.accept_source_route: "== 0"
    net.ipv4.conf.all.accept_redirects: "== 0"
    net.ipv4.conf.default.accept_redirects: "== 0"
    net.ipv4.conf.all.secure_redirects: "== 0"
    net.ipv4.conf.default.secure_redirects: "== 0"
    net.ipv4.conf.all.log_martians: "== 1"
    net.ipv4.conf.default.log_martians: "== 1"
    net.ipv4.icmp_echo_ignore_broadcasts: "== 1"
    net.ipv4.icmp_ignore_bogus_error_responses: "== 1"
    net.ipv4.conf.all.rp_filter: "in [1, 2]"
    net.ipv4.conf.default.rp_filter: "in [1, 2]"
    net.ipv4.tcp_syncookies: "== 1"
  sysctl_ipv6:
    net.ipv6.conf.all.forwarding: "== 0"
    net.ipv6.conf.all.accept_ra: "== 0"
    net.ipv6.conf.default.accept_ra: "== 0"
    net.ipv6.conf.all.accept_redirects: "== 0"
    net.ipv6.conf.default.accept_redirects: "== 0"
    net.ipv6.conf.all.accept_source_route: "== 0"
    net.ipv6.conf.default.accept_source_route: "== 0"
  sysctl_kernel:
    kernel.randomize_va_space: "== 2"
    kernel.kptr_restrict: ">= 1"
    kernel.dmesg_restrict: "== 1"
    kernel.yama.ptrace_scope: ">= 1"
    kernel.unprivileged_bpf_disabled: ">= 1"
    kernel.perf_event_paranoid: ">= 2"
    kernel.sysrq: "== 0"
    net.core.bpf_jit_harden: "== 2"
    dev.tty.ldisc_autoload: "== 0"
    fs.suid_dumpable: "== 0"
    fs.protected_hardlinks: "== 1"
    fs.protected_symlinks: "== 1"
    fs.protected_fifos: ">= 1"
    fs.protected_regular: ">= 1"

  # Audit rules: each pattern must appear in `auditctl -l`.
  audit_rules:
    - { id: TIME, name: changes to the system time, pattern: "(adjtimex|settimeofday|clock_settime)" }
    - { id: LOCALTIME, name: changes to /etc/localtime, pattern: "/etc/localtime" }
    - { id: PASSWD, name: changes to /etc/passwd, pattern: "/etc/passwd" }
    - { id: GROUP, name: changes to /etc/group, pattern: "/etc/group" }
    - { id: SHADOW, name: changes to /etc/shadow, pattern: "/etc/shadow" }
    - { id: GSHADOW, name: changes to /etc/gshadow, pattern: "/etc/gshadow" }
    - { id: OPASSWD, name: changes to /etc/security/opasswd, pattern: "/etc/security/opasswd" }
    - { id: HOSTNAME, name: changes to the host name, pattern: "(sethostname|setdomainname)" }
    - { id: ISSUE, name: changes to the login banners, pattern: "/etc/issue" }
    - { id: HOSTS, name: changes to /etc/hosts, pattern: "/etc/hosts" }
    - { id: MACPOLICY, name: changes to the MAC policy, pattern: "(/etc/selinux|/etc/apparmor)" }
    - { id: LOGINS, name: login records, pattern: "(/var/log/lastlog|/var/run/faillock)" }
    - { id: SESSION, name: session records, pattern: "(/var/run/utmp|/var/log/wtmp|/var/log/btmp)" }
    - { id: PERMMOD, name: permission changes, pattern: "(chmod|chown|setxattr)" }
    - { id: ACCESS, name: denied file access, pattern: "(EACCES|EPERM)" }
    - { id: MOUNTS, name: mounts, pattern: "mount" }
    - { id: DELETE, name: file deletions by users, pattern: "(unlink|rename)" }
    - { id: SUDOERS, name: changes to sudoers, pattern: "/etc/sudoers" }
    - { id: MODULES, name: kernel module loading, pattern: "(init_module|finit_module|delete_module)" }

  # path, forbidden permission bits (for find -perm /MASK), all owned by root
  file_permissions:
    - { path: /etc/passwd, forbidden: "0133" }
    - { path: /etc/passwd-, forbidden: "0133" }
    - { path: /etc/group, forbidden: "0133" }
    - { path: /etc/group-, forbidden: "0133" }
    - { path: /etc/shadow, forbidden: "0137" }
    - { path: /etc/shadow-, forbidden: "0137" }
    - { path: /etc/gshadow, forbidden: "0137" }
    - { path: /etc/gshadow-, forbidden: "0137" }
    - { path: /etc/shells, forbidden: "0133" }
    - { path: /etc/security/opasswd, forbidden: "0177" }
    - { path: /etc/ssh/sshd_config, forbidden: "0177" }
    - { path: /etc/crontab, forbidden: "0177" }
    - { path: /etc/cron.hourly, forbidden: "0077" }
    - { path: /etc/cron.daily, forbidden: "0077" }
    - { path: /etc/cron.weekly, forbidden: "0077" }
    - { path: /etc/cron.monthly, forbidden: "0077" }
    - { path: /etc/cron.d, forbidden: "0077" }
    - { path: /etc/issue, forbidden: "0133" }
    - { path: /etc/issue.net, forbidden: "0133" }
    - { path: /etc/motd, forbidden: "0133" }

  sshd_expected:
    permitrootlogin: "== no"
    permitemptypasswords: "== no"
    permituserenvironment: "== no"
    hostbasedauthentication: "== no"
    ignorerhosts: "== yes"
    x11forwarding: "== no"
    allowtcpforwarding: "== no"
    usepam: "== yes"
    loglevel: "in [INFO, VERBOSE]"
    maxauthtries: "<= 4"
    maxsessions: "<= 10"
    logingracetime: "<= 60"
    clientalivecountmax: "<= 3"
    banner: "!= none"
    ciphers: "!~ (cbc|arcfour|3des|blowfish)"
    macs: "!~ (md5|-96|umac-64[@-]|hmac-sha1($|,|-etm))"
    kexalgorithms: "!~ (group1-|group14-sha1|group-exchange-sha1)"

  # --- additional rules (coverage of OpenSCAP / Wazuh topics) -------------------
  # Kernel build options that should be enabled (checked in /boot/config-*).
  kernel_config:
    CONFIG_STRICT_KERNEL_RWX: y
    CONFIG_STRICT_MODULE_RWX: y
    CONFIG_STACKPROTECTOR_STRONG: y
    CONFIG_FORTIFY_SOURCE: y
    CONFIG_RANDOMIZE_BASE: y
    CONFIG_HARDENED_USERCOPY: y
    CONFIG_SECCOMP: y
    CONFIG_SECCOMP_FILTER: y
    CONFIG_SECURITY_YAMA: y
    CONFIG_MODULE_SIG: y
    CONFIG_BUG_ON_DATA_CORRUPTION: y
    CONFIG_SCHED_STACK_END_CHECK: y
    CONFIG_DEVMEM: n
    CONFIG_LEGACY_PTYS: n
    CONFIG_COMPAT_BRK: n
    CONFIG_PROC_KCORE: n

  # Optional, stricter kernel settings with side effects (kdump, containers).
  sysctl_kernel_strict:
    kernel.kexec_load_disabled: "== 1"
    user.max_user_namespaces: "== 0"

  # Kernel command line options (x86-only ones are marked).
  boot_parameters:
    - { option: init_on_free=1, arch: any }
    - { option: page_alloc.shuffle=1, arch: any }
    - { option: slab_nomerge, arch: any }
    - { option: vsyscall=none, arch: amd64 }
    - { option: pti=on, arch: amd64 }

  # auditd data retention and behaviour
  auditd_retention:
    num_logs: ">= 5"
    max_log_file: ">= 8"
    write_logs: "~ (?i)^yes$"
    local_events: "~ (?i)^yes$"
    log_group: "~ ^(root|0)$"
    flush: "~ (?i)^(incremental_async|data|sync)$"
    action_mail_acct: "== root"

  audit_tools: [auditctl, auditd, ausearch, aureport, autrace, augenrules]

  # Additional audit rule topics.
  audit_rules_extra:
    - { id: ACL, name: ACL changes, pattern: "(setfacl|chacl)" }
    - { id: SELINUX-TOOLS, name: SELinux management commands, pattern: "(chcon|semanage|setsebool|setfiles|restorecon)" }
    - { id: USERMOD, name: account management commands, pattern: "(usermod|useradd|userdel|groupmod|chage|passwd)" }
    - { id: SUDO-LOG, name: the sudo log, pattern: "/var/log/sudo" }
    - { id: CRON, name: changes to cron configuration, pattern: "(/etc/cron|/var/spool/cron)" }
    - { id: SSHD-CONFIG, name: changes to the sshd configuration, pattern: "/etc/ssh/sshd_config" }

  # SELinux booleans and the value they should have.
  selinux_booleans:
    selinuxuser_execstack: "off"
    selinuxuser_execmod: "off"
    ssh_sysadm_login: "off"
    deny_execmem: "on"
    httpd_enable_homedirs: "off"
    httpd_execmem: "off"
    ftpd_anon_write: "off"
    tftp_anon_write: "off"
    mount_anyfile: "off"
    polyinstantiation_enabled: "on"

  # Packages that should not be on a server.
  unwanted_packages: [prelink, mcstrans, setroubleshoot, xorg-x11-server-Xorg, xserver-xorg-core, gdm, gdm3]
  # Packages a hardened server needs.
  required_packages: [sudo, audit, auditd, chrony, aide, rsyslog]

snippets:
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg-query -W -f='${Status}' {{ arg }} 2>/dev/null | grep 'install ok installed' >/dev/null
    alpine: apk info -e {{ arg }} >/dev/null

  # Prints the last value of a key = value setting from config files.
  # A missing file yields an empty value, which `"!empty"` turns into a failure.
  conf_value: |
    { cat {{ args.files }} 2>/dev/null || true; } |
      awk -F= -v key='{{ args.key }}' '{k = $1; gsub(/[[:space:]]/, "", k)} k == key {v = $2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)} END {print v}'

checks:
  # ===== 1. File systems ==========================================================
  - id: "HRD-FS-MOD-{{ item }}"
    name: "Kernel module {{ item }} is disabled"
    tags: [hardening, filesystems, modules]
    severity: low
    when: facts.is_root
    loop: "{{ disabled_kernel_modules }}"
    run:
      alpine: grep -rhE '^(install|blacklist)[[:space:]]+{{ item }}([[:space:]]|$)' /etc/modprobe.d /lib/modprobe.d 2>/dev/null
      linux: modprobe -n -v {{ item }} 2>&1
    allow_rc: [0, 1, 2]
    expect: { any: ["~ install( {{ item }})? /(usr/)?bin/(true|false)", "~ (?i)not found", "~ ^blacklist"] }
    rationale: "A loadable {{ item }} module adds kernel code for a file system, protocol or device class this server does not use, and a flaw in it becomes exploitable."
    remediation: "printf 'install {{ item }} /bin/false\\nblacklist {{ item }}\\n' > /etc/modprobe.d/{{ item }}.conf"

  - id: "HRD-FS-OPT-{{ item.path | replace('/', '_') }}-{{ item.option }}"
    name: "{{ item.path }} is mounted with {{ item.option }}"
    tags: [hardening, filesystems]
    loop: "{{ mount_options }}"
    only_if: findmnt -n {{ item.path }} >/dev/null
    run: findmnt -n -o OPTIONS {{ item.path }}
    expect: "~ (^|,){{ item.option }}(,|$)"
    rationale: "Without {{ item.option }} on {{ item.path }} users can place device files, setuid programs or executables in a directory they can write to."
    remediation: "Add {{ item.option }} to the options of {{ item.path }} in /etc/fstab or its mount unit and run `mount -o remount {{ item.path }}`."

  - id: HRD-FS-STICKY
    name: All world-writable directories have the sticky bit
    tags: [hardening, filesystems, permissions]
    severity: high
    timeout: 10m
    run: find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Without the sticky bit every user can delete or replace the files of other users in a world-writable directory.
    remediation: Run `chmod +t` on each listed directory.

  - id: HRD-FS-AUTOMOUNT
    name: Automounting of removable media is disabled
    tags: [hardening, filesystems]
    severity: low
    run: systemctl is-enabled autofs 2>/dev/null
    allow_rc: [0, 1, 4]
    expect: "!in [enabled, enabled-runtime]"
    rationale: Automounting makes the content of any attached medium or network share available without a decision by an administrator.
    remediation: systemctl disable --now autofs

  # ===== 2. Services and software =================================================
  - id: "HRD-SVC-{{ item }}"
    name: "Service {{ item }} is neither running nor enabled"
    tags: [hardening, services]
    loop: "{{ forbidden_services }}"
    run: systemctl is-active --quiet {{ item }} || systemctl is-enabled --quiet {{ item }}
    expect: false
    rationale: "A running or enabled {{ item }} adds attack surface for a function this server does not provide."
    remediation: "systemctl disable --now {{ item }}"

  - id: "HRD-PKG-RPM-{{ item }}"
    name: "Legacy package {{ item }} is not installed"
    tags: [hardening, services, packages]
    loop: "{{ forbidden_rpm_packages }}"
    only_if: command -v rpm && ! command -v dpkg
    run: rpm -q --quiet {{ item }}
    expect: false
    rationale: "The legacy package {{ item }} brings clear-text protocols or services that current systems no longer need."
    remediation: "Remove {{ item }} with dnf or zypper."

  - id: "HRD-PKG-DEB-{{ item }}"
    name: "Legacy package {{ item }} is not installed"
    tags: [hardening, services, packages]
    loop: "{{ forbidden_deb_packages }}"
    only_if: command -v dpkg-query
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: false
    rationale: "The legacy package {{ item }} brings clear-text protocols or services that current systems no longer need."
    remediation: "apt-get purge {{ item }}"

  - id: HRD-SVC-MTA-LOCAL
    name: The mail transfer agent only listens on loopback
    tags: [hardening, services, network]
    only_if: command -v ss
    run: ss -Hlnt 'sport = :25' | awk '{print $4}'
    expect: { each: "~ ^(127\\.0\\.0\\.1|\\[::1\\]):25$" }
    rationale: A mail transfer agent that listens on the network accepts connections from any host, although the server only needs to deliver local mail.
    remediation: Bind the mail transfer agent to loopback, for Postfix with `postconf -e inet_interfaces=loopback-only` and a restart.

  - id: HRD-SVC-TIME-SOURCES
    name: The time service has servers configured
    tags: [hardening, services, time]
    run: |
      cat /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony/sources.d/*.sources /etc/systemd/timesyncd.conf 2>/dev/null |
        grep -E '^[[:space:]]*(server|pool|NTP=[^[:space:]])'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: Without a configured time server the clock drifts, which breaks log correlation and time-based authentication such as Kerberos.
    remediation: Add a server or pool line to the chrony configuration, or NTP= to /etc/systemd/timesyncd.conf, and restart the time service.

  # ===== 3. Network ===============================================================
  - id: "HRD-NET-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [hardening, network, sysctl]
    loop: "{{ sysctl_ipv4 }}"
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
    rationale: "With another value of {{ item.key }} the IPv4 stack routes, accepts or leaves unlogged packets that serve spoofing, redirection or flooding attacks."
    remediation: "Set {{ item.key }} in /etc/sysctl.d/60-hardening.conf and run sysctl --system."

  - id: "HRD-NET6-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [hardening, network, sysctl, ipv6]
    loop: "{{ sysctl_ipv6 }}"
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
    rationale: "With another value of {{ item.key }} the host forwards IPv6 packets or accepts router advertisements, redirects or source routes that let another host steer its traffic."
    remediation: "Set {{ item.key }} in /etc/sysctl.d/60-hardening.conf and run sysctl --system."

  - id: HRD-NET-FIREWALL
    name: A host firewall is active
    tags: [hardening, network, firewall]
    severity: high
    run: |
      for unit in firewalld nftables ufw iptables; do systemctl is-active "$unit" 2>/dev/null; done
    allow_rc: [0, 1, 3, 4]
    expect: { some: "== active" }
    rationale: Without a host firewall every listening port is reachable from the whole network.
    remediation: Define rules for the required ports and enable one of firewalld, nftables or ufw, for example with `systemctl enable --now firewalld`.

  - id: HRD-NET-WIRELESS
    name: Wireless interfaces are disabled
    tags: [hardening, network]
    severity: low
    run: find /sys/class/net/*/ -maxdepth 1 -name wireless 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A wireless interface is a path into the server that bypasses the controls of the wired network.
    remediation: Disable the wireless adapter in the firmware setup or blacklist its driver module so that the interface no longer appears.

  # ===== 4. Kernel and process hardening ============================================
  - id: "HRD-KRN-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [hardening, kernel, sysctl]
    loop: "{{ sysctl_kernel }}"
    # Parameters the kernel does not have (e.g. without BPF JIT) are skipped.
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
    rationale: "With another value of {{ item.key }} local users get kernel information or features that make privilege escalation and data leaks easier."
    remediation: "Set {{ item.key }} in /etc/sysctl.d/60-hardening.conf and run sysctl --system."

  - id: HRD-KRN-CORE-LIMITS
    name: Core dumps are restricted by limits
    tags: [hardening, kernel]
    severity: low
    run: |
      cat /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null |
        grep -E '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: A core dump contains the memory of the crashed process, including passwords and keys.
    remediation: Add the line `* hard core 0` to a file in /etc/security/limits.d.

  - id: HRD-KRN-COREDUMP-STORAGE
    name: systemd-coredump does not store dumps
    tags: [hardening, kernel]
    severity: low
    only_if: test -f /etc/systemd/coredump.conf
    run: { use: conf_value, args: { files: "/etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf", key: Storage } }
    expect: "== none"
    rationale: Stored core dumps keep process memory with passwords and keys on disk.
    remediation: Set Storage=none in /etc/systemd/coredump.conf.

  - id: HRD-KRN-AUDIT-BOOT
    name: Auditing starts with the kernel (audit=1)
    tags: [hardening, kernel, audit]
    run: cat /proc/cmdline
    expect: "~ (^| )audit=1( |$)"
    rationale: Without audit=1 processes that start before auditd are never audited.
    remediation: Add audit=1 to the kernel command line in the boot loader configuration and reboot.

  - id: HRD-KRN-AUDIT-BACKLOG
    name: The kernel audit backlog holds at least 8192 events
    tags: [hardening, kernel, audit]
    severity: low
    run: cat /proc/cmdline | tr ' ' '\n' | awk -F= '$1 == "audit_backlog_limit" {print $2}'
    expect: ["!empty", ">= 8192"]
    rationale: With a small backlog audit events from the boot phase are lost before auditd starts reading them.
    remediation: Add audit_backlog_limit=8192 to the kernel command line in the boot loader configuration and reboot.

  # ===== 5. Mandatory access control ================================================
  - id: HRD-MAC-ACTIVE
    name: SELinux or AppArmor is enforcing
    tags: [hardening, mac]
    severity: high
    run: |
      if command -v getenforce >/dev/null; then getenforce
      elif command -v aa-enabled >/dev/null && aa-enabled --quiet; then echo AppArmor
      else echo none; fi
    expect: "in [Enforcing, AppArmor]"
    rationale: Without mandatory access control a compromised service can use every right of its user account.
    remediation: Set SELINUX=enforcing in /etc/selinux/config and reboot, or enable AppArmor.

  - id: HRD-MAC-CMDLINE
    name: The MAC system is not disabled at boot
    tags: [hardening, mac, boot]
    severity: high
    run: cat /proc/cmdline
    expect: "!~ (selinux=0|enforcing=0|apparmor=0)"
    rationale: selinux=0, enforcing=0 or apparmor=0 on the kernel command line switches mandatory access control off, whatever the configuration files say.
    remediation: Remove the option from the kernel command line in the boot loader configuration and reboot.

  # ===== 6. Auditing ==============================================================
  - id: HRD-AUD-SERVICE
    name: auditd is running and enabled
    tags: [hardening, audit]
    severity: high
    run: echo "$(systemctl show -p ActiveState auditd | cut -d= -f2) $(systemctl show -p UnitFileState auditd | cut -d= -f2)"
    expect: "== active enabled"
    rationale: Without auditd security-relevant events such as logins and permission changes leave no audit trail.
    remediation: Install the audit package and run `systemctl enable --now auditd`.

  - id: "HRD-AUD-RULE-{{ item.id }}"
    name: "Audit rules cover {{ item.name }}"
    tags: [hardening, audit]
    when: facts.is_root
    only_if: command -v auditctl
    loop: "{{ audit_rules }}"
    run: auditctl -l
    expect: "~ {{ item.pattern }}"
    rationale: "Without an audit rule for {{ item.name }} these events leave no trace in the audit log."
    remediation: "Add a rule for {{ item.name }} to a file in /etc/audit/rules.d and load it with `augenrules --load`."

  - id: HRD-AUD-IMMUTABLE
    name: The audit configuration is immutable until reboot
    tags: [hardening, audit]
    severity: low
    when: facts.is_root
    only_if: command -v auditctl
    run: auditctl -s | awk '$1 == "enabled" {print $2}'
    expect: "== 2"
    rationale: Without the immutable flag an attacker with root rights can remove audit rules and then act unrecorded.
    remediation: Add "-e 2" as the last line of the audit rules.

  - id: "HRD-AUD-CONF-{{ item.key }}"
    name: "auditd.conf: {{ item.key }} {{ item.value }}"
    tags: [hardening, audit]
    # auditd accepts the values in any case (ROTATE, rotate).
    only_if: test -f /etc/audit/auditd.conf
    loop:
      max_log_file_action: "~ (?i)^(keep_logs|rotate)$"
      space_left_action: "~ (?i)^(email|exec|single|halt)$"
      admin_space_left_action: "~ (?i)^(single|halt)$"
      disk_full_action: "~ (?i)^(single|halt)$"
      disk_error_action: "~ (?i)^(syslog|single|halt)$"
    run: { use: conf_value, args: { files: /etc/audit/auditd.conf, key: "{{ item.key }}" } }
    expect: "{{ item.value }}"
    rationale: "The setting {{ item.key }} decides what auditd does when its log or disk runs full or fails, and another value lets audit records get lost unnoticed."
    remediation: "Set {{ item.key }} in /etc/audit/auditd.conf to one of the accepted values and restart auditd."

  # ===== 7. Logging ===============================================================
  - id: HRD-LOG-JOURNAL-PERSISTENT
    name: journald keeps logs on disk
    tags: [hardening, logging]
    run: |
      storage=$(cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null |
        awk -F= '$1 == "Storage" {v = $2} END {print v}')
      case "$storage" in
        persistent) echo ok ;;
        ""|auto) if [ -d /var/log/journal ]; then echo ok; else echo "Storage=auto without /var/log/journal"; fi ;;
        *) echo "Storage=$storage" ;;
      esac
    expect: "== ok"
    rationale: A journal that is kept only in memory is lost at reboot, and with it the record of what happened on the system.
    remediation: Set Storage=persistent in /etc/systemd/journald.conf and restart systemd-journald.

  - id: HRD-LOG-JOURNAL-COMPRESS
    name: journald compresses large entries
    tags: [hardening, logging]
    severity: low
    run: { use: conf_value, args: { files: "/etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf", key: Compress } }
    expect: "in [yes, '']"
    as: string
    rationale: Without compression large entries use up the journal's disk quota sooner, and older entries are rotated away earlier.
    remediation: Remove Compress=no from the journald configuration.

  - id: HRD-LOG-FILES
    name: Log files are not readable by others
    tags: [hardening, logging, permissions]
    run: find /var/log -type f -perm /o+rwx 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Log files contain user names, addresses and error details that help an unprivileged user to prepare an attack.
    remediation: Run `chmod o-rwx` on the listed files and correct the mode in the logrotate or syslog configuration that creates them.

  # ===== 8. Access: SSH, sudo, su, cron ==============================================
  - id: "HRD-SSH-{{ item.key | upper }}"
    name: "sshd: {{ item.key }} {{ item.value }}"
    tags: [hardening, access, ssh]
    severity: high
    when: facts.is_root
    only_if: command -v sshd
    loop: "{{ sshd_expected }}"
    run: |
      sshd -T 2>/dev/null | awk -v key={{ item.key }} '$1 == key {print substr($0, length(key) + 2)}'
    expect: "{{ item.value }}"
    rationale: "sshd is the main remote entry to the server. Another value of {{ item.key }} weakens its authentication, session limits, forwarding restrictions, logging or cryptography."
    remediation: "Set {{ item.key }} in /etc/ssh/sshd_config to a value that meets the expectation and reload sshd."

  - id: HRD-SSH-CLIENTALIVE
    name: "sshd: idle sessions are disconnected within 15 minutes"
    tags: [hardening, access, ssh]
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "clientaliveinterval" {print $2}'
    expect: ["> 0", "<= 900"]
    rationale: An abandoned SSH session stays usable for anyone who gets access to the client.
    remediation: Set ClientAliveInterval to a value between 1 and 900 in /etc/ssh/sshd_config and reload sshd.

  - id: HRD-SUDO-PTY
    name: sudo uses a pseudo terminal
    tags: [hardening, access, sudo]
    when: facts.is_root
    run: |
      cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '^[[:space:]]*Defaults([[:space:]]+|.*[[:space:],])use_pty([[:space:],]|$)'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: Without use_pty a program started through sudo can keep access to the user's terminal after sudo ends and inject commands.
    remediation: Add the line `Defaults use_pty` with `visudo`.

  - id: HRD-SUDO-LOG
    name: sudo writes a log file
    tags: [hardening, access, sudo]
    when: facts.is_root
    run: cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '^[[:space:]]*Defaults.*logfile='
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: Without a log file of its own sudo commands are only found among other syslog messages.
    remediation: Add the line `Defaults logfile=/var/log/sudo.log` with `visudo`.

  - id: HRD-SUDO-TIMEOUT
    name: sudo authentication expires within 15 minutes
    tags: [hardening, access, sudo]
    severity: low
    when: facts.is_root
    run: |
      t=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -oE 'timestamp_timeout=-?[0-9]+' | tail -1 | cut -d= -f2)
      echo "${t:-5}"
    expect: [">= 0", "<= 15"]
    rationale: A long or unlimited sudo timestamp lets anyone at an unattended terminal run commands as root without a password.
    remediation: Set timestamp_timeout in a Defaults line to a value between 0 and 15 with `visudo`.

  - id: HRD-SUDO-NOAUTH
    name: No sudo rule disables authentication
    tags: [hardening, access, sudo]
    severity: high
    when: facts.is_root
    run: cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: ["~ ^[^#]*(!authenticate|NOPASSWD:[[:space:]]*ALL[[:space:]]*$)"] }
    rationale: A rule without authentication lets anyone who takes over the account or an open session become root without a credential.
    remediation: Remove !authenticate and the NOPASSWD tag in front of ALL from the sudo rules with `visudo`.

  - id: HRD-SU-WHEEL
    name: su is restricted to a group (pam_wheel)
    tags: [hardening, access]
    run: cat /etc/pam.d/su 2>/dev/null
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\\.so" }
    rationale: Without pam_wheel every user who learns the root password can become root with su.
    remediation: Enable the line `auth required pam_wheel.so use_uid` in /etc/pam.d/su.

  - id: HRD-CRON-ALLOW
    name: cron and at are restricted to allowed users
    tags: [hardening, access, cron]
    severity: low
    run: |
      for f in cron at; do
        if [ -f /etc/$f.deny ] || [ ! -f /etc/$f.allow ]; then echo "$f: use /etc/$f.allow"; fi
      done
    expect: empty
    rationale: A deny list lets every account that is not on it schedule jobs, including accounts created later.
    remediation: Create /etc/cron.allow and /etc/at.allow with the permitted users and remove /etc/cron.deny and /etc/at.deny.

  # ===== 9. Authentication: PAM and passwords ===================================
  - id: HRD-PAM-FAILLOCK
    name: Accounts lock after at most 5 failed logins
    tags: [hardening, authentication, pam]
    severity: high
    run: { use: conf_value, args: { files: /etc/security/faillock.conf, key: deny } }
    expect: ["!empty", "> 0", "<= 5"]
    rationale: Without a lockout an attacker can try passwords against an account without limit.
    remediation: Set deny to a value between 1 and 5 in /etc/security/faillock.conf.

  - id: HRD-PAM-UNLOCK
    name: Locked accounts unlock after at least 15 minutes (or manually)
    tags: [hardening, authentication, pam]
    run: { use: conf_value, args: { files: /etc/security/faillock.conf, key: unlock_time } }
    expect: ["!empty", { any: ["== 0", ">= 900"] }]
    rationale: A short lockout barely slows password guessing down.
    remediation: Set unlock_time to 0 or to at least 900 in /etc/security/faillock.conf.

  - id: "HRD-PWQ-{{ item.key }}"
    name: "Password quality: {{ item.key }} {{ item.value }}"
    tags: [hardening, authentication, passwords]
    loop:
      minlen: ">= 14"
      minclass: ">= 4"
      maxrepeat: "in [1, 2, 3]"
      maxsequence: "in [1, 2, 3]"
      difok: ">= 2"
    run: { use: conf_value, args: { files: "/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf", key: "{{ item.key }}" } }
    expect: ["!empty", "{{ item.value }}"]
    rationale: "The pwquality rule {{ item.key }} keeps short, simple or barely changed passwords from being set."
    remediation: "Set {{ item.key }} in /etc/security/pwquality.conf to a value that meets the expectation."

  - id: HRD-PWHISTORY
    name: The last 5 passwords cannot be reused
    tags: [hardening, authentication, passwords]
    run: |
      v=$(cat /etc/security/pwhistory.conf 2>/dev/null | awk -F= '{k = $1; gsub(/[[:space:]]/, "", k)} k == "remember" {gsub(/[[:space:]]/, "", $2); print $2}' | tail -1)
      [ -n "$v" ] || v=$(grep -rhoE 'pam_(pwhistory|unix)\.so.*remember=[0-9]+' /etc/pam.d 2>/dev/null | grep -oE 'remember=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
      echo "$v"
    expect: ["!empty", ">= 5"]
    rationale: Without a password history users switch back to an old password that others may already know.
    remediation: Set remember = 5 in /etc/security/pwhistory.conf and use pam_pwhistory in the password stack.

  - id: HRD-PW-HASH
    name: New passwords are hashed with SHA-512 or yescrypt
    tags: [hardening, authentication, passwords]
    severity: high
    run: cat /etc/login.defs 2>/dev/null | awk '$1 == "ENCRYPT_METHOD" {print $2}'
    allow_rc: [0, 1]
    expect: "in [SHA512, YESCRYPT]"
    rationale: ENCRYPT_METHOD decides how every new password is hashed, and a weak scheme makes the hashes easy to crack.
    remediation: Set ENCRYPT_METHOD in /etc/login.defs to YESCRYPT, or to SHA512 where yescrypt is not supported.

  # ===== 10. Accounts ===============================================================
  - id: "HRD-ACC-DEFS-{{ item.key }}"
    name: "login.defs: {{ item.key }} {{ item.value }}"
    tags: [hardening, accounts, passwords]
    loop:
      PASS_MAX_DAYS: "<= 365"
      PASS_MIN_DAYS: ">= 1"
      PASS_WARN_AGE: ">= 7"
    run: cat /etc/login.defs 2>/dev/null | awk -v key={{ item.key }} '$1 == key {print $2}'
    allow_rc: [0, 1]
    expect: ["!empty", "{{ item.value }}"]
    rationale: "The setting {{ item.key }} is a password ageing default for new accounts, and a looser value lets passwords live too long, be changed back at once or expire without warning."
    remediation: "Set {{ item.key }} in /etc/login.defs to a value that meets the expectation. Existing accounts are changed with chage."

  - id: HRD-ACC-INACTIVE
    name: Accounts are disabled 45 days after password expiry
    tags: [hardening, accounts, passwords]
    severity: low
    run: useradd -D | awk -F= '$1 == "INACTIVE" {print $2}'
    expect: ["!= -1", ">= 0", "<= 45"]
    rationale: Accounts that stay enabled with an expired password are forgotten entry points.
    remediation: useradd -D -f 45

  - id: HRD-ACC-SHADOWED
    name: All accounts use shadowed passwords
    tags: [hardening, accounts]
    severity: high
    run: |
      cut -d: -f1,2 /etc/passwd
    expect: { each: "~ :x$" }
    rationale: A password hash stored in the world-readable /etc/passwd can be cracked offline by any user.
    remediation: Run `pwconv`.

  - id: HRD-ACC-EMPTY
    name: No account has an empty password
    tags: [hardening, accounts]
    severity: critical
    when: facts.is_root
    run: |
      cut -d: -f1,2 /etc/shadow
    expect: { none: "~ :$" }
    rationale: Anyone can log in to an account whose password field in /etc/shadow is empty.
    remediation: Set a password for each affected account or lock it with `passwd -l <account>`.

  - id: HRD-ACC-UID0
    name: root is the only account with UID 0
    tags: [hardening, accounts]
    severity: critical
    run: |
      awk -F: '$3 == 0 {print $1}' /etc/passwd
    expect: "== root"
    rationale: Every account with UID 0 is root under another name, which hides who acted with full privileges.
    remediation: Find out who created the additional accounts, then delete them or give them an unprivileged UID.

  - id: HRD-ACC-ROOT-GID
    name: root's primary group is GID 0
    tags: [hardening, accounts]
    run: |
      awk -F: '$1 == "root" {print $4}' /etc/passwd
    expect: "== 0"
    rationale: With another primary group the files root creates belong to a group whose members may then get access to them.
    remediation: usermod -g 0 root

  - id: HRD-ACC-LEGACY
    name: No legacy "+" NIS entries in account files
    tags: [hardening, accounts]
    when: facts.is_root
    run: cat /etc/passwd /etc/shadow /etc/group 2>/dev/null
    expect: { none: "~ ^\\+" }
    rationale: A line starting with + pulls accounts from NIS into the local files and can grant access to accounts nobody defined locally.
    remediation: Remove the lines starting with + from /etc/passwd, /etc/shadow and /etc/group.

  - id: HRD-ACC-SYSTEM-LOCKED
    name: System accounts are locked
    tags: [hardening, accounts]
    when: facts.is_root
    run: |
      awk -F: -v min={{ uid_min }} 'NR == FNR {uid[$1] = $3; next}
        ($1 in uid) && uid[$1] < min && $1 != "root" && $2 !~ /^[!*]/ {print $1}' /etc/passwd /etc/shadow
    expect: empty
    rationale: A system account with a usable password allows logins although only a service needs the account.
    remediation: Lock each listed account with `passwd -l <account>`.

  - id: HRD-ACC-PW-CHANGED
    name: No password change date lies in the future
    tags: [hardening, accounts]
    severity: low
    when: facts.is_root
    run: |
      awk -F: -v today="$(( $(date +%s) / 86400 ))" '$3 != "" && $3 > today {print $1}' /etc/shadow
    expect: empty
    rationale: A change date in the future keeps password expiry from taking effect and points to a wrong clock or a manipulated entry.
    remediation: Check the system clock and correct the date with `chage -d <date> <account>`.

  - id: HRD-ACC-MAXDAYS
    name: Every user password expires within 365 days
    tags: [hardening, accounts, passwords]
    when: facts.is_root
    run: |
      awk -F: '$2 ~ /^\$/ && ($5 == "" || $5 > 365) {print $1}' /etc/shadow
    expect: empty
    rationale: A password that never expires stays valid indefinitely after it has leaked.
    remediation: Run `chage --maxdays 365 <account>` for each listed account.

  - id: HRD-ACC-GROUPS-EXIST
    name: Every primary group of an account exists
    tags: [hardening, accounts]
    run: |
      awk -F: 'NR == FNR {g[$3] = 1; next} !($4 in g) {print $1 " (gid " $4 ")"}' /etc/group /etc/passwd
    expect: empty
    rationale: Files of an undefined GID belong to no administered group, and a group created later with that GID gets access to them.
    remediation: Create the missing group with `groupadd -g <gid> <name>` or assign the account an existing primary group with `usermod -g`.

  - id: HRD-ACC-SHADOW-GROUP
    name: The shadow group has no members
    tags: [hardening, accounts]
    run: |
      awk -F: '$1 == "shadow" {print $4}' /etc/group
    expect: empty
    rationale: Members of the shadow group can read the password hashes in /etc/shadow.
    remediation: Remove each member with `gpasswd -d <user> shadow`.

  - id: HRD-ACC-DUPLICATES
    name: No duplicate user names, UIDs, group names or GIDs
    tags: [hardening, accounts]
    severity: high
    run: |
      cut -d: -f1 /etc/passwd | sort | uniq -d | sed 's/^/user name /'
      cut -d: -f3 /etc/passwd | sort | uniq -d | sed 's/^/uid /'
      cut -d: -f1 /etc/group | sort | uniq -d | sed 's/^/group name /'
      cut -d: -f3 /etc/group | sort | uniq -d | sed 's/^/gid /'
    expect: empty
    rationale: Duplicate names or IDs make it impossible to tell from file ownership and logs which account or group is meant.
    remediation: Rename or renumber the listed duplicates with usermod or groupmod.

  - id: HRD-ACC-HOMES
    name: Interactive users have an existing home directory they own
    tags: [hardening, accounts]
    run: |
      awk -F: -v min={{ uid_min }} '$3 >= min && $3 != 65534 && $7 !~ /(nologin|false)$/ {print $1, $6}' /etc/passwd |
        while read -r user home; do
          if [ ! -d "$home" ]; then echo "$user: $home is missing"
          elif [ "$(stat -c %U "$home")" != "$user" ]; then echo "$user: $home is not owned by $user"; fi
        done
    expect: empty
    rationale: A home directory owned by someone else lets that user control the login files of the account, and without a home directory a session starts in /.
    remediation: Create the missing home directory or correct its owner with `chown <user> <home>`.

  - id: HRD-ACC-DOTFILES
    name: Dot files in home directories are not writable by group or others
    tags: [hardening, accounts, permissions]
    run: |
      awk -F: -v min={{ uid_min }} '$3 >= min && $3 != 65534 {print $6}' /etc/passwd |
        while read -r home; do
          if [ -d "$home" ]; then find "$home" -maxdepth 1 -name '.*' -type f -perm /go+w; fi
        done
    expect: empty
    rationale: Whoever can write the dot files of a user can run commands as that user at the next login.
    remediation: Run `chmod go-w` on the listed files.

  - id: HRD-ACC-FORWARD
    name: No .forward, .netrc or .rhosts files
    tags: [hardening, accounts]
    severity: high
    run: |
      find /root /home -maxdepth 2 \( -name .forward -o -name .netrc -o -name .rhosts -o -name .shosts \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: .rhosts and .shosts allow logins without a password, .netrc stores passwords in clear text and .forward sends mail to other systems or programs.
    remediation: Check with the owners that the listed files are not needed and remove them.

  - id: HRD-ACC-TMOUT
    name: Idle shells time out after at most 15 minutes
    tags: [hardening, accounts]
    severity: low
    run: |
      cat /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc 2>/dev/null |
        grep -oE '^[^#]*TMOUT=[0-9]+' | grep -oE '[0-9]+$' | sort -n | sed -n 1p
    allow_rc: [0, 1]
    expect: ["!empty", "> 0", "<= 900"]
    rationale: An idle shell at an unattended terminal can be used by anyone who walks by.
    remediation: Set and export TMOUT=900 in a file below /etc/profile.d and mark it readonly.

  - id: HRD-ACC-UMASK
    name: The default umask is 027 or stricter
    tags: [hardening, accounts]
    severity: low
    run: cat /etc/login.defs 2>/dev/null | awk '$1 == "UMASK" {print $2}'
    allow_rc: [0, 1]
    as: string
    expect: "in ['027', '077', '0027', '0077']"
    rationale: With a looser umask new files are readable by all other users by default.
    remediation: Set UMASK 027 in /etc/login.defs.

  # ===== 11. File permissions ===================================================
  - id: "HRD-PERM-{{ item.path | replace('/', '_') }}"
    name: "{{ item.path }} is owned by root and not too permissive"
    tags: [hardening, permissions]
    severity: high
    loop: "{{ file_permissions }}"
    only_if: test -e {{ item.path }}
    run: find -H {{ item.path }} -maxdepth 0 \( -perm /{{ item.forbidden }} -o ! -user root \)
    expect: empty
    rationale: "Wrong ownership or mode on {{ item.path }} lets unprivileged users change system configuration or read data meant for root only."
    remediation: "chown root {{ item.path }} && chmod go-w,o-rwx {{ item.path }}"

  - id: HRD-PERM-WORLD-WRITABLE
    name: No world-writable files
    tags: [hardening, permissions]
    severity: high
    timeout: 10m
    run: find / -xdev -type f -perm -0002 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Any user can change a world-writable file, including scripts and configuration that root or services read later.
    remediation: Run `chmod o-w` on each listed file.

  - id: HRD-PERM-UNOWNED
    name: No files without an owner or group
    tags: [hardening, permissions]
    timeout: 10m
    run: find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A file without owner or group falls to whichever account is later created with that UID or GID.
    remediation: Assign the listed files to an existing owner and group with chown, or delete them.

  # ===== 12. Boot =================================================================
  - id: HRD-BOOT-CFG
    name: The bootloader configuration is only readable by root
    tags: [hardening, boot]
    severity: high
    run: |
      for f in /boot/grub2/grub.cfg /boot/grub2/user.cfg /boot/grub/grub.cfg; do
        if [ -e "$f" ]; then find "$f" \( -perm /077 -o ! -user root \); fi
      done
    expect: empty
    rationale: The boot loader configuration shows the boot parameters and the password hash, and write access lets a user change how the system boots.
    remediation: Run `chown root:root` and `chmod 600` on the listed files.

  - id: HRD-BOOT-PASSWORD
    name: The bootloader is protected by a password
    tags: [hardening, boot]
    severity: high
    when: facts.is_root
    run: cat /boot/grub2/user.cfg /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*(GRUB2_PASSWORD=|password_pbkdf2[[:space:]])" }
    rationale: Without a boot loader password anyone at the console can edit the kernel command line and boot into a root shell.
    remediation: Set a password with `grub2-setpassword` where the distribution ships it, or add a password_pbkdf2 entry created with `grub-mkpasswd-pbkdf2` to the GRUB configuration.

  - id: HRD-BOOT-RESCUE
    name: Rescue and emergency mode require authentication
    tags: [hardening, boot]
    severity: high
    run: |
      for unit in rescue emergency; do
        systemctl cat "$unit.service" 2>/dev/null | grep -E '^ExecStart=.*(sulogin|systemd-sulogin-shell)' >/dev/null || echo "$unit"
      done
    expect: empty
    rationale: Without sulogin rescue and emergency mode give a root shell to anyone at the console.
    remediation: Remove the drop-ins that replace ExecStart of the listed units so that they start sulogin again.

  # ===== 13. Maintenance ============================================================
  - id: HRD-MNT-AIDE
    name: A file integrity checker is installed and scheduled
    tags: [hardening, maintenance, integrity]
    run: |
      command -v aide >/dev/null || { echo "aide is not installed"; exit 0; }
      if systemctl is-enabled --quiet aidecheck.timer 2>/dev/null || systemctl is-enabled --quiet dailyaidecheck.timer 2>/dev/null ||
         cat /etc/crontab /etc/cron.d/* /etc/cron.daily/* /var/spool/cron/root 2>/dev/null | grep aide >/dev/null; then
        echo scheduled
      else
        echo "aide is not scheduled"
      fi
    expect: "== scheduled"
    rationale: Without regular integrity checks modified system files stay unnoticed.
    remediation: Install AIDE, create the database with `aide --init` and schedule `aide --check` with cron or a systemd timer.

  - id: HRD-MNT-GPGCHECK
    name: Package signatures are checked for every repository
    tags: [hardening, maintenance, packages]
    severity: high
    run:
      rhel: cat /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/*.repo 2>/dev/null
      suse: cat /etc/zypp/zypp.conf /etc/zypp/repos.d/*.repo 2>/dev/null
      debian: cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*(gpgcheck[[:space:]]*=[[:space:]]*(0|no|off|false)|.*trusted=yes|Trusted:[[:space:]]*yes)" }
    rationale: With signature checks switched off a manipulated repository or mirror can deliver modified packages that are installed as root.
    remediation: Set gpgcheck=1 in the dnf, yum or zypper configuration, or remove trusted=yes from the APT sources.

  - id: HRD-MNT-UPDATES
    name: No security updates are pending
    tags: [hardening, maintenance, updates]
    severity: high
    timeout: 5m
    run:
      rhel: dnf -q updateinfo list --security --available 2>/dev/null
      suse: zypper --non-interactive --quiet list-patches --category security 2>/dev/null | grep -E '^[^|]+\|' | grep -v '^Repository'
      debian: apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -E '^Inst .*[Ss]ecurity'
    allow_rc: [0, 1]
    expect: { lines: "== 0" }
    rationale: Every pending security update is a published vulnerability that is still open on this system.
    remediation: Install the listed updates with `dnf upgrade --security`, `zypper patch --category security` or `apt-get upgrade`.

  # ===== 14. Additional rules (topics from OpenSCAP and Wazuh) ===================
  # --- auditing ---------------------------------------------------------------------
  - id: HRD-AUD-PRIVILEGED
    name: Every SUID/SGID program is covered by an audit rule
    tags: [hardening, audit]
    when: facts.is_root
    only_if: command -v auditctl
    timeout: 10m
    # Prints every privileged program without a matching "-F path=" rule.
    run: |
      rules=$(auditctl -l 2>/dev/null)
      find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort |
        while read -r f; do
          case "$rules" in *"path=$f "*|*"path=$f") ;; *) echo "$f" ;; esac
        done
    allow_rc: [0, 1]
    expect: empty
    rationale: SUID and SGID programs run with elevated rights, and without an audit rule their use cannot be traced.
    remediation: Generate rules with e.g. `find / -xdev -perm -4000 -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=unset -k privileged"}'`.

  - id: "HRD-AUD-RULE-{{ item.id }}"
    name: "Audit rules cover {{ item.name }}"
    tags: [hardening, audit]
    when: facts.is_root
    only_if: command -v auditctl
    loop: "{{ audit_rules_extra }}"
    run: auditctl -l
    expect: "~ {{ item.pattern }}"
    rationale: "Without an audit rule for {{ item.name }} these events leave no trace in the audit log."
    remediation: "Add a rule for {{ item.name }} to a file in /etc/audit/rules.d and load it with `augenrules --load`."

  - id: "HRD-AUD-KEEP-{{ item.key }}"
    name: "auditd.conf: {{ item.key }} {{ item.value }}"
    tags: [hardening, audit]
    severity: low
    loop: "{{ auditd_retention }}"
    only_if: test -f /etc/audit/auditd.conf
    run: { use: conf_value, args: { files: /etc/audit/auditd.conf, key: "{{ item.key }}" } }
    expect: ["!empty", "{{ item.value }}"]
    rationale: "The setting {{ item.key }} controls how auditd writes, keeps and protects its log, and another value risks lost or exposed audit records."
    remediation: "Set {{ item.key }} in /etc/audit/auditd.conf to a value that meets the expectation and restart auditd."

  - id: HRD-AUD-LOG-PERMS
    name: Audit logs are only accessible by root
    tags: [hardening, audit, permissions]
    severity: high
    only_if: test -d /var/log/audit
    run: find /var/log/audit \( -type d -perm /027 -o -type f -perm /137 -o ! -user root \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Audit logs show who did what on the system, and anyone who can write them can erase their own traces.
    remediation: Run `chown -R root /var/log/audit`, `chmod 750 /var/log/audit` and `chmod 640` on the log files.

  - id: HRD-AUD-CONF-PERMS
    name: Audit configuration is only writable by root
    tags: [hardening, audit, permissions]
    only_if: test -d /etc/audit
    run: find /etc/audit -type f \( -perm /137 -o ! -user root \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Whoever can change the audit configuration can switch off the recording of their own actions.
    remediation: Run `chown root` and `chmod 640` on the listed files.

  - id: "HRD-AUD-TOOL-{{ item }}"
    name: "Audit tool {{ item }} is owned by root and not writable by others"
    tags: [hardening, audit, permissions]
    severity: low
    loop: "{{ audit_tools }}"
    only_if: command -v {{ item }}
    run: find "$(command -v {{ item }})" \( -perm /022 -o ! -user root \)
    expect: empty
    rationale: "A replaced or modified {{ item }} can hide events or falsify what the audit system reports."
    remediation: "Run `chown root` and `chmod go-w` on the {{ item }} binary."

  # --- kernel ---------------------------------------------------------------------
  - id: "HRD-KCFG-{{ item.key }}"
    name: "Kernel built with {{ item.key }}={{ item.value }}"
    tags: [hardening, kernel, kernel-config]
    severity: low
    loop: "{{ kernel_config }}"
    only_if: test -r /boot/config-$(uname -r)
    # Options that are not set appear as "# CONFIG_X is not set".
    run: |
      v=$(grep -E '^(# )?{{ item.key }}[= ]' /boot/config-$(uname -r) | sed -n 1p)
      case "$v" in
        "{{ item.key }}="*) echo "${v#*=}" ;;
        *"is not set") echo n ;;
        *) echo missing ;;
      esac
    expect: "{{ 'in [n, missing]' if item.value == 'n' else '== ' ~ item.value }}"
    rationale: "The build option {{ item.key }} controls a kernel self-protection feature or a risky legacy interface, and a kernel built otherwise is easier to exploit."
    remediation: "Use a distribution kernel built with {{ item.key }}={{ item.value }}, or rebuild the kernel with that setting."

  - id: HRD-KRN-CPU-VULNERABILITIES
    name: The kernel mitigates all known CPU vulnerabilities
    tags: [hardening, kernel]
    severity: high
    only_if: test -d /sys/devices/system/cpu/vulnerabilities
    run: grep -H . /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null
    allow_rc: [0, 1, 2]
    expect: { none: "~ :Vulnerable" }
    rationale: An unmitigated CPU vulnerability such as Spectre or Meltdown lets a process read memory of the kernel or of other processes.
    remediation: Install current kernel and microcode updates and remove options such as mitigations=off from the kernel command line.

  - id: HRD-KRN-NX
    name: The CPU's no-execute (NX) protection is active
    tags: [hardening, kernel]
    when: facts.arch == "amd64"
    run: grep -m1 -ow nx /proc/cpuinfo
    allow_rc: [0, 1]
    expect: "== nx"
    rationale: Without NX an attacker can execute data injected into the stack or heap as code.
    remediation: Enable the NX/XD feature in the firmware setup or in the CPU settings of the virtual machine.

  - id: "HRD-BOOTPARAM-{{ item.option | replace('=', '-') }}"
    name: "Kernel command line contains {{ item.option }}"
    tags: [hardening, kernel, boot]
    severity: low
    when: item.arch == "any" or item.arch == facts.arch
    loop: "{{ boot_parameters }}"
    run: cat /proc/cmdline
    expect: "~ (^| ){{ item.option }}( |$)"
    rationale: "Without {{ item.option }} the kernel leaves out a hardening measure that makes exploits of kernel memory harder."
    remediation: "Add {{ item.option }} to the kernel command line in the boot loader configuration and reboot."

  - id: "HRD-KRN-STRICT-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }} (strict, may affect kdump or containers)"
    tags: [hardening, kernel, sysctl, strict]
    severity: low
    loop: "{{ sysctl_kernel_strict }}"
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
    rationale: "With another value of {{ item.key }} root can replace the running kernel through kexec, or unprivileged users reach kernel code through user namespaces."
    remediation: "Set {{ item.key }} in /etc/sysctl.d/60-hardening.conf and run sysctl --system."

  # --- PAM ------------------------------------------------------------------------
  - id: HRD-PAM-NULLOK
    name: PAM does not accept empty passwords (no nullok)
    tags: [hardening, authentication, pam]
    severity: high
    run: cat /etc/pam.d/* 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ ^[^#]*pam_unix\\.so.*[[:space:]]nullok" }
    rationale: With nullok pam_unix lets accounts with an empty password log in.
    remediation: Remove nullok from the pam_unix lines in /etc/pam.d, on systems with authselect through `authselect enable-feature without-nullok`.

  - id: HRD-PAM-FAILLOCK-ROOT
    name: Failed logins also lock the root account
    tags: [hardening, authentication, pam]
    severity: low
    run: cat /etc/security/faillock.conf 2>/dev/null
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*even_deny_root" }
    rationale: Without even_deny_root no lockout ever slows down password guessing against root.
    remediation: Add even_deny_root to /etc/security/faillock.conf.

  - id: HRD-PAM-FAIL-INTERVAL
    name: Failed logins are counted over at least 15 minutes
    tags: [hardening, authentication, pam]
    severity: low
    run: { use: conf_value, args: { files: /etc/security/faillock.conf, key: fail_interval } }
    expect: ["!empty", ">= 900"]
    rationale: With a short interval an attacker who paces the attempts never reaches the lockout threshold.
    remediation: Set fail_interval = 900 in /etc/security/faillock.conf.

  - id: HRD-PWQ-ROOT
    name: Password quality rules apply to root as well
    tags: [hardening, authentication, passwords]
    severity: low
    run: cat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*enforce_for_root" }
    rationale: Without enforce_for_root the password rules are only advisory when root sets a password, including its own.
    remediation: echo 'enforce_for_root' >> /etc/security/pwquality.conf

  - id: HRD-PWQ-RETRY
    name: Password changes allow at most 3 retries
    tags: [hardening, authentication, passwords]
    severity: low
    run: { use: conf_value, args: { files: "/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf", key: retry } }
    expect: ["!empty", "<= 3"]
    rationale: Many retries let a user keep trying variants of a weak password until one passes the quality check.
    remediation: Set retry = 3 in /etc/security/pwquality.conf.

  - id: HRD-PAM-HASH-ROUNDS
    name: pam_unix hashes passwords with at least 5000 rounds
    tags: [hardening, authentication, passwords]
    severity: low
    run: |
      cat /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null |
        grep -E '^[[:space:]]*password[[:space:]].*pam_unix\.so' | grep -oE 'rounds=[0-9]+' | cut -d= -f2 | sort -n | sed -n 1p
    allow_rc: [0, 1]
    expect: ["!empty", ">= 5000"]
    rationale: Few hashing rounds make every guess cheap for an attacker who cracks stolen password hashes.
    remediation: Add rounds=5000 or a higher value to the pam_unix line of the password stack.

  # --- accounts and sessions --------------------------------------------------------
  - id: HRD-ACC-SYSTEM-SHELL
    name: System accounts have no login shell
    tags: [hardening, accounts]
    run: |
      awk -F: -v min={{ uid_min }} '$3 < min && $1 !~ /^(root|sync|shutdown|halt)$/ && $7 !~ /(nologin|false)$/ {print $1 " " $7}' /etc/passwd
    expect: empty
    rationale: A system account with a login shell can be used for interactive logins that its service never needs.
    remediation: Set the shell of each listed account to nologin with `usermod -s`.

  - id: HRD-ACC-HOME-MODE
    name: Home directories are mode 750 or stricter
    tags: [hardening, accounts, permissions]
    run: |
      awk -F: -v min={{ uid_min }} '$3 >= min && $3 != 65534 {print $6}' /etc/passwd |
        while read -r home; do
          if [ -d "$home" ]; then find "$home" -maxdepth 0 -perm /027; fi
        done
    expect: empty
    rationale: A home directory open to others exposes private files, keys and the shell history to other users.
    remediation: Run `chmod 750` on each listed home directory.

  - id: HRD-ACC-SHELL-UMASK
    name: Every umask set in shell start files is 027 or stricter
    tags: [hardening, accounts]
    severity: low
    run: |
      cat /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc /etc/csh.cshrc 2>/dev/null |
        grep -oE '^[[:space:]]*umask[[:space:]]+[0-7]+' | awk '{print $2}'
    allow_rc: [0, 1]
    as: string
    expect: ["!empty", { each: "in ['027', '077', '0027', '0077']" }]
    rationale: A looser umask in a shell start file overrides the system default and makes new files readable by all users.
    remediation: Set umask 027 in /etc/profile and in every other shell start file that sets a umask.

  - id: HRD-ACC-BANNER-OSINFO
    name: Login banners do not reveal the operating system
    tags: [hardening, accounts, banners]
    severity: low
    run: cat /etc/issue /etc/issue.net /etc/motd 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ (\\\\[mrsv]|(?i)(ubuntu|debian|red hat|rocky|alma|suse|centos|kernel))" }
    rationale: A banner with the distribution name or kernel version tells an attacker before login which exploits to try.
    remediation: Remove the operating system name and the escape sequences \m, \r, \s and \v from /etc/issue, /etc/issue.net and /etc/motd.

  - id: HRD-ACC-BANNER-PRESENT
    name: A login banner is configured
    tags: [hardening, accounts, banners]
    severity: low
    run: cat /etc/issue.net /etc/issue 2>/dev/null
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: Without a banner users are not told that the system is restricted to authorized use, which can weaken the position after misuse.
    remediation: Write the login notice of your organization to /etc/issue and /etc/issue.net.

  # --- sudo -------------------------------------------------------------------------
  - id: HRD-SUDO-INCLUDES
    name: sudo only includes the standard drop-in directory
    tags: [hardening, access, sudo]
    when: facts.is_root
    run: cat /etc/sudoers 2>/dev/null | grep -E '^[#@]include'
    allow_rc: [0, 1]
    expect: { each: "~ ^[#@]includedir[[:space:]]+/etc/sudoers\\.d$" }
    rationale: An include of another file or directory lets sudo rules come from a place that is not reviewed and protected like /etc/sudoers.d.
    remediation: Remove all include lines except `@includedir /etc/sudoers.d` from /etc/sudoers with `visudo`.

  - id: HRD-SUDO-REAUTH
    name: sudo does not ask for the target user's or root's password
    tags: [hardening, access, sudo]
    severity: low
    when: facts.is_root
    run: cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ ^[[:space:]]*Defaults.*[[:space:],](targetpw|rootpw|runaspw)([[:space:],]|$)" }
    rationale: With targetpw, rootpw or runaspw users have to know the password of root or of the target account, which spreads that password and removes personal accountability.
    remediation: Remove targetpw, rootpw and runaspw from the Defaults lines with `visudo`.

  - id: HRD-SUDO-VISIBLEPW
    name: sudo never echoes passwords
    tags: [hardening, access, sudo]
    severity: low
    when: facts.is_root
    run: cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ ^[[:space:]]*Defaults.*[[:space:],]visiblepw" }
    rationale: With visiblepw sudo reads the password even when it cannot turn off echo, so the password appears on the screen or in session logs.
    remediation: Remove visiblepw from the Defaults lines with `visudo`.

  # --- file permissions -------------------------------------------------------------
  - id: HRD-PERM-BINARIES
    name: System programs are owned by root and not writable by others
    tags: [hardening, permissions]
    severity: high
    timeout: 5m
    run: |
      find /bin/ /sbin/ /usr/bin/ /usr/sbin/ /usr/local/bin/ /usr/local/sbin/ /usr/libexec/ \
        -xdev \( -type f -o -type d \) \( -perm /022 -o ! -user root \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Whoever can write a system program or its directory can replace it with code that root or other users then run.
    remediation: Run `chown root` and `chmod go-w` on the listed files and directories.

  - id: HRD-PERM-LIBRARIES
    name: System libraries are owned by root and not writable by others
    tags: [hardening, permissions]
    severity: high
    timeout: 5m
    run: |
      find /lib/ /lib64/ /usr/lib/ /usr/lib64/ -xdev \( -type f -o -type d \) \( -perm /022 -o ! -user root \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A modified library runs inside every program that loads it, including those started by root.
    remediation: Run `chown root` and `chmod go-w` on the listed files and directories.

  - id: HRD-PERM-SSH-PUBKEYS
    name: Public SSH host keys are not writable by others
    tags: [hardening, permissions, ssh]
    severity: low
    run: find /etc/ssh -name 'ssh_host_*_key.pub' \( -perm /133 -o ! -user root \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A public host key file that others can write can be swapped, so that administrators distribute or verify the wrong key.
    remediation: Run `chown root` and `chmod 644` on the listed files.

  - id: HRD-PERM-VAR-LOG
    name: /var/log is owned by root and not writable by others
    tags: [hardening, permissions, logging]
    run: find /var/log -maxdepth 0 \( -perm /022 -o ! -user root \)
    expect: empty
    rationale: Whoever can write to /var/log can delete, replace or plant log files.
    remediation: chown root /var/log && chmod go-w /var/log

  - id: HRD-PERM-KEYTABS
    name: Kerberos keytabs are only readable by their owner
    tags: [hardening, permissions, kerberos]
    severity: high
    run: find /etc /var/kerberos -name '*.keytab' -perm /077 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A keytab holds the long-term Kerberos keys of a host or service, and anyone who reads it can act as that principal.
    remediation: Run `chmod 600` on each listed keytab.

  # --- SELinux ----------------------------------------------------------------------
  - id: "HRD-SEBOOL-{{ item.key }}"
    name: "SELinux boolean {{ item.key }} is {{ item.value }}"
    tags: [hardening, mac, selinux]
    severity: low
    loop: "{{ selinux_booleans }}"
    only_if: command -v getsebool && selinuxenabled
    run: getsebool {{ item.key }} 2>/dev/null | awk '{print $3}'
    allow_rc: [0, 1]
    # Booleans that do not exist on this policy version are fine.
    expect: { any: ["== {{ item.value }}", empty] }
    rationale: "The SELinux boolean {{ item.key }} switches a part of the policy, and with another value than {{ item.value }} confined programs or users are held less tightly."
    remediation: "setsebool -P {{ item.key }} {{ item.value }}"

  # --- logging ----------------------------------------------------------------------
  - id: HRD-LOG-RSYSLOG-NO-REMOTE-INPUT
    name: rsyslog does not accept remote messages
    tags: [hardening, logging]
    only_if: test -f /etc/rsyslog.conf
    run: cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ ^[[:space:]]*(\\$ModLoad[[:space:]]+im(tcp|udp)|module\\(load=\"im(tcp|udp)\")" }
    rationale: A syslog input open to the network lets any host fill the disk or plant false log entries.
    remediation: Remove the imtcp and imudp module lines from /etc/rsyslog.conf and /etc/rsyslog.d and restart rsyslog. Only a dedicated log server needs them.

  - id: HRD-LOG-RSYSLOG-FILEMODE
    name: rsyslog creates log files with mode 0640 or stricter
    tags: [hardening, logging, permissions]
    severity: low
    only_if: test -f /etc/rsyslog.conf
    run: |
      cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -oE '^[[:space:]]*\$FileCreateMode[[:space:]]+[0-7]+' | awk '{print $2}'
    allow_rc: [0, 1]
    as: string
    expect: ["!empty", { each: "in ['0640', '0600', '0400', '0440']" }]
    rationale: Without a restrictive $FileCreateMode rsyslog creates log files that every user can read.
    remediation: Set `$FileCreateMode 0640` in /etc/rsyslog.conf and restart rsyslog.

  - id: HRD-LOG-JOURNAL-FORWARD
    name: journald forwards to rsyslog when rsyslog is used
    tags: [hardening, logging]
    severity: low
    only_if: systemctl is-active --quiet rsyslog
    run: { use: conf_value, args: { files: "/etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf", key: ForwardToSyslog } }
    expect: "== yes"
    rationale: Without forwarding messages that reach only the journal are missing from the rsyslog files and from a log server that rsyslog feeds.
    remediation: Set ForwardToSyslog=yes in /etc/systemd/journald.conf and restart systemd-journald.

  # --- services -----------------------------------------------------------------------
  - id: HRD-SVC-POSTFIX-LOCAL
    name: Postfix only listens on loopback
    tags: [hardening, services, mail]
    only_if: command -v postconf
    run: postconf -h inet_interfaces
    expect: "in [loopback-only, localhost, 127.0.0.1, '127.0.0.1, [::1]']"
    rationale: A Postfix that listens on the network accepts connections from any host, although the server only needs to deliver local mail.
    remediation: postconf -e inet_interfaces=loopback-only && systemctl restart postfix

  - id: HRD-SVC-NFS-EXPORTS
    name: NFS exports neither disable root squashing nor allow insecure ports
    tags: [hardening, services, nfs]
    severity: high
    only_if: test -s /etc/exports || test -d /etc/exports.d
    run: cat /etc/exports /etc/exports.d/*.exports 2>/dev/null | grep -v '^[[:space:]]*#'
    allow_rc: [0, 1]
    expect: { none: "~ (no_root_squash|[(,]insecure[),])" }
    rationale: no_root_squash gives root on any client root rights on the exported files, and insecure accepts requests from unprivileged client ports where any user can forge them.
    remediation: Remove no_root_squash and insecure from the export options and run `exportfs -ra`.

  - id: HRD-SVC-SSSD-TLS
    name: SSSD verifies LDAP server certificates
    tags: [hardening, services, sssd]
    severity: high
    only_if: test -f /etc/sssd/sssd.conf
    run: cat /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*ldap_tls_reqcert[[:space:]]*=[[:space:]]*(never|allow)" }
    rationale: Without certificate verification an attacker in the network path can pose as the LDAP server and read or forge account data and passwords.
    remediation: Set ldap_tls_reqcert = demand in /etc/sssd/sssd.conf and restart sssd.

  - id: HRD-SVC-CHRONY-USER
    name: chronyd runs as an unprivileged user
    tags: [hardening, services, time]
    severity: low
    only_if: pgrep -x chronyd >/dev/null
    run: ps -o user= -p "$(pgrep -x chronyd | sed -n 1p)"
    expect: "in [chrony, _chrony, ntp]"
    rationale: chronyd processes packets from the network, and running as root turns a flaw in it into a full system compromise.
    remediation: Run chronyd under its unprivileged account, set with the user directive in chrony.conf or the -u option.

  - id: HRD-SVC-CHRONY-CMDPORT
    name: chronyd does not accept commands from the network
    tags: [hardening, services, time]
    severity: low
    only_if: command -v ss && pgrep -x chronyd >/dev/null
    run: ss -Hlnu 'sport = :323' | awk '{print $4}'
    expect: { each: "~ ^(127\\.0\\.0\\.1|\\[::1\\]):323$" }
    rationale: A command port open to the network lets other hosts query the time service and, where cmdallow permits it, reconfigure it.
    remediation: Remove the bindcmdaddress lines that open the port from chrony.conf, or set `cmdport 0`, and restart chronyd.

  - id: HRD-SVC-VSFTPD-ANON
    name: vsftpd does not allow anonymous logins
    tags: [hardening, services, ftp]
    severity: high
    only_if: test -f /etc/vsftpd.conf || test -f /etc/vsftpd/vsftpd.conf
    run: cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*anonymous_enable=yes" }
    rationale: Anonymous FTP lets anyone on the network use the FTP area without an account.
    remediation: Set anonymous_enable=NO in the vsftpd configuration and restart vsftpd.

  - id: HRD-SVC-USBGUARD
    name: USBGuard controls USB devices
    tags: [hardening, services, usb]
    severity: low
    only_if: command -v systemctl
    run: systemctl is-active usbguard 2>/dev/null
    allow_rc: [0, 1, 3, 4]
    expect: "== active"
    rationale: Without USBGuard the server accepts any USB device that is plugged in, including storage and devices that pose as keyboards.
    remediation: Install usbguard, create a policy with `usbguard generate-policy > /etc/usbguard/rules.conf` and run `systemctl enable --now usbguard`.

  # --- software ---------------------------------------------------------------------
  - id: "HRD-SW-UNWANTED-{{ item }}"
    name: "{{ item }} is not installed"
    tags: [hardening, packages]
    severity: low
    loop: "{{ unwanted_packages }}"
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: false
    rationale: "The package {{ item }} is not needed on a server and adds attack surface or interferes with integrity checks."
    remediation: "Remove the package {{ item }} with the package manager."

  - id: HRD-SW-REQUIRED
    name: Packages a hardened server needs are installed
    tags: [hardening, packages]
    run: |
      for p in {{ required_packages | join(' ') }}; do
        if rpm -q --quiet "$p" 2>/dev/null || dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep 'install ok installed' >/dev/null || apk info -e "$p" >/dev/null 2>&1; then echo "$p"; fi
      done
    allow_rc: [0, 1]
    # audit (RPM) and auditd (Debian) are the same software.
    expect:
      all:
        - { some: "== sudo" }
        - { some: "in [audit, auditd]" }
        - { some: "== chrony" }
        - { some: "== aide" }
    rationale: sudo, auditd, chrony and AIDE provide attributable administration, audit records, correct time and integrity checks that the rest of the baseline builds on.
    remediation: Install the missing packages among sudo, audit (auditd on Debian), chrony and aide.

  - id: HRD-SW-LOCALPKG-GPG
    name: Locally installed packages are signature-checked
    tags: [hardening, maintenance, packages]
    severity: low
    only_if: test -f /etc/dnf/dnf.conf
    run: { use: conf_value, args: { files: /etc/dnf/dnf.conf, key: localpkg_gpgcheck } }
    expect: "~ (?i)^(1|true|yes)$"
    rationale: Without localpkg_gpgcheck a package file installed from disk is not signature-checked, so a manipulated download installs as root.
    remediation: Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf.

  - id: HRD-SW-AIDE-ACLS
    name: AIDE also checks ACLs and extended attributes
    tags: [hardening, maintenance, integrity]
    severity: low
    only_if: test -f /etc/aide.conf || test -f /etc/aide/aide.conf
    run: cat /etc/aide.conf /etc/aide/aide.conf 2>/dev/null | grep -vE '^[[:space:]]*#'
    allow_rc: [0, 1]
    expect: [{ some: "~ \\bacl\\b" }, { some: "~ \\bxattrs\\b" }]
    rationale: Without the acl and xattrs attributes AIDE misses changes to ACLs, SELinux labels and file capabilities.
    remediation: Add acl and xattrs to the attribute groups used in the AIDE configuration and reinitialize the database.

  - id: HRD-SW-FIPS
    name: The kernel runs in FIPS mode (informational)
    tags: [hardening, crypto]
    severity: info
    run: cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0
    expect: "== 1"
    rationale: FIPS mode limits the kernel and the crypto libraries to validated algorithms, which some regulations require.
    remediation: Where FIPS is required, enable it with the method of the distribution and reboot. Otherwise no action is needed.
```

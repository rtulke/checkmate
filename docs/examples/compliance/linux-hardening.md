# Linux hardening baseline

A broad server hardening baseline for current Linux distributions, structured like the public hardening guides of the SCAP Security Guide (OpenSCAP) and the CIS benchmarks: file systems, services, network parameters, auditing, logging, access control, accounts, file permissions, boot and maintenance. Check IDs and wording are our own; the thresholds are common defaults and can be tuned in `vars`. Select sections with tags, e.g. `--tags network` or `--tags audit`.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/compliance/linux-hardening.yml`](https://github.com/rtulke/checkmate/blob/main/examples/compliance/linux-hardening.yml)
- :material-format-list-checks: **Checks**  
  227 from 67 definitions, 14 with loops
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

snippets:
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg-query -W -f='${Status}' {{ arg }} 2>/dev/null | grep -q 'install ok installed'
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
    remediation: "printf 'install {{ item }} /bin/false\\nblacklist {{ item }}\\n' > /etc/modprobe.d/{{ item }}.conf"

  - id: "HRD-FS-OPT-{{ item.path | replace('/', '_') }}-{{ item.option }}"
    name: "{{ item.path }} is mounted with {{ item.option }}"
    tags: [hardening, filesystems]
    loop: "{{ mount_options }}"
    only_if: findmnt -n {{ item.path }} >/dev/null
    run: findmnt -n -o OPTIONS {{ item.path }}
    expect: "~ (^|,){{ item.option }}(,|$)"

  - id: HRD-FS-STICKY
    name: All world-writable directories have the sticky bit
    tags: [hardening, filesystems, permissions]
    severity: high
    timeout: 10m
    run: find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: HRD-FS-AUTOMOUNT
    name: Automounting of removable media is disabled
    tags: [hardening, filesystems]
    severity: low
    run: systemctl is-enabled autofs 2>/dev/null
    allow_rc: [0, 1, 4]
    expect: "!in [enabled, enabled-runtime]"

  # ===== 2. Services and software =================================================
  - id: "HRD-SVC-{{ item }}"
    name: "Service {{ item }} is neither running nor enabled"
    tags: [hardening, services]
    loop: "{{ forbidden_services }}"
    run: systemctl is-active --quiet {{ item }} || systemctl is-enabled --quiet {{ item }}
    expect: false
    remediation: "systemctl disable --now {{ item }}"

  - id: "HRD-PKG-RPM-{{ item }}"
    name: "Legacy package {{ item }} is not installed"
    tags: [hardening, services, packages]
    loop: "{{ forbidden_rpm_packages }}"
    only_if: command -v rpm && ! command -v dpkg
    run: rpm -q --quiet {{ item }}
    expect: false

  - id: "HRD-PKG-DEB-{{ item }}"
    name: "Legacy package {{ item }} is not installed"
    tags: [hardening, services, packages]
    loop: "{{ forbidden_deb_packages }}"
    only_if: command -v dpkg-query
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: false

  - id: HRD-SVC-MTA-LOCAL
    name: The mail transfer agent only listens on loopback
    tags: [hardening, services, network]
    only_if: command -v ss
    run: ss -Hlnt 'sport = :25' | awk '{print $4}'
    expect: { each: "~ ^(127\\.0\\.0\\.1|\\[::1\\]):25$" }

  - id: HRD-SVC-TIME-SOURCES
    name: The time service has servers configured
    tags: [hardening, services, time]
    run: |
      cat /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony/sources.d/*.sources /etc/systemd/timesyncd.conf 2>/dev/null |
        grep -E '^[[:space:]]*(server|pool|NTP=[^[:space:]])'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  # ===== 3. Network ===============================================================
  - id: "HRD-NET-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [hardening, network, sysctl]
    loop: "{{ sysctl_ipv4 }}"
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
    remediation: "Set {{ item.key }} in /etc/sysctl.d/60-hardening.conf and run sysctl --system."

  - id: "HRD-NET6-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [hardening, network, sysctl, ipv6]
    loop: "{{ sysctl_ipv6 }}"
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"

  - id: HRD-NET-FIREWALL
    name: A host firewall is active
    tags: [hardening, network, firewall]
    severity: high
    run: |
      for unit in firewalld nftables ufw iptables; do systemctl is-active "$unit" 2>/dev/null; done
    allow_rc: [0, 1, 3, 4]
    expect: { some: "== active" }

  - id: HRD-NET-WIRELESS
    name: Wireless interfaces are disabled
    tags: [hardening, network]
    severity: low
    run: find /sys/class/net/*/ -maxdepth 1 -name wireless 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  # ===== 4. Kernel and process hardening ============================================
  - id: "HRD-KRN-{{ item.key }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [hardening, kernel, sysctl]
    loop: "{{ sysctl_kernel }}"
    # Parameters the kernel does not have (e.g. without BPF JIT) are skipped.
    only_if: test -e /proc/sys/{{ item.key | replace('.', '/') }}
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"

  - id: HRD-KRN-CORE-LIMITS
    name: Core dumps are restricted by limits
    tags: [hardening, kernel]
    severity: low
    run: |
      cat /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null |
        grep -E '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  - id: HRD-KRN-COREDUMP-STORAGE
    name: systemd-coredump does not store dumps
    tags: [hardening, kernel]
    severity: low
    only_if: test -f /etc/systemd/coredump.conf
    run: { use: conf_value, args: { files: "/etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf", key: Storage } }
    expect: "== none"

  - id: HRD-KRN-AUDIT-BOOT
    name: Auditing starts with the kernel (audit=1)
    tags: [hardening, kernel, audit]
    run: cat /proc/cmdline
    expect: "~ (^| )audit=1( |$)"

  - id: HRD-KRN-AUDIT-BACKLOG
    name: The kernel audit backlog holds at least 8192 events
    tags: [hardening, kernel, audit]
    severity: low
    run: cat /proc/cmdline | tr ' ' '\n' | awk -F= '$1 == "audit_backlog_limit" {print $2}'
    expect: ["!empty", ">= 8192"]

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

  - id: HRD-MAC-CMDLINE
    name: The MAC system is not disabled at boot
    tags: [hardening, mac, boot]
    severity: high
    run: cat /proc/cmdline
    expect: "!~ (selinux=0|enforcing=0|apparmor=0)"

  # ===== 6. Auditing ==============================================================
  - id: HRD-AUD-SERVICE
    name: auditd is running and enabled
    tags: [hardening, audit]
    severity: high
    run: echo "$(systemctl is-active auditd 2>/dev/null) $(systemctl is-enabled auditd 2>/dev/null)"
    expect: "== active enabled"

  - id: "HRD-AUD-RULE-{{ item.id }}"
    name: "Audit rules cover {{ item.name }}"
    tags: [hardening, audit]
    when: facts.is_root
    loop: "{{ audit_rules }}"
    run: auditctl -l
    expect: "~ {{ item.pattern }}"

  - id: HRD-AUD-IMMUTABLE
    name: The audit configuration is immutable until reboot
    tags: [hardening, audit]
    severity: low
    when: facts.is_root
    run: auditctl -s | awk '$1 == "enabled" {print $2}'
    expect: "== 2"
    remediation: Add "-e 2" as the last line of the audit rules.

  - id: "HRD-AUD-CONF-{{ item.key }}"
    name: "auditd.conf: {{ item.key }} {{ item.value }}"
    tags: [hardening, audit]
    # auditd accepts the values in any case (ROTATE, rotate).
    loop:
      max_log_file_action: "~ (?i)^(keep_logs|rotate)$"
      space_left_action: "~ (?i)^(email|exec|single|halt)$"
      admin_space_left_action: "~ (?i)^(single|halt)$"
      disk_full_action: "~ (?i)^(single|halt)$"
      disk_error_action: "~ (?i)^(syslog|single|halt)$"
    run: { use: conf_value, args: { files: /etc/audit/auditd.conf, key: "{{ item.key }}" } }
    expect: "{{ item.value }}"

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

  - id: HRD-LOG-JOURNAL-COMPRESS
    name: journald compresses large entries
    tags: [hardening, logging]
    severity: low
    run: { use: conf_value, args: { files: "/etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf", key: Compress } }
    expect: "in [yes, '']"
    as: string

  - id: HRD-LOG-FILES
    name: Log files are not readable by others
    tags: [hardening, logging, permissions]
    run: find /var/log -type f -perm /o+rwx 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

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

  - id: HRD-SSH-CLIENTALIVE
    name: "sshd: idle sessions are disconnected within 15 minutes"
    tags: [hardening, access, ssh]
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "clientaliveinterval" {print $2}'
    expect: ["> 0", "<= 900"]

  - id: HRD-SUDO-PTY
    name: sudo uses a pseudo terminal
    tags: [hardening, access, sudo]
    when: facts.is_root
    run: |
      cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '^[[:space:]]*Defaults([[:space:]]+|.*[[:space:],])use_pty([[:space:],]|$)'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  - id: HRD-SUDO-LOG
    name: sudo writes a log file
    tags: [hardening, access, sudo]
    when: facts.is_root
    run: cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '^[[:space:]]*Defaults.*logfile='
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  - id: HRD-SUDO-TIMEOUT
    name: sudo authentication expires within 15 minutes
    tags: [hardening, access, sudo]
    severity: low
    when: facts.is_root
    run: |
      t=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -oE 'timestamp_timeout=-?[0-9]+' | tail -1 | cut -d= -f2)
      echo "${t:-5}"
    expect: [">= 0", "<= 15"]

  - id: HRD-SUDO-NOAUTH
    name: No sudo rule disables authentication
    tags: [hardening, access, sudo]
    severity: high
    when: facts.is_root
    run: cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    allow_rc: [0, 1]
    expect: { none: ["~ ^[^#]*(!authenticate|NOPASSWD:[[:space:]]*ALL[[:space:]]*$)"] }

  - id: HRD-SU-WHEEL
    name: su is restricted to a group (pam_wheel)
    tags: [hardening, access]
    run: cat /etc/pam.d/su 2>/dev/null
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\\.so" }

  - id: HRD-CRON-ALLOW
    name: cron and at are restricted to allowed users
    tags: [hardening, access, cron]
    severity: low
    run: |
      for f in cron at; do
        if [ -f /etc/$f.deny ] || [ ! -f /etc/$f.allow ]; then echo "$f: use /etc/$f.allow"; fi
      done
    expect: empty

  # ===== 9. Authentication: PAM and passwords ===================================
  - id: HRD-PAM-FAILLOCK
    name: Accounts lock after at most 5 failed logins
    tags: [hardening, authentication, pam]
    severity: high
    run: { use: conf_value, args: { files: /etc/security/faillock.conf, key: deny } }
    expect: ["!empty", "> 0", "<= 5"]

  - id: HRD-PAM-UNLOCK
    name: Locked accounts unlock after at least 15 minutes (or manually)
    tags: [hardening, authentication, pam]
    run: { use: conf_value, args: { files: /etc/security/faillock.conf, key: unlock_time } }
    expect: ["!empty", { any: ["== 0", ">= 900"] }]

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

  - id: HRD-PWHISTORY
    name: The last 5 passwords cannot be reused
    tags: [hardening, authentication, passwords]
    run: |
      v=$(cat /etc/security/pwhistory.conf 2>/dev/null | awk -F= '{k = $1; gsub(/[[:space:]]/, "", k)} k == "remember" {gsub(/[[:space:]]/, "", $2); print $2}' | tail -1)
      [ -n "$v" ] || v=$(grep -rhoE 'pam_(pwhistory|unix)\.so.*remember=[0-9]+' /etc/pam.d 2>/dev/null | grep -oE 'remember=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
      echo "$v"
    expect: ["!empty", ">= 5"]

  - id: HRD-PW-HASH
    name: New passwords are hashed with SHA-512 or yescrypt
    tags: [hardening, authentication, passwords]
    severity: high
    run: cat /etc/login.defs 2>/dev/null | awk '$1 == "ENCRYPT_METHOD" {print $2}'
    allow_rc: [0, 1]
    expect: "in [SHA512, YESCRYPT]"

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

  - id: HRD-ACC-INACTIVE
    name: Accounts are disabled 45 days after password expiry
    tags: [hardening, accounts, passwords]
    severity: low
    run: useradd -D | awk -F= '$1 == "INACTIVE" {print $2}'
    expect: ["!= -1", ">= 0", "<= 45"]

  - id: HRD-ACC-SHADOWED
    name: All accounts use shadowed passwords
    tags: [hardening, accounts]
    severity: high
    run: |
      cut -d: -f1,2 /etc/passwd
    expect: { each: "~ :x$" }

  - id: HRD-ACC-EMPTY
    name: No account has an empty password
    tags: [hardening, accounts]
    severity: critical
    when: facts.is_root
    run: |
      cut -d: -f1,2 /etc/shadow
    expect: { none: "~ :$" }

  - id: HRD-ACC-UID0
    name: root is the only account with UID 0
    tags: [hardening, accounts]
    severity: critical
    run: |
      awk -F: '$3 == 0 {print $1}' /etc/passwd
    expect: "== root"

  - id: HRD-ACC-ROOT-GID
    name: root's primary group is GID 0
    tags: [hardening, accounts]
    run: |
      awk -F: '$1 == "root" {print $4}' /etc/passwd
    expect: "== 0"

  - id: HRD-ACC-LEGACY
    name: No legacy "+" NIS entries in account files
    tags: [hardening, accounts]
    when: facts.is_root
    run: cat /etc/passwd /etc/shadow /etc/group 2>/dev/null
    expect: { none: "~ ^\\+" }

  - id: HRD-ACC-SYSTEM-LOCKED
    name: System accounts are locked
    tags: [hardening, accounts]
    when: facts.is_root
    run: |
      awk -F: -v min={{ uid_min }} 'NR == FNR {uid[$1] = $3; next}
        ($1 in uid) && uid[$1] < min && $1 != "root" && $2 !~ /^[!*]/ {print $1}' /etc/passwd /etc/shadow
    expect: empty

  - id: HRD-ACC-PW-CHANGED
    name: No password change date lies in the future
    tags: [hardening, accounts]
    severity: low
    when: facts.is_root
    run: |
      awk -F: -v today="$(( $(date +%s) / 86400 ))" '$3 != "" && $3 > today {print $1}' /etc/shadow
    expect: empty

  - id: HRD-ACC-MAXDAYS
    name: Every user password expires within 365 days
    tags: [hardening, accounts, passwords]
    when: facts.is_root
    run: |
      awk -F: '$2 ~ /^\$/ && ($5 == "" || $5 > 365) {print $1}' /etc/shadow
    expect: empty

  - id: HRD-ACC-GROUPS-EXIST
    name: Every primary group of an account exists
    tags: [hardening, accounts]
    run: |
      awk -F: 'NR == FNR {g[$3] = 1; next} !($4 in g) {print $1 " (gid " $4 ")"}' /etc/group /etc/passwd
    expect: empty

  - id: HRD-ACC-SHADOW-GROUP
    name: The shadow group has no members
    tags: [hardening, accounts]
    run: |
      awk -F: '$1 == "shadow" {print $4}' /etc/group
    expect: empty

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

  - id: HRD-ACC-DOTFILES
    name: Dot files in home directories are not writable by group or others
    tags: [hardening, accounts, permissions]
    run: |
      awk -F: -v min={{ uid_min }} '$3 >= min && $3 != 65534 {print $6}' /etc/passwd |
        while read -r home; do
          if [ -d "$home" ]; then find "$home" -maxdepth 1 -name '.*' -type f -perm /go+w; fi
        done
    expect: empty

  - id: HRD-ACC-FORWARD
    name: No .forward, .netrc or .rhosts files
    tags: [hardening, accounts]
    severity: high
    run: |
      find /root /home -maxdepth 2 \( -name .forward -o -name .netrc -o -name .rhosts -o -name .shosts \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: HRD-ACC-TMOUT
    name: Idle shells time out after at most 15 minutes
    tags: [hardening, accounts]
    severity: low
    run: |
      cat /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc 2>/dev/null |
        grep -oE '^[^#]*TMOUT=[0-9]+' | grep -oE '[0-9]+$' | sort -n | sed -n 1p
    allow_rc: [0, 1]
    expect: ["!empty", "> 0", "<= 900"]

  - id: HRD-ACC-UMASK
    name: The default umask is 027 or stricter
    tags: [hardening, accounts]
    severity: low
    run: cat /etc/login.defs 2>/dev/null | awk '$1 == "UMASK" {print $2}'
    allow_rc: [0, 1]
    as: string
    expect: "in ['027', '077', '0027', '0077']"

  # ===== 11. File permissions ===================================================
  - id: "HRD-PERM-{{ item.path | replace('/', '_') }}"
    name: "{{ item.path }} is owned by root and not too permissive"
    tags: [hardening, permissions]
    severity: high
    loop: "{{ file_permissions }}"
    only_if: test -e {{ item.path }}
    run: find {{ item.path }} -maxdepth 0 \( -perm /{{ item.forbidden }} -o ! -user root \)
    expect: empty
    remediation: "chown root {{ item.path }} && chmod go-w,o-rwx {{ item.path }}"

  - id: HRD-PERM-WORLD-WRITABLE
    name: No world-writable files
    tags: [hardening, permissions]
    severity: high
    timeout: 10m
    run: find / -xdev -type f -perm -0002 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: HRD-PERM-UNOWNED
    name: No files without an owner or group
    tags: [hardening, permissions]
    timeout: 10m
    run: find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

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

  - id: HRD-BOOT-PASSWORD
    name: The bootloader is protected by a password
    tags: [hardening, boot]
    severity: high
    when: facts.is_root
    run: cat /boot/grub2/user.cfg /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*(GRUB2_PASSWORD=|password_pbkdf2[[:space:]])" }

  - id: HRD-BOOT-RESCUE
    name: Rescue and emergency mode require authentication
    tags: [hardening, boot]
    severity: high
    run: |
      for unit in rescue emergency; do
        systemctl cat "$unit.service" 2>/dev/null | grep -qE '^ExecStart=.*(sulogin|systemd-sulogin-shell)' || echo "$unit"
      done
    expect: empty

  # ===== 13. Maintenance ============================================================
  - id: HRD-MNT-AIDE
    name: A file integrity checker is installed and scheduled
    tags: [hardening, maintenance, integrity]
    run: |
      command -v aide >/dev/null || { echo "aide is not installed"; exit 0; }
      if systemctl is-enabled --quiet aidecheck.timer 2>/dev/null || systemctl is-enabled --quiet dailyaidecheck.timer 2>/dev/null ||
         cat /etc/crontab /etc/cron.d/* /etc/cron.daily/* /var/spool/cron/root 2>/dev/null | grep -q aide; then
        echo scheduled
      else
        echo "aide is not scheduled"
      fi
    expect: "== scheduled"

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
```

# CIS Red Hat Enterprise Linux 7

Automated checks for 193 recommendations of the CIS Red Hat Enterprise Linux 7 benchmark (version 3.1.1), converted from the goss audit content of the ansible-lockdown project. Check names describe what is verified; the recommendation number is in the ID and the description. Select profiles with tags, e.g. `--tags cis-level-1+cis-server`.

**Policy:** [`cis/rhel7.yml`](https://github.com/rtulke/checkmate/blob/main/cis/rhel7.yml) · **Benchmark version:** 3.1.1

```bash
checkmate run cis/rhel7.yml --tags cis-level1-server
checkmate run cis/rhel7.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-RHEL7-1.1.1.1-cramfs` | cramfs: modprobe -n -v cramfs \| grep -E '(cramfs\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.1.2-squashfs` | squashfs: modprobe -n -v squashfs \| grep -E '(squashfs\|install)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.1.1.3-udf` | udf: modprobe -n -v udf \| grep -E '(udf\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.6-dev_shm` | /dev/shm is a separate mount with noexec, nodev, nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.18-home` | /home is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.17-home_2` | /home is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.1.2-tmp` | /tmp is a separate mount with noexec, nodev, nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.10-var` | /var is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.1.15-var_log` | /var/log is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.1.16-var_log_audit` | /var/log/audit is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.1.12-var_tmp` | /var/tmp is a separate mount with noexec, nodev, nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.11-var_tmp_2` | /var/tmp is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.1.20-cdrom_nodev` | cdrom nodev: if [ `grep -c -i cdrom /etc/fstab` = 1 ] ; then if [ `grep -c -E 'cdrom.\*nodev' /etc/fsta… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.19-cdrom_noexec` | cdrom noexec: if [ `grep -c -i cdrom /etc/fstab` = 1 ] ; then if [ `grep -c -E 'cdrom.\*noexec' /etc/fst… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.21-cdrom_nosuid` | cdrom nosuid: if [ `grep -c -i cdrom /etc/fstab` = 1 ] ; then if [ `grep -c -E 'cdrom.\*nosuid' /etc/fst… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.20-floppy_nodev` | floppy nodev: if [ `grep -c -i floppy /etc/fstab` = 1 ] ; then if [ `grep -c -E 'floppy.\*nodev' /etc/fs… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.19-floppy_noexec` | floppy noexec: if [ `grep -c -i floppy /etc/fstab` = 1 ] ; then if [ `grep -c -E 'floppy.\*noexec' /etc/f… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.21-floppy_nosuid` | floppy nosuid: if [ `grep -c -i floppy /etc/fstab` = 1 ] ; then if [ `grep -c -E 'floppy.\*nosuid' /etc/f… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.22-sticky_bit` | sticky bit: df --local -P 2> /dev/null \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.23-autofs-enabled` | Service autofs is not enabled | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.23-autofs-running` | Service autofs is not running | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.1.24-cramfs` | cramfs: modprobe -n -v usb-storage \| grep -E '(usb-storage\|install)' | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.1-gpg_keys` | gpg keys: rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary} | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.2-repos_configured` | repos configured: yum repolist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.3-gpg_check_global` | gpg check global: if [ `grep -c -E '^\\s\*gpgcheck.\*0' /etc/yum.conf` -ge 1 ]; then echo FAIL; elif [ `grep -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.3-gpg_check_repo` | gpg check repo: if [ `grep -c -E '^\\s\*gpgcheck.\*0' /etc/yum.repos.d/\*.repo` -ge 1 ]; then echo FAIL; elif… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.4-subscription` | subscription: subscription-manager list --consumed \| grep -A4 'Roles:\\s\*Red Hat Enterprise Linux Server' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.5-rhnsd-enabled` | Service rhnsd is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.2.5-rhnsd-running` | Service rhnsd is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.3.1-aide` | Package aide is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.3.2-aide_cron` | aide cron: grep -rs aide /etc/cron.\* /etc/crontab /var/spool/cron/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.4.1-boot_grub2_user.cfg-attrs` | /boot/grub2/user.cfg: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.4.2-boot_grub2_grub.cfg-attrs` | /boot/grub2/grub.cfg: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.4.3-single_user_1` | single user 1: grep /sbin/sulogin /usr/lib/systemd/system/rescue.service | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.4.3-single_user_2` | single user 2: grep /sbin/sulogin /usr/lib/systemd/system/emergency.service | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-fs.suid_dumpable` | Kernel parameter fs.suid_dumpable is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-coredump-enabled` | Service coredump is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-coredump-running` | Service coredump is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-etc_systemd_coredump.conf-attrs` | /etc/systemd/coredump.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-etc_systemd_coredump.conf-content` | /etc/systemd/coredump.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-core_dumps_limits` | core dumps limits: grep -E "\\\*.\*hard.\*core.\*0" /etc/security/limits.conf /etc/security/limits.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.1-suid_dumpable_2` | suid dumpable 2: grep "fs\\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.2-kernel_nx` | kernel nx: journalctl \| grep 'protection: active' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.3-kernel.randomize_va_space` | Kernel parameter kernel.randomize_va_space is 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.3-aslr_enabled_2` | aslr enabled 2: grep "kernel\\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/\* \| cut -d ":" -f2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.5.4-prelink` | Package prelink is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.1-libselinux` | Package libselinux is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.5-selinux_config_enforcing` | selinux config enforcing: grep -Ei "^\\s\*SELINUX=[Ee]nforcing" /etc/selinux/config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.4-selinux_config_mode` | selinux config mode: grep -Ei "^\\s\*SELINUX=(enforcing\|permissive)" /etc/selinux/config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.2-selinux_disabled_boot` | selinux disabled boot: grep "^\\s\*linux" /boot/grub2/grub.cfg \| grep -E "(selinux=0\|enforcing=0)" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.3-selinux_policy` | selinux policy: grep SELINUXTYPE= /etc/selinux/config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.5-selinux_run_enforcing` | selinux run enforcing: getenforce | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.4-selinux_running_mode` | selinux running mode: getenforce | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.3-selinux_sestatus` | selinux sestatus: sestatus \| grep 'Loaded policy' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.6-selinux_unconfined` | selinux unconfined: ps -eZ \| grep unconfined_service_t | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.8-mcstrans` | Package mcstrans is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.6.1.7-setroubleshoot` | Package setroubleshoot is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.7.2-etc_issue-attrs` | /etc/issue: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.7.2-etc_issue-content` | /etc/issue has the expected content (5 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.7.3-etc_issue.net-attrs` | /etc/issue.net: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.7.3-etc_issue.net-content` | /etc/issue.net has the expected content (5 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.7.1-etc_motd-attrs` | /etc/motd: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.7.1-etc_motd-content` | /etc/motd has the expected content (5 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-1.8.1-gdm` | Package gdm is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-1.9-security-updates` | security updates: yum check-update | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.1.1-xinetd` | Package xinetd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.2-xorgs-x11-servers` | Package xorgs-x11-servers is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.3-avahi` | Package avahi is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.4-cups` | Package cups is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.5-dhcp` | Package dhcp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.6-openldap-servers` | Package openldap-servers is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.7-bind` | Package bind is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.8-vsftpd` | Package vsftpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.9-httpd` | Package httpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.10-dovecot` | Package dovecot is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.11-samba` | Package samba is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.12-squid` | Package squid is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.13-net-snmp` | Package net-snmp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.14-ypserver` | Package ypserver is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.15-telnet-server` | Package telnet-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.16-mta_installed` | mta installed: ss -lntu \| grep -E ":25\\s" \| grep -E -v "\\s(127.0.0.1\|\\[?::1\\]?):25\\s" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.1-chrony` | Package chrony is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.2-chronyd-enabled` | Service chronyd is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.2-chronyd-running` | Service chronyd is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.2-etc_chrony.conf-attrs` | /etc/chrony.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.2-etc_chrony.conf-content` | /etc/chrony.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.2-etc_sysconfig_chronyd-attrs` | /etc/sysconfig/chronyd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.2.1.2-etc_sysconfig_chronyd-content` | /etc/sysconfig/chronyd has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.3.5-openldap-clients` | Package openldap-clients is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.3.2-rsh` | Package rsh is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.3.3-talk` | Package talk is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.3.4-telnet` | Package telnet is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-2.3.1-ypbind` | Package ypbind is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.1.1-net.ipv6.conf.all.disable_ipv6` | Kernel parameter net.ipv6.conf.all.disable_ipv6 is 1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-3.1.1-net.ipv6.conf.default.disable_ipv6` | Kernel parameter net.ipv6.conf.default.disable_ipv6 is 1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-3.1.1-ipv6_boot_grub` | ipv6 boot grub: grep "^\\s\*linux" /boot/grub2/grub.cfg \| grep -v ipv6.disable=1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-3.1.1-ipv6_default_grub` | ipv6 default grub: grep "^\\s\*linux" /etc/default/grub \| grep -v ipv6.disable=1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-3.1.1-iwconfig` | iwconfig: iwconfig | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.2.2-net.ipv4.conf.all.send_redirects` | Kernel parameter net.ipv4.conf.all.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.2.2-net.ipv4.conf.default.send_redirects` | Kernel parameter net.ipv4.conf.default.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.2.1-net.ipv4.ip_forward` | Kernel parameter net.ipv4.ip_forward is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.1-net.ipv4.conf.all.accept_source_route` | Kernel parameter net.ipv4.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.1-net.ipv4.conf.default.accept_source_rout` | Kernel parameter net.ipv4.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.2-net.ipv4.conf.all.accept_redirects` | Kernel parameter net.ipv4.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.2-net.ipv4.conf.default.accept_redirects` | Kernel parameter net.ipv4.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.3-net.ipv4.conf.all.secure_redirects` | Kernel parameter net.ipv4.conf.all.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.3-net.ipv4.conf.default.secure_redirects` | Kernel parameter net.ipv4.conf.default.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.4-net.ipv4.conf.all.log_martians` | Kernel parameter net.ipv4.conf.all.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.4-net.ipv4.conf.default.log_martians` | Kernel parameter net.ipv4.conf.default.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.5-net.ipv4.icmp_echo_ignore_broadcasts` | Kernel parameter net.ipv4.icmp_echo_ignore_broadcasts is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.6-net.ipv4.icmp_ignore_bogus_error_respons` | Kernel parameter net.ipv4.icmp_ignore_bogus_error_responses is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.7-net.ipv4.conf.all.rp_filter` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.7-net.ipv4.conf.all.rp_filter_2` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.3.8-net.ipv4.tcp_syncookies` | Kernel parameter net.ipv4.tcp_syncookies is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.4.1-modprobe_dccp` | modprobe dccp: modprobe -n -v dccp | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-3.4.2-modprobe_sctp` | modprobe sctp: modprobe -n -v sctp | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-3.5.1.1-firewalld` | Package firewalld is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.1-iptables` | Package iptables is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.2-iptables-services` | Package iptables-services is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.3-nftables` | Package nftables is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.4-firewalld-enabled` | Service firewalld is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.4-firewalld-running` | Service firewalld is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.3-nftables-enabled` | Service nftables is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.3-nftables-running` | Service nftables is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.5-default_zone` | default zone: firewall-cmd --get-default-zone | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-3.5.1.6-nic_assigned` | nic assigned: nmcli -t connection show \| awk -F ':' '{if($4){print $4}}' \| while read INT; do firewall-… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.1.1.1-audit` | Package audit is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.1.1-audit-libs` | Package audit-libs is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.1.2-auditd-enabled` | Service auditd is enabled | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.1.2-auditd-running` | Service auditd is running | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.1.3-auditd_grub` | auditd grub: grep "^\\s\*linux" /boot/grub2/grub.cfg \| grep -Evc "(audit=1\|rescue)" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.2.1-auditd_max_log` | auditd max log: grep max_log_file /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.2.2-auditd_max_log_action` | auditd max log action: grep max_log_file_action /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.2.3-audit_logs_full_action` | audit logs full action: grep -E "(space_left\|action_mail_acct)" /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.2.1-audit_grub_backlog` | audit grub backlog: grep audit_backlog_limit /etc/default/grub | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.3-auditd_time_cnf` | auditd time cnf: grep time-change /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.3-auditd_time_live` | auditd time live: auditctl -l \| grep time-change | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.4-auditd_identity_cnf` | auditd identity cnf: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.4-auditd_identity_live` | auditd identity live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.5-auditd_locale_cnf` | auditd locale cnf: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.5-auditd_locale_live` | auditd locale live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.6-auditd_MAC_cnf` | auditd MAC cnf: grep MAC-policy /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.6-auditd_MAC_live` | auditd MAC live: auditctl -l \| grep MAC-policy | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.7-auditd_logins_cnf` | auditd logins cnf: grep logins /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.7-auditd_logins_live` | auditd logins live: auditctl -l \| grep logins | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.8-auditd_session_live` | auditd session live: auditctl -l \| grep -E '(session\|logins)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.8-auditd_sessions_cnf` | auditd sessions cnf: grep -E '(session\|logins)' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.9-auditd_perms_cnf` | auditd perms cnf: grep perm_mod /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.9-auditd_perms_live` | auditd perms live: auditctl -l \| grep perm_mod | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.10-auditd_access_cnf` | auditd access cnf: sh -c "grep auid /etc/audit/rules.d/\*.rules" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.10-auditd_access_live` | auditd access live: auditctl -l \| grep access | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.11-auditd_priv_cmds_cnf` | auditd priv cmds cnf: grep delete /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.12-auditd_mounts_cnf` | auditd mounts cnf: grep mounts /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.12-auditd_mounts_live` | auditd mounts live: auditctl -l \| grep mounts | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.13-auditd_delete_cnf` | auditd delete cnf: grep delete /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.13-auditd_delete_live` | auditd delete live: auditctl -l \| grep delete | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.14-auditd_admin_scope_cnf` | auditd admin scope cnf: grep scope /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.14-auditd_admin_scope_live` | auditd admin scope live: auditctl -l \| grep scope | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.15-auditd_sudolog_cnf` | auditd sudolog cnf: grep actions /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.15-auditd_sudolog_live` | auditd sudolog live: auditctl -l \| grep actions | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.16-auditd_admin_module_live` | auditd admin module live: auditctl -l \| grep modules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.16-auditd_module_cnf` | auditd module cnf: grep modules /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.1.17-auditd_immutable` | auditd immutable: grep "-e 2" /etc/audit/rules.d/\*.rules \| cut -d ":" -f2 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-4.2.1.1-rsyslog` | Package rsyslog is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.1.1-rsyslog-enabled` | Service rsyslog is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.1.1-rsyslog-running` | Service rsyslog is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.1.3-rsyslog_d_perms` | rsyslog d perms: grep '\\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/\*.conf \| grep -cv '\\$FileCreateM… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.1.4-etc_rsyslog.conf-attrs` | /etc/rsyslog.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.1.4-etc_rsyslog.conf-content` | /etc/rsyslog.conf has the expected content (16 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.1.5-remote_syslog` | remote syslog: grep "^\*.\*[^I][^I]\*@" /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.2.1-journald_fwd_syslog` | journald fwd syslog: grep -Ei "^ForwardToSyslog" /etc/systemd/journald.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.2.2-journald_compress` | journald compress: grep -Ei "^compress" /etc/systemd/journald.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.2.3-journald_Storage` | journald Storage: grep -Ei "^Storage" /etc/systemd/journald.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-4.2.3-logfile_configured` | logfile configured: find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \\; | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.1-cronie` | Package cronie is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.1-crond-enabled` | Service crond is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.1-crond-running` | Service crond is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.2-etc_crontab-attrs` | /etc/crontab: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.7-etc_cron.d-attrs` | /etc/cron.d: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.4-etc_cron.daily-attrs` | /etc/cron.daily: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.3-etc_cron.hourly-attrs` | /etc/cron.hourly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.6-etc_cron.monthly-attrs` | /etc/cron.monthly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.5-etc_cron.weekly-attrs` | /etc/cron.weekly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.8-etc_cron.allow-attrs` | /etc/cron.allow: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.8-etc_cron.deny-absent` | /etc/cron.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.9-etc_at.allow-attrs` | /etc/at.allow: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.1.9-etc_at.deny-absent` | /etc/at.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.2.1-sudo` | Package sudo is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.2.2-pty_sudoers_d` | pty sudoers d: ls -1 /etc/sudoers.d/\* > /dev/null 2>&1; if [ '$?' = '0' ]; then grep -c '^Defaults.\*\\sus… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.2.2-sudoers_pty` | sudoers pty: grep use_pty /etc/sudoers | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.2.3-log_sudoers_d` | log sudoers d: grep -c '^Defaults logfile=/var/log/\*.log' /etc/sudoers.d/.\*/ | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.2.3-sudoers_log` | sudoers log: grep logfile /etc/sudoers | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.1-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.2-etc_ssh_ssh_host_prv_key_group` | /etc/ssh/ssh host prv key group: groupkeys=$(sudo find /etc/ssh/ -name \*_key -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.2-etc_ssh_ssh_host_prv_key_perms` | /etc/ssh/ssh host prv key perms: keyperms=$(sudo find /etc/ssh/ -name \*_key -type f -perm /137 ); echo $keyperms | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.2.3-etc_ssh_ssh_host_prv_key_user` | /etc/ssh/ssh host prv key user: userkeys=$(sudo find /etc/ssh/ -name \*_key -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.3-etc_ssh_ssh_host_pub_key_group` | /etc/ssh/ssh host pub key group: groupkeys=$(sudo find /etc/ssh/ -name \*_key.pub -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.3-etc_ssh_ssh_host_pub_key_perms` | /etc/ssh/ssh host pub key perms: keysperm=$(sudo find /etc/ssh/ -name \*_key.pub -type f  -perm /137 ); echo $keyperms | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.3-etc_ssh_ssh_host_pub_key_user` | /etc/ssh/ssh host pub key user: userkeys=$(sudo find /etc/ssh/ -name \*_key.pub -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.5-ssh_loglevel` | ssh loglevel: grep -E "^LogLevel" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.6-ssh_x11` | ssh x11: grep -Ei "X11forwarding" /etc/ssh/sshd_config | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.7-sshd_authtries` | sshd authtries: grep -Ei "maxauthtries" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.8-ssh_rhosts` | ssh rhosts: grep -Ei "Ignorerhosts" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.9-ssh_hostbased_auth` | ssh hostbased auth: grep -Ei "HostBasedAuth" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.10-ssh_permit_root` | ssh permit root: grep -Ei "permitrootlogin" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.11-ssh_empty_passwd` | ssh empty passwd: grep -Ei "permitemptypasswords" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.12-ssh_userenv` | ssh userenv: grep -Ei "PermitUserEnvironment" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.13-sshd_ciphers` | sshd ciphers: grep -Ei "^Ciphers" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.14-sshd_MACS` | sshd MACS: grep -Ei "^MACs" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.15-sshd_KEX` | sshd KEX: grep -Ei "^KEX" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.16-sshd_clientalive` | sshd clientalive: grep -Ei "^ClientAlive" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.17-ssh_logingrace` | ssh logingrace: grep -Ei "^logingrace" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.19-ssh_usepam` | ssh usepam: grep -Ei "^usepam" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.20-sshd_tcpforwarding` | sshd tcpforwarding: grep -Ei "^allowtcpforward" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.21-ssh_maxstartups` | ssh maxstartups: grep -Ei "^MaxStartups" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.3.22-ssh_maxsessions` | ssh maxsessions: grep -Ei "^MaxSessions" /etc/ssh/sshd_config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.4.1-etc_security_pwquality.conf-attrs` | /etc/security/pwquality.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.4.1-etc_security_pwquality.conf-content` | /etc/security/pwquality.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.4.2-password_auth_accountlock` | password auth accountlock: grep -E "account\\s+required" /etc/pam.d/password-auth | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.4.3-password_auth_sha` | password auth sha: grep sha512 /etc/pam.d/password-auth | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.4.4-password_auth_remember` | password auth remember: grep remember /etc/pam.d/password-auth | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.4.4-system_auth_remember` | system auth remember: grep remember /etc/pam.d/system-auth | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.1.1-login_defs_max_days` | login defs max days: grep PASS_MAX_DAYS /etc/login.defs | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.1.2-login_defs_min_days` | login defs min days: grep PASS_MIN_DAYS /etc/login.defs | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.1.3-login_defs_warn_age` | login defs warn age: grep PASS_WARN_AGE /etc/login.defs | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.1.4-inactive_passwd` | inactive passwd: useradd -D \| grep INACTIVE | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.1.4-inactive_users` | inactive users: grep -E ^[^:]+:[^\\!\*] /etc/shadow \| grep -vw root \| cut -d : -f1,7 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.1.5-passwd_chg_past` | No user has a last password change date in the future | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.2-secure_system_LK` | secure system LK: /awk -F: '$3<1000' /etc/passwd \| egrep -wv 'root' \| cut -d: -f1 \| xargs -I '{}' passwd -S… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.2-secure_system_accts` | secure system accts: /awk -F: '$3<1000' /etc/passwd \| egrep -v 'root\|sync\|halt\|shutdown\|/sbin/nologin\|/bin/fal… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.3-root` | User root has UID 0 and GID 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.4-etc_profile.d_tmout.sh-attrs` | /etc/profile.d/tmout.sh: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.4-etc_profile.d_tmout.sh-content` | /etc/profile.d/tmout.sh has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.5-etc_profile-attrs` | /etc/profile: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.5.5-etc_profile-content` | /etc/profile has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.7-etc_group-attrs` | /etc/group: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.7-etc_group-content` | /etc/group has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.7-etc_pam.d_su-attrs` | /etc/pam.d/su: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-5.7-etc_pam.d_su-content` | /etc/pam.d/su has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.1-rpm_filecheck` | rpm filecheck: rpm -Va --nomtime --nosize --nomd5 --nolinkto > /tmp/cis_rpmcheck \| grep -vw c && cat /tm… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-RHEL7-6.1.2-passwd_perms` | passwd perms: stat -L -c "%a %U %G" /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.3-passwd-_perms` | passwd perms: stat -L -c "%a %U %G" /etc/passwd- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.4-shadow_perms` | shadow perms: stat -L -c "%a %U %G" /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.5-shadow-_perms` | shadow perms: stat -L -c "%a %U %G" /etc/shadow- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.6-gshadow-_perms` | gshadow perms: stat -L -c "%a %U %G" /etc/gshadow- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.7-gshadow_perms` | gshadow perms: stat -L -c "%a %U %G" /etc/gshadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.8-group_perms` | group perms: stat -L -c "%a %U %G" /etc/group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.9-group-_perms` | group perms: stat -L -c "%a %U %G" /etc/group- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.10-world_writable` | world writable: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.11-unowned` | unowned: df --local -P \| awk {'if (NR!=1) print $6'} \| xargs -I '{}' find '{}' -xdev -nouser | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.12-ungrouped` | ungrouped: df --local -P \| awk {'if (NR!=1) print $6'} \| xargs -I '{}' find '{}' -xdev -nogroup | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.13-suid_executables` | suid executables: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.1.14-sgid_executables` | sgid executables: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.1-etc_passwd-attrs` | /etc/passwd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.1-etc_passwd-content` | /etc/passwd has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.2-etc_shadow-attrs` | /etc/shadow: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.2-etc_shadow-content` | /etc/shadow has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.3-passwd_group_exist` | passwd group exist: pwck -r \| grep 'no group' \| awk '{ gsub("[:\\47]",""); print $2}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.4-shadow` | Group shadow does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.5-no_dup_username` | no dup username: cat /etc/passwd \| cut -d: -f1 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.6-no_dup_groupname` | no dup groupname: cat /etc/group \| cut -d: -f1 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.7-no_dup_uid` | no dup uid: cat /etc/passwd \| cut -d: -f3 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.8-no_dup_gid` | no dup gid: cat /etc/group \| cut -d: -f3 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.9-uid_0_check` | uid 0 check: awk -F: '($3 == 0) { print $1 }' /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.10-root_path_check` | root path check: /bin/bash --login -c 'env \| grep ^PATH=' \| sed -e 's/PATH=//' -e 's/::/:/' -e 's/:$//' -e… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.11-home_dirs_exist` | home dirs exist: set -o pipefail; pwck -r \| grep -P "^user '(?P<user>.\*)': directory '(?P<dir>.\*)' does no… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.12-home_dirs_owned` | home dirs owned: getent passwd {1000..60000} \|  awk -F: '{ print $1  " "  $6 }' \| while read user dir; do … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.13-home_dirs_exist` | home dirs exist: for i in `getent passwd {1000..60000} \|  awk '{split($0,a,":");print a[6]}'`; do stat -c … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.14-dot_file_perms` | dot file perms: find /home/ -name "\\.\*" -perm /g+w,o+w | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.15-dot_forward_files` | dot forward files: find /home/ -name .forward | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.16-dot_netrc_files` | dot netrc files: find /home/ -name .netrc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-RHEL7-6.2.17-dot_rhosts_files` | dot rhosts files: find /home/ -name .rhosts | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |

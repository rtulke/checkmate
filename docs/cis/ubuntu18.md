# CIS Ubuntu 18.04 LTS

Automated checks for 229 recommendations of the CIS Ubuntu 18.04 LTS benchmark (version 2.1.0), converted from the goss audit content of the ansible-lockdown project. Check names describe what is verified; the recommendation number is in the ID and the description. Select profiles with tags, e.g. `--tags cis-level-1+cis-server`.

**Policy:** [`cis/ubuntu18.yml`](https://github.com/rtulke/checkmate/blob/main/cis/ubuntu18.yml) · **Benchmark version:** 2.1.0

```bash
checkmate run cis/ubuntu18.yml --tags cis-level1-server
checkmate run cis/ubuntu18.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-UBUNTU18-1.1.1.1-cramfs` | cramfs: if [ `lsmod \| grep -c cramfs` != 0 ]; then  "modprobe -n -v jffs \| grep -E '(cramfs\|insta… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.1.2-freevxfs` | freevxfs: if [ `lsmod \| grep -c freevxfs` != 0 ]; then  "modprobe -n -v jffs \| grep -E '(freevxfs\|i… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.1.4-hfs` | hfs: if [ `lsmod \| grep -c hfs` != 0 ]; then  "modprobe -n -v jffs \| grep -E '(hfs\|install)'";… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.1.5-hfsplus` | hfsplus: if [ `lsmod \| grep -c hfsplus` != 0 ]; then  "modprobe -n -v jffs \| grep -E '(hfsplus\|ins… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.1.3-jffs` | jffs: if [ `lsmod \| grep -c jffs` != 0 ]; then  "modprobe -n -v jffs \| grep -E '(jffs\|install)'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.1.6-udf` | udf: if [ `lsmod \| grep -c udf` != 0 ]; then  "modprobe -n -v jffs \| grep -E '(udf\|install)'";… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.2-tmp` | /tmp is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.3-tmp` | /tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.4-tmp` | /tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.5-tmp` | /tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.6-dev_shm` | /dev/shm is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.7-dev_shm` | /dev/shm is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.8-dev_shm` | /dev/shm is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.9-dev_shm` | /dev/shm is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.10-var` | /var is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-1.1.11-var_tmp` | /var/tmp is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-1.1.12-var_tmp` | /var/tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.13-var_tmp` | /var/tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.14-var_tmp` | /var/tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.15-var_log` | /var/log is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-1.1.16-var_log_audit` | /var/log/audit is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.17-home` | /home is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-1.1.17-home-2` | /home is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.19-cdrom_nodev` | cdrom nodev: if [ `grep -c -i cdrom /etc/fstab` = 1 ] ; then if [ `grep -c -E 'cdrom.\*nodev' /etc/fsta… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.19-floppy_nodev` | floppy nodev: if [ `grep -c -i floppy /etc/fstab` = 1 ] ; then if [ `grep -c -E 'floppy.\*nodev' /etc/fs… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.20-cdrom_nosuid` | cdrom nosuid: if [ `grep -c -i cdrom /etc/fstab` = 1 ] ; then if [ `grep -c -E 'cdrom.\*nosuid' /etc/fst… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.20-floppy_nosuid` | floppy nosuid: if [ `grep -c -i floppy /etc/fstab` = 1 ] ; then if [ `grep -c -E 'floppy.\*nosuid' /etc/f… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.21-cdrom_noexec` | cdrom noexec: if [ `grep -c -i cdrom /etc/fstab` = 1 ] ; then if [ `grep -c -E 'cdrom.\*noexec' /etc/fst… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.21-floppy_noexec` | floppy noexec: if [ `grep -c -i floppy /etc/fstab` = 1 ] ; then if [ `grep -c -E 'floppy.\*noexec' /etc/f… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.22-sticky_bit` | sticky bit: df --local -P 2> /dev/null \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.23-autofs-enabled` | Service autofs is not enabled | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.23-autofs-running` | Service autofs is not running | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.1.24-cramfs` | cramfs: modprobe -n -v usb-storage \| grep -E '(usb-storage\|install)' | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.2.1-repos_configd` | repos configd: echo "Please check manually for configured repos" | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.2.2-repos_configd` | repos configd: echo "Please check manually for gpg keys" | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.4.1-usr_sbin_grub-mkconfig-attrs` | /usr/sbin/grub-mkconfig: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.4.1-usr_sbin_grub-mkconfig-content` | /usr/sbin/grub-mkconfig has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.4.2-boot_grub_grub.cfg-attrs` | /boot/grub/grub.cfg: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.4.2-boot_grub_grub.cfg-content` | /boot/grub/grub.cfg has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.4.3-boot_grub_grub.cfg-attrs` | /boot/grub/grub.cfg: exists, mode 0256 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.4.4-check_root_pw` | check root pw: grep -Eq '^root:\\$[0-9]' /etc/shadow \|\| echo "root is not locked" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.1-kernel_nx` | kernel nx: journalctl \| grep 'protection: active' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.2-kernel.randomize_va_space` | Kernel parameter kernel.randomize_va_space is 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.2-aslr_enabled_2` | aslr enabled 2: grep "^kernel\\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/\* \| cut -d ":" -f2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.3-prelink` | Package prelink is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-fs.suid_dumpable` | Kernel parameter fs.suid_dumpable is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-coredump-enabled` | Service coredump is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-coredump-running` | Service coredump is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-etc_systemd_coredump.conf-attrs` | /etc/systemd/coredump.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-etc_systemd_coredump.conf-content` | /etc/systemd/coredump.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-core_dumps_limits` | core dumps limits: grep -E "\\\*.\*hard.\*core.\*0" /etc/security/limits.conf /etc/security/limits.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.5.4-suid_dumpable_2` | suid dumpable 2: grep "fs\\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.6.1.1-apparmor` | Package apparmor is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.6.1.2-boot_grub_grub.cfg-attrs` | /boot/grub/grub.cfg: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.6.1.2-boot_grub_grub.cfg-content` | /boot/grub/grub.cfg has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.6.1.2-etc_default_grub-attrs` | /etc/default/grub: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.6.1.2-etc_default_grub-content` | /etc/default/grub has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.6.1.3-apparmor_enf_or_comp` | apparmor enf or comp: LOADED=`apparmor_status \| grep 'profiles are loaded' \| awk '{print $1}'` && ENFORCE=`appa… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.7.1-check_motd_files` | check motd files: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.7.2-etc_issue.net-attrs` | /etc/issue.net: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.7.3-etc_issue-attrs` | /etc/issue: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.7.5-check_motd_files` | check motd files: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.7.6-check_motd_files` | check motd files: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.8.1-gdm3` | Package gdm3 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-1.9-check_updates` | check updates: apt update \| tail -1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.1-chrony` | Package chrony is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-chrony` | Package chrony is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-ntp` | Package ntp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-chronyd-enabled` | Service chronyd is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-chronyd-running` | Service chronyd is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-timesyncd-enabled` | Service timesyncd is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-timesyncd-running` | Service timesyncd is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-etc_chrony_chrony.conf-attrs` | /etc/chrony/chrony.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.1.3-etc_chrony_chrony.conf-content` | /etc/chrony/chrony.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.2-xserver-xorg` | Package xserver-xorg is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.3-avahi-daemon` | Package avahi-daemon is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.4-cups` | Package cups is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.5-cups` | Package cups is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.6-slapd` | Package slapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.8-bind9` | Package bind9 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.9-vsftpd` | Package vsftpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.10-httpd` | Package httpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.11-dovecot-imapd` | Package dovecot-imapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.11-dovecot-pop3d` | Package dovecot-pop3d is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.12-samba` | Package samba is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.13-squid` | Package squid is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.14-snmpd` | Package snmpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.15-port_25_local_only` | port 25 local only: ss -lntu \| grep -E ':25\\s' \| grep -E -v '\\s(127.0.0.1\|::1):25\\s' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.16-rsync` | Package rsync is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.1.17-nis` | Package nis is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.2.1-nis` | Package nis is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.2.2-rsh-client` | Package rsh-client is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.2.3-talk` | Package talk is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.2.4-telnet` | Package telnet is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.2.5-ldap-utils` | Package ldap-utils is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.2.6-rpcbind` | Package rpcbind is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-2.3-non_essen_svcs` | non essen svcs: echo "Manual -  checking of services that are not required are removed or masked" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.1.2-wireless_disabled` | wireless disabled: nmcli radio all \| tail -1 | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.1-net.ipv4.conf.all.send_redirects` | Kernel parameter net.ipv4.conf.all.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.1-net.ipv4.conf.default.send_redirects` | Kernel parameter net.ipv4.conf.default.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.1-ipv4_disable_all_redirect` | ipv4 disable all redirect: grep -E "^\\s\*net\\.ipv4\\.conf\\.all\\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.1-ipv4_disable_def_redirect` | ipv4 disable def redirect: grep -E "^\\s\*net\\.ipv4\\.conf\\.default\\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.2-net.ipv4.ip_forward` | Kernel parameter net.ipv4.ip_forward is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.2-net.ipv6.conf.all.forwarding` | Kernel parameter net.ipv6.conf.all.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.2-ipv4_ip_forward` | ipv4 ip forward: grep -E "^\\s\*net\\.ipv4\\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/\*.conf /usr/lib/sysctl… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.2-ipv6_ip_forward` | ipv6 ip forward: grep -E "^\\s\*net\\.ipv6\\.conf\\.all\\.forwarding" /etc/sysctl.conf /etc/sysctl.d/\*.conf /usr… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-net.ipv4.conf.all.accept_source_route` | Kernel parameter net.ipv4.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-net.ipv4.conf.default.accept_source_rout` | Kernel parameter net.ipv4.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-ipv4_all_source_route` | ipv4 all source route: grep "net\\.ipv4\\.conf\\.all\\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-ipv4_def_source_route` | ipv4 def source route: grep "net\\.ipv4\\.conf\\.default\\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-net.ipv4.conf.all.accept_redirects` | Kernel parameter net.ipv4.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-net.ipv4.conf.default.accept_redirects` | Kernel parameter net.ipv4.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-ipv4_all_icmp_redirects` | ipv4 all icmp redirects: grep "net\\.ipv4\\.conf\\.all\\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-ipv4_def_icmp_redirects` | ipv4 def icmp redirects: grep "net\\.ipv4\\.conf\\.default\\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.3-net.ipv4.conf.all.secure_redirects` | Kernel parameter net.ipv4.conf.all.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.2.3-net.ipv4.conf.default.secure_redirects` | Kernel parameter net.ipv4.conf.default.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.3-ipv4_all_sec_redirects` | ipv4 all sec redirects: grep "net\\.ipv4\\.conf\\.all\\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.3-ipv4_def_sec_redirects` | ipv4 def sec redirects: grep "net\\.ipv4\\.conf\\.default\\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.4-net.ipv4.conf.all.log_martians` | Kernel parameter net.ipv4.conf.all.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.4-net.ipv4.conf.default.log_martians` | Kernel parameter net.ipv4.conf.default.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.4-ipv4_all_martians` | ipv4 all martians: grep "net\\.ipv4\\.conf\\.all\\.log_martians" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.4-ipv4_def_martians` | ipv4 def martians: grep "net\\.ipv4\\.conf\\.default\\.log_martians" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.5-net.ipv4.icmp_echo_ignore_broadcasts` | Kernel parameter net.ipv4.icmp_echo_ignore_broadcasts is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.5-ipv4_ignore_icmp_broadcast` | ipv4 ignore icmp broadcast: grep "net\\.ipv4\\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.6-net.ipv4.icmp_ignore_bogus_error_respons` | Kernel parameter net.ipv4.icmp_ignore_bogus_error_responses is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.6-ipv4_ignore_bogus` | ipv4 ignore bogus: grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.7-net.ipv4.conf.all.rp_filter` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.7-net.ipv4.conf.default.rp_filter` | Kernel parameter net.ipv4.conf.default.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.7-ipv4_all_rp_filter` | ipv4 all rp filter: grep "net\\.ipv4\\.conf\\.all\\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.7-ipv4_def_rp_filter` | ipv4 def rp filter: grep "net\\.ipv4\\.conf\\.default\\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.8-net.ipv4.tcp_syncookies` | Kernel parameter net.ipv4.tcp_syncookies is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.8-ipv4_tcp_syncookies` | ipv4 tcp syncookies: grep "net\\.ipv4\\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-net.ipv6.conf.all.accept_source_route` | Kernel parameter net.ipv6.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-net.ipv6.conf.default.accept_source_rout` | Kernel parameter net.ipv6.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-ipv6_all_source_route` | ipv6 all source route: grep "net\\.ipv6\\.conf\\.all\\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.1-ipv6_def_source_route` | ipv6 def source route: grep "net\\.ipv6\\.conf\\.default\\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-net.ipv6.conf.all.accept_redirects` | Kernel parameter net.ipv6.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-net.ipv6.conf.default.accept_redirects` | Kernel parameter net.ipv6.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-ipv6_all_icmp_redirects` | ipv6 all icmp redirects: grep "net\\.ipv6\\.conf\\.all\\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.2-ipv6_def_icmp_redirects` | ipv6 def icmp redirects: grep "net\\.ipv6\\.conf\\.default\\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.9-net.ipv6.conf.all.accept_ra` | Kernel parameter net.ipv6.conf.all.accept_ra is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.9-net.ipv6.conf.default.accept_ra` | Kernel parameter net.ipv6.conf.default.accept_ra is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.9-ipv6_all_rtr_adverts` | ipv6 all rtr adverts: grep "net\\.ipv6\\.conf\\.all\\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.3.9-ipv6_def_rtr_adverts` | ipv6 def rtr adverts: grep "net\\.ipv6\\.conf\\.default\\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.4.1-lsmod_dccp` | lsmod dccp: lsmod \| grep dccp | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.1-modprobe_dccp` | modprobe dccp: modprobe -n -v dccp | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.2-lsmod_sctp` | lsmod sctp: lsmod \| grep sctp | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.2-modprobe_sctp` | modprobe sctp: modprobe -n -v sctp | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.3-lsmod_RDS` | lsmod RDS: lsmod \| grep rds | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.3-modprobe_RDS` | modprobe RDS: modprobe -n -v RDS | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.4-lsmod_TIPC` | lsmod TIPC: lsmod \| grep tipc | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.4.4-modprobe_TIPC` | modprobe TIPC: modprobe -n -v TIPC | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-3.5.1.1-ufw` | Package ufw is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.2-iptables-persistent` | Package iptables-persistent is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.3-ufw-enabled` | Service ufw is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.3-ufw-running` | Service ufw is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.4-ufw_local` | ufw local: ufw status verbose | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.5-ufw_outbound` | ufw outbound: echo "Manual - Please confirm firewall outbound Policies match site policies" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.6-ufw_open_ports` | ufw open ports: echo "Manual - Please confirm firewall rules exist for open ports match site policies" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.1.7-ufw_def_deny` | ufw def deny: echo "Manual - Please confirm firewall default deny policy match site policies" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.1-nftables` | Package nftables is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.2-ufw` | Package ufw is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.3-ip6tables_flushed` | ip6tables flushed: ip6tables -L | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.3-iptables_flushed` | iptables flushed: iptables -L | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.4-nft_tables` | nft tables: echo "Manual - Please confirm nfttables table exists and matched site policy" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.5-nft_chains` | nft chains: echo "Manual - Please confirm nfttables base chain exists and matched site policy" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.6-nft_loopback` | nft loopback: echo "Manual - Please confirm nfttables loopback traffic configured and matched site poli… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.7-nft_conns` | nft conns: echo "Manual - Please confirm nfttables connections are configured and matched site polic… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.8-nft_def_deny` | nft def deny: echo "Manual - Please confirm nfttables default denies are configured and matched site po… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.9-nftables-enabled` | Service nftables is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.9-nftables-running` | Service nftables is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.10-etc_nftables.conf-attrs` | /etc/nftables.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.2.10-nft_rules` | nft rules: echo "Manual - Please review nfttables configuration and matches site policy" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.1.1-iptables` | Package iptables is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.1.1-iptables-persistent` | Package iptables-persistent is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.1.2-nftables` | Package nftables is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.1.3-ufw` | Package ufw is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.2.1-ipt_def_deny` | ipt def deny: echo "Manual - Please confirm iptables default denies are configured and matched site pol… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.2.2-ipt_loopback` | ipt loopback: echo "Manual - Please confirm iptables loopback connections are configured and matched si… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.2.3-ipt_conns_config` | ipt conns config: echo "Manual - Please confirm iptables outbound and connections are configured and matche… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.2.4-ipt_open_ports` | ipt open ports: echo "Manual - Please confirm iptables rules for open ports configured and matched site p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.3.1-ipt6_def_deny` | ipt6 def deny: echo "Manual - Please confirm ip6tables default denies are configured and matched site po… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.3.2-ipt6_loopback` | ipt6 loopback: echo "Manual - Please confirm ip6tables loopback connections are configured and matched s… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.3.3-ipt6_conns_config` | ipt6 conns config: echo "Manual - Please confirm ip6tables outbound and connections are configured and match… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-3.5.3.3.4-ipt6_open_ports` | ipt6 open ports: echo "Manual - Please confirm ip6tables rules for open ports configured and matched site … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.1.1.1-audispd-plugins` | Package audispd-plugins is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.1-auditd` | Package auditd is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.2-auditd-enabled` | Service auditd is enabled | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.2-auditd-running` | Service auditd is running | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.3-etc_default_grub-attrs` | /etc/default/grub: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.3-etc_default_grub-content` | /etc/default/grub has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.3-auditd_grub` | auditd grub: grep "^\\s\*linux" /boot/grub/grub.cfg \| grep -Evc "audit=1" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.4-etc_default_grub-attrs` | /etc/default/grub: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.4-etc_default_grub-content` | /etc/default/grub has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.1.4-auditd_grub_backlog` | auditd grub backlog: grep "^\\s\*linux" /boot/grub/grub.cfg \| grep -Evc "audit_backlog_limit=" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.2.1-etc_audit_auditd.conf-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.2.1-etc_audit_auditd.conf-content` | /etc/audit/auditd.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.2.2-etc_audit_auditd.conf-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.2.2-etc_audit_auditd.conf-content` | /etc/audit/auditd.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.2.3-etc_audit_auditd.conf-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.2.3-etc_audit_auditd.conf-content` | /etc/audit/auditd.conf has the expected content (3 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.3-auditd_time_cnf` | auditd time cnf: grep time-change /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.3-auditd_time_live` | auditd time live: auditctl -l \| grep time-change | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.4-auditd_identity_cnf` | auditd identity cnf: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.4-auditd_identity_live` | auditd identity live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.5-auditd_locale_cnf` | auditd locale cnf: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.5-auditd_locale_live` | auditd locale live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.7-auditd_logins_cnf` | auditd logins cnf: grep logins /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.7-auditd_logins_live` | auditd logins live: auditctl -l \| grep logins | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.8-auditd_session_live` | auditd session live: auditctl -l \| grep -E '(session\|logins)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.8-auditd_sessions_cnf` | auditd sessions cnf: grep -E '(session\|logins)' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.9-auditd_perms_cnf` | auditd perms cnf: grep perm_mod /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.9-auditd_perms_live` | auditd perms live: auditctl -l \| grep perm_mod | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.10-auditd_access_cnf` | auditd access cnf: sh -c "grep auid /etc/audit/rules.d/\*.rules" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.10-auditd_access_live` | auditd access live: auditctl -l \| grep access | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.11-auditd_priv_cmds_cnf` | auditd priv cmds cnf: grep delete /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.12-auditd_mounts_cnf` | auditd mounts cnf: grep mounts /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.12-auditd_mounts_live` | auditd mounts live: auditctl -l \| grep mounts | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.13-auditd_delete_cnf` | auditd delete cnf: grep delete /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.13-auditd_delete_live` | auditd delete live: auditctl -l \| grep delete | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.14-auditd_admin_scope_cnf` | auditd admin scope cnf: grep scope /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.14-auditd_admin_scope_live` | auditd admin scope live: auditctl -l \| grep scope | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.15-auditd_sudolog_cnf` | auditd sudolog cnf: grep actions /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.15-auditd_sudolog_live` | auditd sudolog live: auditctl -l \| grep actions | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.16-auditd_admin_module_live` | auditd admin module live: auditctl -l \| grep modules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.16-auditd_module_cnf` | auditd module cnf: grep modules /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.1.17-auditd_immutable` | auditd immutable: grep "-e 2" /etc/audit/rules.d/\*.rules \| cut -d ":" -f2 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-4.2.1.1-rsyslog` | Package rsyslog is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.2-rsyslog-enabled` | Service rsyslog is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.2-rsyslog-running` | Service rsyslog is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.3-etc_rsyslog.conf-attrs` | /etc/rsyslog.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.3-etc_rsyslog.conf-content` | /etc/rsyslog.conf has the expected content (16 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.4-etc_rsyslog.conf-attrs` | /etc/rsyslog.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.4-etc_rsyslog.conf-content` | /etc/rsyslog.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.4-rsyslog_d_perms` | rsyslog d perms: grep '\\$FileCreateMode' /etc/rsyslog.d/\*.conf \| grep -cv '\\$FileCreateMode 0[0,6][0,4]0' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.5-remote_syslog` | remote syslog: grep "^\*.\*[^I][^I]\*@" /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.6-rsyslog_des_hosts` | rsyslog des hosts: grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.1.6-rsyslog_des_hosts_tcp` | rsyslog des hosts tcp: grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.2.1-etc_systemd_journald.conf-attrs` | /etc/systemd/journald.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.2.1-etc_systemd_journald.conf-content` | /etc/systemd/journald.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.2.2-etc_systemd_journald.conf-attrs` | /etc/systemd/journald.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.2.2-etc_systemd_journald.conf-content` | /etc/systemd/journald.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.2.3-etc_systemd_journald.conf-attrs` | /etc/systemd/journald.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.2.3-etc_systemd_journald.conf-content` | /etc/systemd/journald.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.2.3-logfile_configured` | logfile configured: find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \\; | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.3-logrotate_config` | logrotate config: echo " Manual - Please ensure lograote is configured as per site policy" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.4-etc_logrotate.conf-attrs` | /etc/logrotate.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.4-etc_logrotate.conf-content` | /etc/logrotate.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-4.4-logrotate_config` | logrotate config: grep -Es "^\\s\*create\\s+\\S+" /etc/logrotate.conf /etc/logrotate.d/\* \| grep - E -v "\\s(0)?[… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.1-cron` | Package cron is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.1-cron-enabled` | Service cron is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.1-cron-running` | Service cron is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.2-etc_crontab-attrs` | /etc/crontab: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.7-etc_cron.d-attrs` | /etc/cron.d: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.4-etc_cron.daily-attrs` | /etc/cron.daily: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.3-etc_cron.hourly-attrs` | /etc/cron.hourly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.6-etc_cron.monthly-attrs` | /etc/cron.monthly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.5-etc_cron.weekly-attrs` | /etc/cron.weekly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.8-etc_cron.allow-attrs` | /etc/cron.allow: exists, mode 0640 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.8-etc_cron.deny-absent` | /etc/cron.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.9-etc_at.allow-attrs` | /etc/at.allow: exists, mode 0640 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.1.9-etc_at.deny-absent` | /etc/at.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.1-sudo` | Package sudo is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.2-etc_sudoers-attrs` | /etc/sudoers: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.2-etc_sudoers-content` | /etc/sudoers has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.2-pty_sudoers_d` | pty sudoers d: ls -1 /etc/sudoers.d/\* > /dev/null 2>&1; if [ '$?' = '0' ]; then grep -c '^Defaults.\*\\sus… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.3-etc_sudoers-attrs` | /etc/sudoers: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.3-etc_sudoers-content` | /etc/sudoers has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.3-log_sudoers_d` | log sudoers d: grep -c '^Defaults logfile=/var/log/\*.log' /etc/sudoers.d/.\*/ | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.1-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.2-etc_ssh_ssh_host_key_group` | /etc/ssh/ssh host key group: groupkeys=$(sudo find /etc/ssh/ -name \*_key -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.2-etc_ssh_ssh_host_key_perms` | /etc/ssh/ssh host key perms: keyperms=$(sudo find /etc/ssh/ -name \*_key -type f -perm /137 ); echo $keyperms | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.2.3-etc_ssh_ssh_host_key_user` | /etc/ssh/ssh host key user: userkeys=$(sudo find /etc/ssh/ -name \*_key -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.3-etc_ssh_ssh_host_key_group` | /etc/ssh/ssh host key group: groupkeys=$(sudo find /etc/ssh/ -name \*_key.pub -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.3-etc_ssh_ssh_host_key_perms` | /etc/ssh/ssh host key perms: keysperm=$(sudo find /etc/ssh/ -name \*_key.pub -type f  -perm /137 ); echo $keyperms | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.3-etc_ssh_ssh_host_key_user` | /etc/ssh/ssh host key user: userkeys=$(sudo find /etc/ssh/ -name \*_key.pub -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.5-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.5-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.6-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.6-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.7-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.7-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.8-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.8-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.9-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.9-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.10-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.10-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.11-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.11-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.12-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.12-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.13-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.13-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.14-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.14-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.15-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.15-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.16-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.16-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.17-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.17-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.18-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.18-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.18-ssh_config_banner` | ssh config banner: grep -Eis '^\\s\*Banner\\s+"?none\\b'/etc/ssh/sshd_config.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.19-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.19-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.20-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.20-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.21-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.21-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.22-etc_ssh_sshd_config-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.3.22-etc_ssh_sshd_config-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.1-libpam-pwquality` | Package libpam-pwquality is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.1-etc_security_pwquality.conf-attrs` | /etc/security/pwquality.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.1-etc_security_pwquality.conf-content` | /etc/security/pwquality.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.2-etc_pam.d_common-auth-attrs` | /etc/pam.d/common-auth: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.2-etc_pam.d_common-auth-content` | /etc/pam.d/common-auth has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.3-etc_pam.d_common-password-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.3-etc_pam.d_common-password-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.4-etc_pam.d_common-password-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.4.4-etc_pam.d_common-password-content` | /etc/pam.d/common-password has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.1-etc_login.defs-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.1-etc_login.defs-content` | /etc/login.defs has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.2-etc_login.defs-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.2-etc_login.defs-content` | /etc/login.defs has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.2-users_max_pw_expire` | users max pw expire: awk -F: '(/^[^:]+:[^!\*]/ && ($5>365 \|\| $5~/([0-1]\|-1\|\\s\*)/)){print $1 " " $5}' /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.3-etc_login.defs-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.3-etc_login.defs-content` | /etc/login.defs has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.3-user_expire_warn` | user expire warn: awk -F: '(/^[^:]+:[^!\*]/ && $6<7){print $1 " " $6}' /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.4-inactive_passwd` | inactive passwd: useradd -D \| grep INACTIVE | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.4-inactive_users` | inactive users: grep -E ^[^:]+:[^\\!\*] /etc/shadow \| grep -vw root \| cut -d : -f1,7 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.1.5-passwd_chg_past` | No user has a last password change date in the future | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.2-secure_system_LK` | secure system LK: /awk -F: '$3<1000' /etc/passwd \| egrep -wv 'root' \| cut -d: -f1 \| xargs -I '{}' passwd -S… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.2-secure_system_accts` | secure system accts: /awk -F: '$3<1000' /etc/passwd \| egrep -v 'root\|sync\|halt\|shutdown\|/sbin/nologin\|/bin/fal… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.3-root` | User root exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.4-etc_pam.d_common-session-attrs` | /etc/pam.d/common-session: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.4-etc_pam.d_common-session-content` | /etc/pam.d/common-session has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.4-umask_027` | umask 027: grep -RPi "'(^\|^[^#]\*)\\s\*umask\\s+([0-7][0-7][01][0-7]\\b\|[0-7][0-7][0-7][0-6]\\b\|[0-7][01][… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.5-etc_profile.d_tmout.sh-attrs` | /etc/profile.d/tmout.sh: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.5.5-etc_profile.d_tmout.sh-content` | /etc/profile.d/tmout.sh has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.6-root_system_console` | root system console: echo "Manual check of valid terminal in /etc/securetty is required" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.7-etc_group-attrs` | /etc/group: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.7-etc_group-content` | /etc/group has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.7-etc_pam.d_su-attrs` | /etc/pam.d/su: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-5.7-etc_pam.d_su-content` | /etc/pam.d/su has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.1-rpm_filecheck` | rpm filecheck: echo "Manual Check of packages required" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU18-6.1.2-passwd_perms` | passwd perms: stat -L -c "%a %U %G" /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.3-passwd-_perms` | passwd perms: stat -L -c "%a %U %G" /etc/passwd- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.4-group_perms` | group perms: stat -L -c "%a %U %G" /etc/group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.5-group-_perms` | group perms: stat -L -c "%a %U %G" /etc/group- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.6-shadow_perms` | shadow perms: stat -L -c "%a %U %G" /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.7-shadow-_perms` | shadow perms: stat -L -c "%a %U %G" /etc/shadow- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.8-gshadow_perms` | gshadow perms: stat -L -c "%a %U %G" /etc/gshadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.9-gshadow-_perms` | gshadow perms: stat -L -c "%a %U %G" /etc/gshadow- | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.10-world_writable` | world writable: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.11-unowned_dirs` | unowned dirs: df --local -P \| awk {'if (NR!=1) print $6'} \| xargs -I '{}' find '{}' -xdev -nouser | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.12-no_ungrouped` | no ungrouped: df --local -P \| awk {'if (NR!=1) print $6'} \| xargs -I '{}' find '{}' -xdev -nogroup | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.13-audit_suid_exec` | audit suid exec: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.1.14-audit_sgid` | audit sgid: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.1-etc_passwd-attrs` | /etc/passwd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.1-etc_passwd-content` | /etc/passwd has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.2-etc_shadow-attrs` | /etc/shadow: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.2-etc_shadow-content` | /etc/shadow has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.3-passwd_group_exist` | passwd group exist: awk -F: '{print $4}' /etc/passwd \|sort -u > /tmp/uid && awk -F: '{print $3}' /etc/group\| … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.4-home_dirs_exist` | home dirs exist: pwck -r | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.5-home_dirs_owned` | home dirs owned: getent passwd {1000..60000} \|  awk -F: '{ print $1  " "  $7 }' \| while read user dir; do … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.6-home_dirs_restrict` | home dirs restrict: export def_home=`grep "^HOME" /etc/default/useradd \|cut -d= -f2` && for i in `ls $def_hom… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.7-dot_file_perms` | dot file perms: find /home/ -name "\\.\*" -perm /g+w,o+w | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.8-dot_netrc_files` | dot netrc files: find /home/ -name .netrc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.9-dot_forward_files` | dot forward files: find /home/ -name .forward | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.10-dot_rhosts_files` | dot rhosts files: find /home/ -name .rhosts | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.11-uid_0_check` | uid 0 check: awk -F: '($3 == 0) { print $1 }' /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.12-root_path_check` | root path check: /bin/bash --login -c 'env \| grep ^PATH=' \| sed -e 's/PATH=//' -e 's/::/:/' -e 's/:$//' -e… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.13-no_dup_uid` | no dup uid: cat /etc/passwd \| cut -d: -f3 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.14-no_dup_gid` | no dup gid: cat /etc/group \| cut -d: -f3 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.15-no_dup_username` | no dup username: cat /etc/passwd \| cut -d: -f1 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.16-no_dup_groupname` | no dup groupname: cat /etc/group \| cut -d: -f1 \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU18-6.2.17-empty_shadow_group` | empty shadow group: grep ^shadow /etc/group \| awk -F':''{print $NF}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |

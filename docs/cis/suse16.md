# CIS SUSE Linux Enterprise 16

Automated checks for 315 recommendations of the CIS SUSE Linux Enterprise 16 benchmark (version 1.0.0), converted from the goss audit content of the ansible-lockdown project. Check names describe what is verified; the recommendation number is in the ID and the description. Select profiles with tags, e.g. `--tags cis-level-1+cis-server`.

**Policy:** [`cis/suse16.yml`](https://github.com/rtulke/checkmate/blob/main/cis/suse16.yml) · **Benchmark version:** 1.0.0

```bash
checkmate run cis/suse16.yml --tags cis-level1-server
checkmate run cis/suse16.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-SUSE16-1.1.1.1-blacklist_cramfs` | blacklist cramfs: grep cramfs /etc/modprobe.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.1-cramfs` | cramfs: modprobe -n -v cramfs \| grep -E '(cramfs\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.2-blacklist_firewire_core` | blacklist firewire core: grep firewire-core /etc/modprobe.d/\*.conf | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.2-firewire_core` | firewire core: modprobe -n -v firewire-core \| grep -E '(firewire-core\|install)' | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.3-blacklist_freevxfs` | blacklist freevxfs: grep freevxfs /etc/modprobe.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.3-freevxfs` | freevxfs: modprobe -n -v freevxfs \| grep -E '(freevxfs\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.4-blacklist_hfs` | blacklist hfs: grep hfs /etc/modprobe.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.4-hfs` | hfs: modprobe -n -v hfs \| grep -E '(hfs\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.5-blacklist_hfsplus` | blacklist hfsplus: grep hfsplus /etc/modprobe.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.5-hfsplus` | hfsplus: modprobe -n -v hfsplus \| grep -E '(hfsplus\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.6-blacklist_jffs2` | blacklist jffs2: grep jffs2 /etc/modprobe.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.6-jffs2` | jffs2: modprobe -n -v jffs2 \| grep -E '(jffs2\|install)' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.1.7-blacklist_overlay` | blacklist overlay: grep overlay /etc/modprobe.d/\*.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.1.7-overlay` | overlay: modprobe -n -v overlay \| grep -E '(overlay\|install)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.1.8-blacklist_squashfs` | blacklist squashfs: grep squashfs /etc/modprobe.d/\*.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.1.8-squashfs` | squashfs: modprobe -n -v squashfs \| grep -E '(squashfs\|install)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.1.9-blacklist_udf` | blacklist udf: grep udf /etc/modprobe.d/\*.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.1.9-udf` | udf: modprobe -n -v udf \| grep -E '(udf\|install)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.1.10-mounted_fstypes` | mounted fstypes: findmnt -klo FSTYPE \| sort -u | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.1-tmp_mount` | /tmp is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.2-tmp_nodev_options` | /tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.2-tmp_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.2-tmp_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.3-tmp_nosuid_options` | /tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.3-tmp_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.3-tmp_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.4-tmp_noexec_options` | /tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.4-tmp_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.1.4-tmp_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.1-dev_shm_mount` | /dev/shm is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.2-dev_shm_nodev_options` | /dev/shm is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.2-dev_shm_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.2-dev_shm_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.3-dev_shm_nosuid_options` | /dev/shm is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.3-dev_shm_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.3-dev_shm_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.4-dev_shm_noexec_options` | /dev/shm is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.4-dev_shm_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.2.4-dev_shm_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.3.1-home_mount` | /home is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.2.3.2-home_nodev_options` | /home is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.3.2-home_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.3.2-home_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.3.3-home_nosuid_options` | /home is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.3.3-home_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.3.3-home_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.4.1-var_mount` | /var is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.2.4.2-var_nodev_options` | /var is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.4.2-var_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.4.2-var_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.4.3-var_nosuid_options` | /var is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.4.3-var_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.4.3-var_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.1-var_tmp_mount` | /var/tmp is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.2.5.2-var_tmp_nodev_options` | /var/tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.2-var_tmp_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.2-var_tmp_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.3-var_tmp_nosuid_options` | /var/tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.3-var_tmp_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.3-var_tmp_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.4-var_tmp_noexec_options` | /var/tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.4-var_tmp_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.5.4-var_tmp_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.1-var_log_mount` | /var/log is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.2.6.2-var_log_nodev_options` | /var/log is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.2-var_log_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.2-var_log_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.3-var_log_nosuid_options` | /var/log is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.3-var_log_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.3-var_log_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.4-var_log_noexec_options` | /var/log is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.4-var_log_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.6.4-var_log_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.1-var_log_audit_mount` | /var/log/audit is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.1.2.7.2-var_log_audit_nodev_options` | /var/log/audit is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.2-var_log_audit_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.2-var_log_audit_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.3-var_log_audit_nosuid_options` | /var/log/audit is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.3-var_log_audit_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.3-var_log_audit_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.4-var_log_audit_noexec_options` | /var/log/audit is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.4-var_log_audit_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.1.2.7.4-var_log_audit_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.2.1.1-gpg_keys` | gpg keys: rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary} | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.2.1.2-gpg_check_global` | gpg check global: grep -Pis -- '^\\h\*gpgcheck\\h\*=\\h\*(0\|false\|no\|off)\\b' /etc/zypp/zypp.conf /usr/etc/zypp/zy… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.2.1.3-repo_gpgcheck_global` | repo gpgcheck global: grep -E "^repo_gpgcheck" /etc/zypp/zypp.conf /etc/zypp/zypp.conf.d/\* | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.2.1.3-repo_gpgcheck_repo` | repo gpgcheck repo: if [ `find /etc/zypp/repos.d/ -type f -exec grep 'repo_gpgcheck\*' {} \\; \| grep -v '1\|on\|t… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.2.1.4-repos_configured` | repos configured: zypper repos | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.2.1.5-zypp_solver_only_requires-attrs` | /etc/zypp/zypp.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.2.1.5-zypp_solver_only_requires-content` | /etc/zypp/zypp.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.2.2.1-package-updates` | package updates: zypper lu | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.1-libselinux1_installed` | Package libselinux1 is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.2-grub_app_armor-attrs` | /etc/default/grub: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.2-grub_app_armor-content` | /etc/default/grub has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.2-selinux_boot_grub-attrs` | /etc/default/grub: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.2-selinux_boot_grub-content` | /etc/default/grub has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.3-selinux_targeted-attrs` | /etc/selinux/config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.3-selinux_targeted-content` | /etc/selinux/config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.4-mcstrans` | Package mcstrans is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.5-selinux_config_not_disabled-attrs` | /etc/selinux/config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.5-selinux_config_not_disabled-content` | /etc/selinux/config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.5-selinux_running_not_disabled` | selinux running not disabled: getenforce | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.6-selinux_config_enforcing-attrs` | /etc/selinux/config: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.3.1.6-selinux_config_enforcing-content` | /etc/selinux/config has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.3.1.6-selinux_running_enforcing` | selinux running enforcing: getenforce | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.3.1.7-setroubleshoot` | Package setroubleshoot is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.3.1.8-selinux_no_unconfined_services` | selinux no unconfined services: ps -eZ \| grep unconfined_service_t | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.4.2-grub_bootloaders_perms-attrs` | /boot/grub2/grub.cfg: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.1-fs_protected_hardlinks` | Kernel parameter fs.protected_hardlinks is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.1-fs_protected_hardlinks_conf` | fs protected hardlinks conf: grep "fs.protected_hardlinks" /etc/sysctl.conf /etc/sysctl.d/\* 2>/dev/null | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.2-fs_protected_symlinks` | Kernel parameter fs.protected_symlinks is 1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.5.2-fs_protected_symlinks_conf` | fs protected symlinks conf: grep "fs.protected_symlinks" /etc/sysctl.conf /etc/sysctl.d/\* 2>/dev/null | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-1.5.3-fs_suid_dumpable` | Kernel parameter fs.suid_dumpable is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.3-fs_suid_dumpable_conf` | fs suid dumpable conf: grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/\* 2>/dev/null | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.4-kernel_dmesg_restrict_running` | Kernel parameter kernel.dmesg_restrict is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.4-kernel_dmesg_restrict_conf` | kernel dmesg restrict conf: grep "kernel\\.dmesg_restrict" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.5-kernel_kptr_restrict_running` | Kernel parameter kernel.kptr_restrict is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.5-kernel_kptr_restrict_conf` | kernel kptr restrict conf: grep "kernel\\.kptr_restrict" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.6-kernel_randomize_va_space_running` | Kernel parameter kernel.randomize_va_space is 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.6-kernel_randomize_va_space_conf` | kernel randomize va space conf: grep "kernel\\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.7-kernel_yama_ptrace_scope_running` | Kernel parameter kernel.yama.ptrace_scope is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.7-kernel_yama_ptrace_scope_conf` | kernel yama ptrace scope conf: grep "kernel\\.yama\\.ptrace_scope" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.8-coredump_conf_d_processsizemax-attrs` | /etc/systemd/coredump.conf.d/60-cis.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.8-coredump_conf_d_processsizemax-content` | /etc/systemd/coredump.conf.d/60-cis.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.9-coredump_conf_d_storage-attrs` | /etc/systemd/coredump.conf.d/60-cis.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.5.9-coredump_conf_d_storage-content` | /etc/systemd/coredump.conf.d/60-cis.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.1-crypto_pkg_installed` | Package crypto-policies-scripts is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.2-crypto_policies_config` | crypto policies config: cat /etc/crypto-policies/config | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.3-crypto_policies_not_in_sshd` | crypto policies not in sshd: grep -Pi '^\\h\*CRYPTO_POLICY\\h\*=' /etc/sysconfig/ssh | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.4-crypto_policies_no_sha1_current-attrs` | /etc/crypto-policies/state/CURRENT.pol: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.4-crypto_policies_no_sha1_current-content` | /etc/crypto-policies/state/CURRENT.pol has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.5-crypto_policies_no_weakmacs-attrs` | /etc/crypto-policies/state/CURRENT.pol: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.5-crypto_policies_no_weakmacs-content` | /etc/crypto-policies/state/CURRENT.pol has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.6-crypto_policies_no_ssh_cbc-attrs` | /etc/crypto-policies/state/CURRENT.pol: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.6-crypto_policies_no_ssh_cbc-content` | /etc/crypto-policies/state/CURRENT.pol has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.7-crypto_policies_no_ssh_chacha-poly1305-attrs` | /etc/crypto-policies/state/CURRENT.pol: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.6.7-crypto_policies_no_ssh_chacha-poly1305-content` | /etc/crypto-policies/state/CURRENT.pol has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.1-check_motd_files` | check motd files: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.2-check_etc_issue` | check etc issue: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.3-check_etc_issue_net` | check etc issue net: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.4-pam_motd_configured` | pam motd configured: grep -Psi '^\\h\*session\\h+(required\|optional)\\h+pam_motd\\.so\\b.\*\\bmotd=' \\ | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.5-sshd_banner_content` | sshd banner content: b="$(sshd -T 2>/dev/null \| awk '$1 == "banner" {print $2}')" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.6-motd_access_configured` | motd access configured: find /etc/motd -maxdepth 0 \\( -perm /0133 -o ! -user root -o ! -group root \\) 2>/dev/null… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.7-etc_issue_access-attrs` | /etc/issue: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.8-etc_issue_net_access-attrs` | /etc/issue.net: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-1.7.9-sshd_banner_file_perms` | The SSH banner file is owned by root and not writable by others | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.1-autofs_pkg` | Package autofs is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.2-avahi_pkg` | Package avahi is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.3-dhcp_pkg` | Package dhcp-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.4-dns_pkg` | Package bind9 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.5-dnsmasq_pkg` | Package dnsmasq is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.6-samba_pkg` | Package samba is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.7-openldap2` | Package openldap2 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.7-openldap2_5` | Package openldap2_5 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.8-ftp_pkg` | Package vsftpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.9-cyrus_imapd_pkg` | Package cyrus-imapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.9-dovecot_pkg` | Package dovecot is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.11-cups_pkg` | Package cups is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.13-rsync_pkg` | Package rsync is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.14-snmp_pkg` | Package net-snmp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.15-telnet_pkg` | Package telnet-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.16-tftp_pkg` | Package tftp-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.17-squid_pkg` | Package squid is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.18-apache2_pkg` | Package apache2 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.18-nginx_pkg` | Package nginx is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.19-xinetd_pkg` | Package xinetd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.20-xwindow_pkg` | Package xwayland is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-2.1.21-mta_listening_port25` | mta listening port25: ss -lntu \| grep -E ":25\\s" \| grep -E -v "\\s(127.0.0.1\|\\[?::1\\]?):25\\s" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.1.21-postfix_inet_interfaces` | postfix inet interfaces: if command -v postconf >/dev/null 2>&1; then postconf inet_interfaces; else echo 'postfix… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.2.1-ftp_client` | Package ftp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.2.2-openldap2_6-client_removed` | Package openldap2_6-client is not installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-2.2.3-nis_client` | Package ypbind is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.2.4-telnet` | Package telnet is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.2.5-tftp-client` | Package tftp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.1-chrony_tool` | Package chrony is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.1-ntp` | Package ntp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.1-timesync_masked-attrs` | /etc/systemd/system/systemd-timesyncd.service: exists, is a symbolic link, links to /dev/null | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.1-chrony_runs_as_chrony_user` | chrony runs as chrony user: grep -Es '^\\s\*OPTIONS=' /etc/sysconfig/chronyd 2>/dev/null \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.1-chrony_time_source` | chrony time source: grep -Ers '^\\s\*(server\|pool)\\s+\\S+' /etc/chrony.conf /etc/chrony.d/ 2>/dev/null \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.2-chronyd-enabled` | Service chronyd is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.3.1.2-chronyd-running` | Service chronyd is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.1-cron` | Package cron is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.1-cron-enabled` | Service cron is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.1-cron-running` | Service cron is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.2-crontab_perms-attrs` | /etc/crontab: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.3-cron_hourly_perms-attrs` | /etc/cron.hourly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.4-cron_daily_perms-attrs` | /etc/cron.daily: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.5-cron_weekly_perms-attrs` | /etc/cron.weekly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.6-cron_monthly_perms-attrs` | /etc/cron.monthly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.7-cron_yearly_perms-attrs` | /etc/cron.yearly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.8-cron_d_perms-attrs` | /etc/cron.d: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.9-crontab_allow_restricted-attrs` | /etc/cron.allow: exists, mode 0640 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.1.9-crontab_deny_absent-absent` | /etc/cron.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.2.1-etc_at.allow-attrs` | /etc/at.allow: exists, mode 0640 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.2.1-at_deny_absent-absent` | /etc/at.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.3.1-timer_unit_perms` | timer unit perms: find /run/systemd/system /etc/systemd/system /usr/lib/systemd/system -type f -name '\*.tim… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.3.2-service_unit_perms` | service unit perms: find /run/systemd/system /etc/systemd/system /usr/lib/systemd/system -type f -name '\*.ser… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.3.3-systemd_dropin_dir_perms` | systemd dropin dir perms: find /run/systemd/system /etc/systemd/system /usr/lib/systemd/system -type d \\( ! -user r… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-2.4.3.4-systemd_user_linger` | systemd user linger: loginctl list-users --no-legend \| awk '$1 != 0 {print $2}' \| xargs -r -I{} sh -c 'loginct… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.1.1-ipv6_disabled-attrs` | /etc/sysctl.d/60-disable_ipv6.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.1.1-ipv6_disabled-content` | /etc/sysctl.d/60-disable_ipv6.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.1.2-wireless_disabled` | wireless disabled: if [ $(find /sys/class/net/\*/ -type d -name wireless) ]; then echo MANUAL; else echo OK; … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.1.3-bluetooth_pkg` | Package bluez is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.1-lsmod_atm` | lsmod atm: lsmod \| grep -i atm | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.1-modprobe_atm` | modprobe atm: modprobe -n -v atm | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.2-lsmod_can` | lsmod can: lsmod \| grep -i can | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.2-modprobe_can` | modprobe can: modprobe -n -v can | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.3-lsmod_dccp` | lsmod dccp: lsmod \| grep -i dccp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.3-modprobe_dccp` | modprobe dccp: modprobe -n -v dccp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.4-lsmod_tipc` | lsmod tipc: lsmod \| grep -i tipc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.4-modprobe_tipc` | modprobe tipc: modprobe -n -v tipc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.5-lsmod_rds` | lsmod rds: lsmod \| grep -i rds | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.5-modprobe_rds` | modprobe rds: modprobe -n -v rds | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.6-lsmod_sctp` | lsmod sctp: lsmod \| grep -i sctp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.2.6-modprobe_sctp` | modprobe sctp: modprobe -n -v sctp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.1-net_ipv4_ip_forward` | Kernel parameter net.ipv4.ip_forward is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.2-net_ipv4_conf_all_forwarding` | Kernel parameter net.ipv4.conf.all.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.3-net_ipv4_conf_default_forwarding` | Kernel parameter net.ipv4.conf.default.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.4-net_ipv4_conf_all_send_redirects` | Kernel parameter net.ipv4.conf.all.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.5-net_ipv4_conf_default_send_redirects` | Kernel parameter net.ipv4.conf.default.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.6-net_ipv4_icmp_ignore_bogus_error_respons` | Kernel parameter net.ipv4.icmp_ignore_bogus_error_responses is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.7-net_ipv4_icmp_echo_ignore_broadcasts` | Kernel parameter net.ipv4.icmp_echo_ignore_broadcasts is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.8-net_ipv4_conf_all_accept_redirects` | Kernel parameter net.ipv4.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.9-net_ipv4_conf_default_accept_redirects` | Kernel parameter net.ipv4.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.10-net_ipv4_conf_all_secure_redirects` | Kernel parameter net.ipv4.conf.all.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.11-net_ipv4_conf_default_secure_redirects` | Kernel parameter net.ipv4.conf.default.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.12-net_ipv4_conf_all_rp_filter` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.13-net_ipv4_conf_default_rp_filter` | Kernel parameter net.ipv4.conf.default.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.14-net_ipv4_conf_all_accept_source_route` | Kernel parameter net.ipv4.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.15-net_ipv4_conf_default_accept_source_rout` | Kernel parameter net.ipv4.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.16-net_ipv4_conf_all_log_martians` | Kernel parameter net.ipv4.conf.all.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.17-net_ipv4_conf_default_log_martians` | Kernel parameter net.ipv4.conf.default.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.18-net_ipv4_tcp_syncookies` | Kernel parameter net.ipv4.tcp_syncookies is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.1.19-net_ipv4_conf_lo_route_localnet` | Kernel parameter net.ipv4.conf.lo.route_localnet is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.1-net_ipv6_conf_all_forwarding` | Kernel parameter net.ipv6.conf.all.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.2-net_ipv6_conf_default_forwarding` | Kernel parameter net.ipv6.conf.default.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.3-net_ipv6_conf_all_accept_redirects` | Kernel parameter net.ipv6.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.4-net_ipv6_conf_default_accept_redirects` | Kernel parameter net.ipv6.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.5-net_ipv6_conf_all_accept_source_route` | Kernel parameter net.ipv6.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.6-net_ipv6_conf_default_accept_source_rout` | Kernel parameter net.ipv6.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.7-net_ipv6_conf_all_accept_ra` | Kernel parameter net.ipv6.conf.all.accept_ra is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-3.3.2.8-net_ipv6_conf_default_accept_ra` | Kernel parameter net.ipv6.conf.default.accept_ra is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-firewalld_installed` | Package firewalld is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-firewalld_started-enabled` | Service firewalld is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-firewalld_started-running` | Service firewalld is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-iptables_stopped-enabled` | Service iptables is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-iptables_stopped-running` | Service iptables is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-nftables_stopped-enabled` | Service nftables is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.1-nftables_stopped-running` | Service nftables is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.2-cis_4_1_2` | cis 4 1 2: grep -Pi -- '^\\h\*FirewallBackend\\h\*=\\h\*nftables\\b' /etc/firewalld/firewalld.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.3-firewalld-enabled` | Service firewalld is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.3-firewalld-running` | Service firewalld is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.4-cis_4_1_4` | cis 4 1 4: for z in $(firewall-cmd --get-active-zones 2>/dev/null \| awk '!/^ /{print $1}'); do i=$(f… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-4.1.5-cis_4_1_5_lo_zone` | cis 4 1 5 lo zone: firewall-cmd --get-zone-of-interface=lo | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.6-cis_4_1_6_ipv4` | cis 4 1 6 ipv4: firewall-cmd --zone trusted --list-rich-rules | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-4.1.8-cis_4_1_8` | cis 4 1 8: firewall-cmd --get-default-zone | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.1-sshd_config_perms-attrs` | /etc/ssh/sshd_config: mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.1-sshd_config_root_path_perms-attrs` | /usr/etc/ssh/sshd_config: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.1-sshd_config_d_file` | sshd config d file: find /etc/ssh/sshd_config.d /usr/etc/ssh/sshd_config.d -xdev -type f -name '\*.conf' \\( -p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.2-etc_ssh_ssh_host_prv_key_group` | /etc/ssh/ssh host prv key group: groupkeys=$(sudo find /etc/ssh/ -name \*_key -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.2-etc_ssh_ssh_host_prv_key_perms` | /etc/ssh/ssh host prv key perms: keyperms=$(sudo find /etc/ssh/ -name \*_key -type f -perm /137 ); echo $keyperms | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.2-etc_ssh_ssh_host_prv_key_user` | /etc/ssh/ssh host prv key user: userkeys=$(sudo find /etc/ssh/ -name \*_key -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.3-etc_ssh_ssh_host_pub_key_group` | /etc/ssh/ssh host pub key group: groupkeys=$(sudo find /etc/ssh/ -name \*_key.pub -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.3-etc_ssh_ssh_host_pub_key_perms` | /etc/ssh/ssh host pub key perms: find /etc/ssh/ -name '\*_key.pub' -type f -perm /133 \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.3-etc_ssh_ssh_host_pub_key_user` | /etc/ssh/ssh host pub key user: userkeys=$(sudo find /etc/ssh/ -name \*_key.pub -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.4-sshd_access_limited` | SSH access is limited with AllowUsers, AllowGroups, DenyUsers or DenyGroups | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.5-sshd_banner-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.5-ssh_configd_banner` | ssh configd banner: grep -Eis '^\\s\*Banner\\s+"?none\\b'/etc/ssh/sshd_config.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.6-no_weak_ssh_ciphers` | no weak ssh ciphers: sshd -T \| grep -Pi -- '^ciphers\\h+\\"?([^#\\n\\r]+,)?((3des\|aes(128\|192\|256))-cbc)\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.7-sshd_clientalive_live` | sshd clientalive live: sshd -T \| grep -i '^clientalive' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.8-ssh_disable_forward_live` | ssh disable forward live: sshd -T \| grep -i '^disableforwarding' | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.9-ssh_gssapi_live` | ssh gssapi live: sshd -T \| grep -i gssapiauthentication | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.10-ssh_hostbased_auth_live` | ssh hostbased auth live: sshd -T \| grep -i '^hostbasedauthentication' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.11-ssh_rhosts_live` | ssh rhosts live: sshd -T \| grep -i '^ignorerhosts' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.12-no_weak_ssh_kex` | no weak ssh kex: sshd -T \| grep -Pi -- 'kexalgorithms\\h+([^#\\n\\r]+,)?(diffie-hellman-group1-sha1\|diffie-he… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.13-ssh_logingrace_live` | ssh logingrace live: sshd -T \| grep -i '^logingracetime' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.14-ssh_loglevel_live` | ssh loglevel live: sshd -T \| grep -i '^loglevel' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.15-no_weak_ssh_macs` | no weak ssh macs: sshd -T \| grep -Pi -- 'macs\\h+([^#\\n\\r]+,)?(hmac-md5\|hmac-md5-96\|hmac-ripemd160\|hmac-sha1… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.16-sshd_authtries` | sshd authtries: sshd -T 2>/dev/null \| grep -i '^maxauthtries' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.17-ssh_maxstartups` | ssh maxstartups: sshd -T 2>/dev/null \| grep -i '^maxstartups' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.18-ssh_maxsessions` | ssh maxsessions: sshd -T 2>/dev/null \| grep -i '^maxsessions' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.19-ssh_empty_passwd` | ssh empty passwd: sshd -T 2>/dev/null \| grep -i '^permitemptypasswords' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.20-ssh_permit_root` | ssh permit root: sshd -T 2>/dev/null \| grep -i '^permitrootlogin' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.21-ssh_userenv` | ssh userenv: sshd -T 2>/dev/null \| grep -i '^permituserenvironment' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.22-ssh_usepam` | ssh usepam: sshd -T 2>/dev/null \| grep -i '^usepam' \|\| true | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.23-ssh_pq_kex_sntrup761` | ssh pq kex sntrup761: sshd -T \| awk '(tolower($1)=="kexalgorithms" && $2~/sntrup761x25519-sha512/) {print $2}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.1.24-ssh_listen_address` | ssh listen address: sshd -T \| grep -i '^listenaddress' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.2.1-sudo_pkg` | Package sudo is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.2-pty_sudoers_d` | pty sudoers d: export PTY=`grep -q -Ei '^\\s\*Defaults\\s+(\\[^#]+,\\s\*)?use_pty' /etc/sudoers /etc/sudoers.d… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.3-log_sudoers_d` | log sudoers d: export LOG=`grep -q -Esi '^\\s\*Defaults\\s+([^#]+,\\s\*)?logfile=' /etc/sudoers /etc/sudoers.… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.4-nopasswd_sudoers_d` | nopasswd sudoers d: grep -R NOPASSWD /etc/sudoers /etc/sudoers.d/\* \| grep -v '.\*\\:#' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.2.5-authenticate_sudoers` | authenticate sudoers: grep -r "^[^#].\*\\!authenticate" /etc/sudoers\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.6-sudo_timeout` | sudo timeout: grep -rP "timestamp_timeout=\\K[0-9]\*" /etc/sudoers\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.7-restrict_su-attrs` | /etc/pam.d/su: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.7-restrict_su-content` | /etc/pam.d/su has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.2.7-sugroup_etc_group` | The group that pam_wheel allows to use su has no members | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.1.1-pam_version` | Package pam is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.1.1-pam_version-version` | Package pam version >= 1.3.0-150000.6.71.2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.1.1-faillock_attempts_deny-attrs` | /etc/security/faillock.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.1.1-faillock_attempts_deny-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.1.2-faillock_unlock_time-attrs` | /etc/security/faillock.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.1.2-faillock_unlock_time-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.1.3-faillock_root_unlock_time-attrs` | /etc/security/faillock.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.3.2.1.3-faillock_root_unlock_time-content` | /etc/security/faillock.conf has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.3.2.2.1-dict_check_not_pam` | dict check not pam: grep -Psi -- '^\\h\*dictcheck\\h\*=\\h\*0\\b' /etc/security/pwquality.conf /etc/security/pwquali… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.2.2-difok_check_not_pam` | difok check not pam: grep -Psi -- '^\\h\*difok\\h\*=\\h\*([2-9]\|[1-9][0-9]+)\\b' /etc/security/pwquality.conf /etc/se… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.2.3-minlen_check_not_pam` | minlen check not pam: grep -Psi -- '^\\h\*minlen\\h\*=\\h\*(1[4-9]\|[2-9][0-9]\|[1-9][0-9]{2,})\\b' /etc/security/pwqual… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.2.4-passwd_complex_check_not_pam` | passwd complex check not pam: grep -Psi -- '^\\h\*(minclass\|[dulo]credit)\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.2.5-maxrepeat_check_not_pam` | maxrepeat check not pam: grep 'maxrepeat' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.2.6-maxsequence_check_not_pam` | maxsequence check not pam: grep 'maxsequence' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.2.7-enforce_for_root_check_not_pam` | enforce for root check not pam: grep 'enforce_for_root' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.3.1-pwhistory_remember_use_pam` | pwhistory remember use pam: pam-config --query --pwhistory --pwhistory-remember | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.3.2-pwhistory_remember_root_use_pam` | pwhistory remember root use pam: pam-config --query --pwhistory --pwhistory-enforce_for_root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.3.3-pwhistory_authtok_use_pam` | pwhistory authtok use pam: grep -P -- '^\\h\*password\\h+([^#\\n\\r]+)\\h+pam_pwhistory\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.4.1-pam_unix_nullok` | pam unix nullok: pam-config --query --unix --unix-nullok | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.4.2-pam_unix_remember_root` | pam unix remember root: grep -Pi '^\\h\*password\\h+([^#\\n\\r]+\\h+)?pam_unix\\.so\\b' /etc/pam.d/\* \| grep -Pv '\\brememb… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.4.3-pam_unix_password_use_pam` | pam unix password use pam: pam-config --query --unix --unix-sha512 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.3.2.4.4-pam_unix_authtok` | pam unix authtok: grep -P -- '^\\h\*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b' /et… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.1-login_defs_max_days-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.1-login_defs_max_days-content` | /etc/login.defs has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.1-check_user_expiry` | check user expiry: grep -E '^[^:]+:[^!\*]' /etc/shadow \| cut -d: -f1,5 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.2-login_defs_min_days-attrs` | /etc/login.defs: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.4.1.2-login_defs_min_days-content` | /etc/login.defs has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.4.1.2-check_users_MIN_DAYS` | check users MIN DAYS: grep -E '^[^:]+:[^!\*]' /etc/shadow \| cut -d: -f1,4 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.4.1.3-login_defs_warn_age-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.3-login_defs_warn_age-content` | /etc/login.defs has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.3-check_users_MAX_DAYS` | check users MAX DAYS: grep -E '^[^:]+:[^!\*]' /etc/shadow \| cut -d: -f1,6 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.4-login_defs_hashing-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.4-login_defs_hashing-content` | /etc/login.defs has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.5-inactive_passwd` | inactive passwd: useradd -D \| grep INACTIVE | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.5-inactive_users` | inactive users: awk -F':' '($2~/^\\\\$.+\\\\$/) {if($7 > 45 \|\| $7 < 0)print $1 }' /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.1.6-passwd_chg_past` | No user has a last password change date in the future | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.1-uid_0_check` | uid 0 check: awk -F: '($3 == 0) { print $1 }' /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.2-gid_0_check` | gid 0 check: awk -F: '($1 !~ /^(root\|sync\|shutdown\|halt\|operator)$/ && $4 == 0) {print $1}' /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.3-group_root_only_0` | group root only 0: awk -F: '$3=='0'{print $1":"$3}' /etc/group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.4-root_passwd_set` | root passwd set: passwd -S root \| awk '$2 ~ /^P/ {print "OK Password"}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.5-root_path_check` | root path check: /bin/bash --login -c 'env \| grep ^PATH=' \| sed -e 's/PATH=//' -e 's/::/:/' -e 's/:$//' -e… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.6-root_umask_bash_profile` | root umask bash profile: grep -i umask /root/.bash_profile /root/bashrc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.7-secure_system_accts` | secure system accts: awk -F: '$3<1000' /etc/passwd \| grep -Ev 'root\|sync\|halt\|shutdown\|nfsnobody\|/sbin/nologin… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.2.8-invalid_shell_lock_accts` | invalid shell lock accts: l_valid_shells="^($(awk -F\\/ '$NF != "nologin" {print}' /etc/shells \| sed -rn '/^\\//{s,/,… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.3.1-nologin_not_in_shells-attrs` | /etc/shells: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.4.3.1-nologin_not_in_shells-content` | /etc/shells has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-5.4.3.2-check_timeout` | check timeout: grep TMOUT /etc/profile.d/\*.sh /etc/profile /etc/profile.d/\*.sh\| cut -d ":" -f2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.3.3-umask_profile_scripts` | umask profile scripts: grep -i "^\\s\*umask" /etc/profile /etc/profile.d/\*.sh /etc/login.defs /etc/default/login /… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-5.4.3.4-umask_profile_d` | umask profile d: grep -Pi -- '^\\h\*umask\\h+0[2-7][7]\\b' /etc/profile.d/60-default_umask.sh | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.1-systemd-journald-enabled` | Service systemd-journald is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.1-systemd-journald-running` | Service systemd-journald is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.2-systemd-journal-remote.service-enabled` | Service systemd-journal-remote.service is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.2-systemd-journal-remote.service-running` | Service systemd-journal-remote.service is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.2-systemd-journal-remote.socket-enabled` | Service systemd-journal-remote.socket is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.2-systemd-journal-remote.socket-running` | Service systemd-journal-remote.socket is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.2-journald_remote_service_masked` | journald remote service masked: systemctl is-enabled systemd-journal-remote.service | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.2-journald_remote_socket_masked` | journald remote socket masked: systemctl is-enabled systemd-journal-remote.socket | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.3-journald_compress` | journald compress: grep -i compress /etc/systemd/journald.conf /etc/systemd/journald.conf.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.1.4-journald_storage` | journald storage: grep -i storage /etc/systemd/journald.conf /etc/systemd/journald.conf.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.2.1-rsyslog` | Package rsyslog is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.2.2-rsyslog-enabled` | Service rsyslog is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.2.2-rsyslog-running` | Service rsyslog is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.2.4-rsyslog_filecreatemode` | rsyslog filecreatemode: grep -P '^\\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.2.7-rsyslog_no_imtcp` | rsyslog no imtcp: grep -P '^\\s\*\\$ModLoad\\s+imtcp\|^\\s\*\\$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.2.9-rsyslog-module-gtls` | Package rsyslog-module-gtls is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.1.2.10-rsyslog_gtls_configured` | rsyslog gtls configured: grep -P '^\\$DefaultNetstreamDriver\\s+gtls' /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_cloud_init` | logfile permissions cloud init: find /var/log -type f -regextype posix-extended -regex '/var/log/(cloud-init\\.log.\*\|local… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_default` | logfile permissions default: find /var/log -type f -regextype posix-extended -not -regex '/var/log/apt/.\*' -not -regex… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_gdm` | logfile permissions gdm: find /var/log -type f -regextype posix-extended -regex '.\*/(gdm\|gdm3)(/.\*)?' \\( -perm /01… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_journal` | logfile permissions journal: find /var/log -type f -regextype posix-extended -regex '.\*\\.journal~?' \\( -perm /0137 -o … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_secure` | logfile permissions secure: find /var/log -type f -regextype posix-extended -regex '.\*/(secure(,.\*\|\\..\*\|-.\*)?\|auth\\.l… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_sssd` | logfile permissions sssd: find /var/log -type f -regextype posix-extended -regex '.\*/(sssd\|SSSD)(/.\*)?' \\( -perm /0… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_tmp` | logfile permissions tmp: find /var/log -type f -regextype posix-extended -regex '/var/log/((u\|b\|w)tmp.\*\|lastlog.\*\|… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.1.3.1-logfile_permissions_zypp` | logfile permissions zypp: find /var/log/zypp /var/log/zypper.log -type f \\( -perm /0133 -o -not -user root -o \\( -n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.2.1.1-audit_packages` | Package audit is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.1.2-auditd_service-enabled` | Service auditd.service is enabled | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.1.2-auditd_service-running` | Service auditd.service is running | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.1.3-audit_default_grub` | audit default grub: grep audit= /etc/default/grub | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.1.3-audit_running_grub` | audit running grub: grep audit= /proc/cmdline | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.1.4-audit_backlog_default_grub` | audit backlog default grub: grep audit_backlog /etc/default/grub | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.1.4-audit_backlog_running_grub` | audit backlog running grub: grep audit_backlog /proc/cmdline | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.2.1-auditd_log_size` | auditd log size: grep -Po -- '^\\h\*max_log_file\\h\*=\\h\*\\d+\\b' /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.2.2-max_log_action_auditd_conf` | max log action auditd conf: grep max_log_file_action /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.2.3-logs_full_auditd_conf-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.2.3-logs_full_auditd_conf-content` | /etc/audit/auditd.conf has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.2.4-logs_low_space_auditd_conf` | logs low space auditd conf: grep space_left_action /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.1-cis_6_2_3_1_cnf` | cis 6 2 3 1 cnf: grep -E -- 'path=/etc/sudoers\|dir=/etc/sudoers.d' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.1-cis_6_2_3_1_live` | cis 6 2 3 1 live: auditctl -l \| grep 'sudoers' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.2-cis_6_2_3_2_cnf` | cis 6 2 3 2 cnf: grep -E -- 'user_emulation' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.2-cis_6_2_3_2_live` | cis 6 2 3 2 live: auditctl -l \| grep user_emulation | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.3-cis_6_2_3_3_cnf` | cis 6 2 3 3 cnf: grep -E -- 'sudo_log_file' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.3-cis_6_2_3_3_live` | cis 6 2 3 3 live: auditctl -l \| grep sudo_log_file | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.4-cis_6_2_3_4_cnf` | cis 6 2 3 4 cnf: grep -E -- 'time-change\|/etc/localtime' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.4-cis_6_2_3_4_live` | cis 6 2 3 4 live: auditctl -l \| grep -E -- 'time-change\|/etc/localtime' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.5-cis_6_2_3_5_cnf` | cis 6 2 3 5 cnf: grep -E -- 'sethostname\|setdomainname' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.5-cis_6_2_3_5_live` | cis 6 2 3 5 live: auditctl -l \| grep -E -- 'sethostname\|setdomainname' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.6-cis_6_2_3_6_cnf` | cis 6 2 3 6 cnf: grep -E -- 'path=/etc/issue' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.6-cis_6_2_3_6_live` | cis 6 2 3 6 live: auditctl -l \| grep -E -- 'path=/etc/issue' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.7-cis_6_2_3_7_cnf` | cis 6 2 3 7 cnf: grep -E -- 'path=/etc/host' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.7-cis_6_2_3_7_live` | cis 6 2 3 7 live: auditctl -l \| grep -E -- 'path=/etc/host' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.8-cis_6_2_3_8_cnf` | cis 6 2 3 8 cnf: grep -E -- 'dir=/etc/NetworkManager/' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.8-cis_6_2_3_8_live` | cis 6 2 3 8 live: auditctl -l \| grep -E -- 'dir=/etc/NetworkManager/' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.9-cis_6_2_3_9_cnf` | cis 6 2 3 9 cnf: grep -E -- '-k privileged' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.9-cis_6_2_3_9_live` | cis 6 2 3 9 live: auditctl -l \| grep -E -- 'key=privileged' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.10-cis_6_2_3_10_cnf` | cis 6 2 3 10 cnf: grep -E -- 'arch=b64.\*-k access' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.10-cis_6_2_3_10_live` | cis 6 2 3 10 live: auditctl -l \| grep -E -- 'arch=b64.\*key=access' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.11-cis_6_2_3_11_cnf` | cis 6 2 3 11 cnf: grep -E -- 'path=/etc/group' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.11-cis_6_2_3_11_live` | cis 6 2 3 11 live: auditctl -l \| grep -E -- 'path=/etc/group' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.12-cis_6_2_3_12_cnf` | cis 6 2 3 12 cnf: grep -E -- 'path=/etc/passwd' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.12-cis_6_2_3_12_live` | cis 6 2 3 12 live: auditctl -l \| grep -E -- 'path=/etc/passwd' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.13-cis_6_2_3_13_cnf` | cis 6 2 3 13 cnf: grep -E -- 'path=/etc/shadow' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.13-cis_6_2_3_13_live` | cis 6 2 3 13 live: auditctl -l \| grep -E -- 'path=/etc/shadow' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.14-cis_6_2_3_14_cnf` | cis 6 2 3 14 cnf: grep -E -- 'path=/etc/security/opasswd' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.14-cis_6_2_3_14_live` | cis 6 2 3 14 live: auditctl -l \| grep -E -- 'path=/etc/security/opasswd' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.15-cis_6_2_3_15_cnf` | cis 6 2 3 15 cnf: grep -E -- 'dir=/etc/pam.d/' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.15-cis_6_2_3_15_live` | cis 6 2 3 15 live: auditctl -l \| grep -E -- 'dir=/etc/pam.d/' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.16-cis_6_2_3_16_cnf` | cis 6 2 3 16 cnf: grep -E -- 'arch=b64.\*chmod.\*-k perm_mod' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.16-cis_6_2_3_16_live` | cis 6 2 3 16 live: auditctl -l \| grep -E -- 'arch=b64.\*chmod.\*key=perm_mod' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.17-cis_6_2_3_17_cnf` | cis 6 2 3 17 cnf: grep -E -- 'arch=b64.\*chown.\*-k perm_mod' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.17-cis_6_2_3_17_live` | cis 6 2 3 17 live: auditctl -l \| grep -E -- 'arch=b64.\*chown.\*key=perm_mod' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.18-cis_6_2_3_18_cnf` | cis 6 2 3 18 cnf: grep -E -- 'arch=b64.\*setxattr.\*-k perm_mod' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.18-cis_6_2_3_18_live` | cis 6 2 3 18 live: auditctl -l \| grep -E -- 'arch=b64.\*setxattr.\*key=perm_mod' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.19-cis_6_2_3_19_cnf` | cis 6 2 3 19 cnf: grep -E -- 'arch=b64.\*mount.\*-k mounts' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.19-cis_6_2_3_19_live` | cis 6 2 3 19 live: auditctl -l \| grep -E -- 'arch=b64.\*mount.\*key=mounts' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.20-cis_6_2_3_20_cnf` | cis 6 2 3 20 cnf: grep -E -- 'path=/var/run/utmp' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.20-cis_6_2_3_20_live` | cis 6 2 3 20 live: auditctl -l \| grep -E -- 'path=/var/run/utmp' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.21-cis_6_2_3_21_cnf` | cis 6 2 3 21 cnf: grep -E -- 'path=/var/log/lastlog' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.21-cis_6_2_3_21_live` | cis 6 2 3 21 live: auditctl -l \| grep -E -- 'path=/var/log/lastlog' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.22-cis_6_2_3_22_cnf` | cis 6 2 3 22 cnf: grep -E -- 'arch=b64.\*unlink.\*-k delete' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.22-cis_6_2_3_22_live` | cis 6 2 3 22 live: auditctl -l \| grep -E -- 'arch=b64.\*unlink.\*key=delete' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.23-cis_6_2_3_23_cnf` | cis 6 2 3 23 cnf: grep -E -- 'arch=b64.\*rename.\*-k delete' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.23-cis_6_2_3_23_live` | cis 6 2 3 23 live: auditctl -l \| grep -E -- 'arch=b64.\*rename.\*key=delete' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.24-cis_6_2_3_24_cnf` | cis 6 2 3 24 cnf: grep -E -- 'path=/etc/selinux' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.24-cis_6_2_3_24_live` | cis 6 2 3 24 live: auditctl -l \| grep -E -- 'path=/etc/selinux' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.25-cis_6_2_3_25_cnf` | cis 6 2 3 25 cnf: grep -E -- 'path=/usr/bin/chcon' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.25-cis_6_2_3_25_live` | cis 6 2 3 25 live: auditctl -l \| grep -E -- 'path=/usr/bin/chcon' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.26-cis_6_2_3_26_cnf` | cis 6 2 3 26 cnf: grep -E -- 'path=/usr/bin/setfacl' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.26-cis_6_2_3_26_live` | cis 6 2 3 26 live: auditctl -l \| grep -E -- 'path=/usr/bin/setfacl' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.27-cis_6_2_3_27_cnf` | cis 6 2 3 27 cnf: grep -E -- 'path=/usr/bin/chacl' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.27-cis_6_2_3_27_live` | cis 6 2 3 27 live: auditctl -l \| grep -E -- 'path=/usr/bin/chacl' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.28-cis_6_2_3_28_cnf` | cis 6 2 3 28 cnf: grep -E -- 'path=/usr/sbin/usermod' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.28-cis_6_2_3_28_live` | cis 6 2 3 28 live: auditctl -l \| grep -E -- 'path=/usr/sbin/usermod' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.29-cis_6_2_3_29_cnf` | cis 6 2 3 29 cnf: grep -E -- 'path=/usr/bin/kmod' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.29-cis_6_2_3_29_live` | cis 6 2 3 29 live: auditctl -l \| grep -E -- 'path=/usr/bin/kmod' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.30-cis_6_2_3_30_cnf` | cis 6 2 3 30 cnf: grep -E -- 'arch=b64.\*init_module.\*-k kernel_modules' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.30-cis_6_2_3_30_live` | cis 6 2 3 30 live: auditctl -l \| grep -E -- 'arch=b64.\*init_module.\*key=kernel_modules' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.31-cis_6_2_3_31_cnf` | cis 6 2 3 31 cnf: grep -E -- 'arch=b64.\*delete_module.\*-k kernel_modules' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.31-cis_6_2_3_31_live` | cis 6 2 3 31 live: auditctl -l \| grep -E -- 'arch=b64.\*delete_module.\*key=kernel_modules' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.32-cis_6_2_3_32_cnf` | cis 6 2 3 32 cnf: grep -E -- 'arch=b64.\*create_module.\*-k kernel_modules' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.32-cis_6_2_3_32_live` | cis 6 2 3 32 live: auditctl -l \| grep -E -- 'arch=b64.\*create_module.\*key=kernel_modules' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.33-cis_6_2_3_33_cnf` | cis 6 2 3 33 cnf: grep -Ph -- '^\\h\*-c\\b' /etc/audit/rules.d/\*.rules \| tail -1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.3.34-cis_6_2_3_34_cnf` | cis 6 2 3 34 cnf: grep -Ph -- '^\\h\*-e\\h+2\\b' /etc/audit/rules.d/\*.rules \| tail -1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.1-auditd_log_directory_mode` | auditd log directory mode: d="$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}' /etc/audit/auditd.conf 2>/dev/null … | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.1-auditd_log_group_configured` | auditd log group configured: grep -Psi -- '^\\h\*log_group\\h\*=\\h\*(root\|adm)\\b' /etc/audit/auditd.conf \|\| true | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.2-cis_6_2_4_2` | cis 6 2 4 2: [ -f /etc/audit/auditd.conf ] && find "$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}'… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.3-cis_6_2_4_3` | cis 6 2 4 3: [ -f /etc/audit/auditd.conf ] && find "$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}'… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.4-cis_6_2_4_4_conf` | cis 6 2 4 4 conf: grep -Pi -- '^\\h\*log_group\\h\*=\\h\*(root\|audit)\\b' /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.5-cis_6_2_4_5` | cis 6 2 4 5: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) -perm /0137 2>/dev/null | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.6-cis_6_2_4_6` | cis 6 2 4 6: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -user root 2>/dev/null | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.7-cis_6_2_4_7` | cis 6 2 4 7: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -group root 2>/dev/null | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.8-sbin_auditctl-attrs` | /sbin/auditctl: exists, mode 0755 or stricter | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.8-sbin_auditd-attrs` | /sbin/auditd: exists, mode 0755 or stricter | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.8-sbin_augenrules-attrs` | /sbin/augenrules: exists, mode 0755 or stricter | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.8-sbin_aureport-attrs` | /sbin/aureport: exists, mode 0755 or stricter | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.8-sbin_ausearch-attrs` | /sbin/ausearch: exists, mode 0755 or stricter | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.9-sbin_auditctl_mode-attrs` | /sbin/auditctl: exists, owner root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.9-sbin_auditd_mode-attrs` | /sbin/auditd: exists, owner root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.9-sbin_augenrules_mode-attrs` | /sbin/augenrules: exists, owner root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.9-sbin_aureport_mode-attrs` | /sbin/aureport: exists, owner root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.9-sbin_ausearch_mode-attrs` | /sbin/ausearch: exists, owner root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.10-sbin_auditctl_group-attrs` | /sbin/auditctl: exists, group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.10-sbin_auditd_group-attrs` | /sbin/auditd: exists, group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.10-sbin_augenrules_group-attrs` | /sbin/augenrules: exists, group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.10-sbin_aureport_group-attrs` | /sbin/aureport: exists, group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.2.4.10-sbin_ausearch_group-attrs` | /sbin/ausearch: exists, group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.3.1-aide` | Package aide is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.3.2-etc_cron.d_aide_cron-attrs` | /etc/cron.d/aide_cron: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-6.3.3-aide_audit_tools-attrs` | /etc/aide.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-6.3.3-aide_audit_tools-content` | /etc/aide.conf has the expected content (5 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-SUSE16-7.1.1-passwd_perms-attrs` | /etc/passwd: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.2-passwd-_perms-attrs` | /etc/passwd-: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.3-group_perms-attrs` | /etc/group: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.4-group-_perms-attrs` | /etc/group-: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.5-shadow_perms-attrs` | /etc/shadow: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.6-shadow-_perms-attrs` | /etc/shadow-: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.7-gshadow_perms-attrs` | /etc/gshadow: mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.8-gshadow-_perms-attrs` | /etc/gshadow-: mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.9-etc_shells_perms-attrs` | /etc/shells: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.10-etc_security_opasswd_perms-attrs` | /etc/security/opasswd: mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.11-world_writable` | world writable: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.12-unowned_dirs` | No file or directory is without an owner or a group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.1.13-audit_sgid` | audit sgid: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.1-shadowed_passwds-attrs` | /etc/passwd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.1-shadowed_passwds-content` | /etc/passwd has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.2-passwd_fields_not_empty_shadow-attrs` | /etc/shadow: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.2-passwd_fields_not_empty_shadow-content` | /etc/shadow has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.3-passwd_group_exist` | passwd group exist: awk -F: '{print $4}' /etc/passwd \|sort -u > /tmp/uid && awk -F: '{print $3}' /etc/group\| … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.4-no_dup_uid` | no dup uid: cat /etc/passwd \| cut -d: -f3 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.5-no_dup_gid` | no dup gid: cat /etc/group \| cut -d: -f3 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.6-no_dup_username` | no dup username: cat /etc/passwd \| cut -d: -f1 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.7-no_dup_groupname` | no dup groupname: cat /etc/group \| cut -d: -f1 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.8-home_dirs_exist` | home dirs exist: for i in `cat /etc/passwd \| grep -Ev "halt\|sync\|shutdown\|nfsnobody\|nologin\|false" \| cut -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.8-home_dirs_ownership` | home dirs ownership: awk -F: '$3 >= 1000 && $3 <= 60000 { print $1 " " $6 }' /etc/passwd \| while read user dir… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.8-home_dirs_permissions` | home dirs permissions: export def_home=`grep "^HOME=" /etc/default/useradd \|cut -d= -f2` && for i in `ls $def_ho… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.9-bad_dot_files` | bad dot files: find /home/ -name "\\.forward" -o -name "\\.netrc" -o -name "\\.rhosts" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.9-dot_file_bash_history` | dot file bash history: find /home/ -name "\\.bash_history" -perm /go+rwx | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.9-dot_file_perms` | dot file perms: find /home/ -name "\\.\*" -perm /g+w,o+w \| grep -v .bash_history | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-SUSE16-7.2.10-cis_7_2_10` | cis 7 2 10: awk -F: '($2 != "x" && $2 != "!" && $2 != "") { print $1 }' /etc/group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |

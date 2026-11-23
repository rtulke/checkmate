# CIS Ubuntu 22.04 LTS

Automated checks for 280 recommendations of the CIS Ubuntu 22.04 LTS benchmark (version 3.0.0), converted from the goss audit content of the ansible-lockdown project. Check names describe what is verified; the recommendation number is in the ID and the description. Select profiles with tags, e.g. `--tags cis-level-1+cis-server`.

**Policy:** [`cis/ubuntu22.yml`](https://github.com/rtulke/checkmate/blob/main/cis/ubuntu22.yml) · **Benchmark version:** 3.0.0

```bash
checkmate run cis/ubuntu22.yml --tags cis-level1-server
checkmate run cis/ubuntu22.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-UBUNTU22-1.1.1.1-cramfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.1-cramfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.1-cramfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.1-cramfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.2-freevxfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.2-freevxfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.2-freevxfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.2-freevxfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.3-hfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.3-hfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.3-hfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.3-hfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.4-hfsplus_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.4-hfsplus_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.4-hfsplus_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.4-hfsplus_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.5-jffs2_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.5-jffs2_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.5-jffs2_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.5-jffs2_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.6-overlay_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.6-overlay_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.6-overlay_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.6-overlay_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.8-udf_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.8-udf_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.8-udf_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.8-udf_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.1.9-usb-storage_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.9-usb-storage_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.9-usb-storage_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.9-usb-storage_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.10-cve_fs` | cve fs: /var/fs_with_cves.sh | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.11-firewire-core_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.11-firewire-core_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.11-firewire-core_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.1.11-firewire-core_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.1-tmp_mount` | /tmp is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.2-tmp_options_nodev` | /tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.2-tmp_fstab_nodev_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.2-tmp_fstab_nodev_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.3-tmp_nosuid_options` | /tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.3-tmp_fstab_nosuid_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.3-tmp_fstab_nosuid_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.4-tmp_noexec_options` | /tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.4-tmp_fstab_noexec_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.1.4-tmp_fstab_noexec_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.1-dev_shm_mount` | /dev/shm is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.2-dev_shm_nodev_options` | /dev/shm is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.2-dev_shm_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.2-dev_shm_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.3-dev_shm_nosuid_options` | /dev/shm is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.3-dev_shm_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.3-dev_shm_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.4-dev_shm_noexec_options` | /dev/shm is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.4-dev_shm_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.2.4-dev_shm_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.3.1-home_mount` | /home is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.2.3.2-home_nodev_options` | /home is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.3.2-home_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.3.2-home_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.3.3-home_nosuid_options` | /home is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.3.3-home_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.3.3-home_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.4.1-var_mount` | /var is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.2.4.2-var_nodev_options` | /var is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.4.2-var_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.4.2-var_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.4.3-var_nosuid_options` | /var is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.4.3-var_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.4.3-var_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.1-var_tmp_mount` | /var/tmp is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.2.5.2-var_tmp_nodev_options` | /var/tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.2-var_tmp_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.2-var_tmp_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.3-var_tmp_nosuid_options` | /var/tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.3-var_tmp_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.3-var_tmp_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.4-var_tmp_noexec_options` | /var/tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.4-var_tmp_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.5.4-var_tmp_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.1-var_log_mount` | /var/log is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.2.6.2-var_log_nodev_options` | /var/log is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.2-var_log_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.2-var_log_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.3-var_log_nosuid_options` | /var/log is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.3-var_log_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.3-var_log_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.4-var_log_noexec_options` | /var/log is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.4-var_log_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.6.4-var_log_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.1-var_log_audit_mount` | /var/log/audit is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.1.2.7.2-var_log_audit_nodev_options` | /var/log/audit is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.2-var_log_audit_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.2-var_log_audit_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.3-var_log_audit_nosuid_options` | /var/log/audit is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.3-var_log_audit_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.3-var_log_audit_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.4-var_log_audit_noexec_options` | /var/log/audit is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.4-var_log_audit_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.1.2.7.4-var_log_audit_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.2.1.1-gpg_keys_list` | gpg keys list: echo "MANUAL - Please check manually for gpg keys" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.2.1.2-gpg_configd` | gpg configd: echo "MANUAL - Please check manually that repositories are configured as expected" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.2.2.1-check_updates` | check updates: apt update 2>&1 \| grep -q 'All packages are up to date.' && echo OK \|\| apt --simulate upg… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.1-apparmor` | Package apparmor is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.2-apparmor_boot_grub-attrs` | /boot/grub/grub.cfg: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.2-apparmor_boot_grub-content` | /boot/grub/grub.cfg has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.2-grub_app_armor-attrs` | /etc/default/grub: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.2-grub_app_armor-content` | /etc/default/grub has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.3-apparmor_enf_or_comp` | apparmor enf or comp: LOADED=`apparmor_status \| grep 'profiles are loaded' \| awk '{print $1}'` && ENFORCE=`appa… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.3.1.4-apparmor_enf_only` | apparmor enf only: if [ "`apparmor_status \| grep 'profiles are in complain mode.' \| awk '{print $1}'`" != "0… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-1.4.1-bootloader_password_set-attrs` | /etc/grub.d/00_user: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.4.1-bootloader_password_set-content` | /etc/grub.d/00_user has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.4.2-default_grub_perms-attrs` | /boot/grub/grub.cfg: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.1-kernel.randomize_va_space` | Kernel parameter kernel.randomize_va_space is 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.1-aslr_enabled_2` | aslr enabled 2: grep "kernel\\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.2-kernel.yama.ptrace_scope` | Kernel parameter kernel.yama.ptrace_scope is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.2-ptrace_restrict_2` | ptrace restrict 2: grep "kernel\\.yama\\.ptrace_scope" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.3-fs.suid_dumpable` | Kernel parameter fs.suid_dumpable is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.3-suid_dumpable_2` | suid dumpable 2: grep "fs\\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.4-core_dumps_limits` | core dumps limits: grep -E "\\\*.\*hard.\*core.\*0" /etc/security/limits.conf /etc/security/limits.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.5-prelink` | Package prelink is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.6-apport` | Package apport is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.6-error_report_apport_disable-attrs` | /etc/default/apport: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.5.6-error_report_apport_disable-content` | /etc/default/apport has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.1-disable_dyn_motd-attrs` | /etc/pam.d/sshd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.1-disable_dyn_motd-content` | /etc/pam.d/sshd has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.1-etc_motd_content-content` | /etc/motd has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.2-local_login_banner` | local login banner: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.3-cremote_login_banner` | cremote login banner: grep -Eis "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.4-motd_perms-attrs` | /etc/motd: mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.5-etc_issue_perms-attrs` | /etc/issue: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.6.6-etc_issue_net_perms-attrs` | /etc/issue.net: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-1.7.1-gdm3` | Package gdm3 is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-2.1.1-autofs_masked-attrs` | /etc/systemd/system/autofs.service: exists, is a symbolic link, links to /dev/null | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.2-avahi_pkg` | Package avahi is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.3-dhcp_pkg` | Package isc-dhcp-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.4-dns_pkg` | Package bind9 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.5-dnsmasq_pkg` | Package dnsmasq is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.6-ftp_pkg` | Package vsftp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.7-ldap_pkg` | Package slapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.8-dovecot_imapd_pkg` | Package dovecot-imapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.8-dovecot_pop3d_pkg` | Package dovecot-pop3d is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.11-cups_pkg` | Package cups is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.13-rsync_pkg` | Package rsync is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.14-samba_pkg` | Package samba is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.15-snmp_pkg` | Package snmpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.16-tftp_pkg` | Package tftpd-hpa is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.17-squid_pkg` | Package squid is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.18-apache2_pkg` | Package apache2 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.18-nginx_pkg` | Package nginx is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.19-xinetd_pkg` | Package xinetd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.1.20-xwindow_pkg` | Package xserver-common is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-2.1.22-manual_listening_ports` | manual listening ports: echo "Manual!! - Please check only approved services are listening" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.2.1-nis_client` | Package nis is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.2.2-rsh-client` | Package rsh-client is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.2.3-talk` | Package talk is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.2.4-telnet` | Package telnet is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.2.5-ldap-utils` | Package ldap-utils is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.2.6-ftp_client` | Package ftp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.1.1-chrony` | Package chrony is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.1.1-ntp` | Package ntp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.1.1-systemd-timesyncd` | Package systemd-timesyncd is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.2.1-timesynd_timeservers-attrs` | /etc/systemd/timesyncd.conf.d/50-timesyncd.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.2.1-timesynd_timeservers-content` | /etc/systemd/timesyncd.conf.d/50-timesyncd.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.2.2-timesyncd-enabled` | Service systemd-timesyncd is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.3.2.2-timesyncd-running` | Service systemd-timesyncd is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.1-cron` | Package cron is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.1-cron-enabled` | Service cron is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.1-cron-running` | Service cron is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.2-crontab_perms-attrs` | /etc/crontab: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.3-cron_hourly_perms-attrs` | /etc/cron.hourly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.4-cron_daily_perms-attrs` | /etc/cron.daily: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.5-cron_weekly_perms-attrs` | /etc/cron.weekly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.6-cron_monthly_perms-attrs` | /etc/cron.monthly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.7-cron_yearly_perms-attrs` | /etc/cron.yearly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.8-cron_d_perms-attrs` | /etc/cron.d: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.9-etc_cron.allow-attrs` | /etc/cron.allow: exists, mode 0640 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.1.9-cron_deny_absent-absent` | /etc/cron.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.2.1-etc_at.allow-attrs` | /etc/at.allow: exists, mode 0640 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-2.4.2.1-at_deny_absent-absent` | /etc/at.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.1.1-grub_ipv6` | grub ipv6: grep -i "^[^#]\\s.\*ipv6" /boot/grub/grub.cfg | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.1.1-ipv6_etc_default_grub` | ipv6 etc default grub: grep -i "GRUB_CMDLINE_LINUX=.\*ipv6" /etc/default/grub | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.1.2-wireless_disabled` | wireless disabled: find /sys/class/net/\*/wireless -type d 2>/dev/null \| sed 's\|/wireless$\|\|' \| while read if… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.1.3-bluetooth_pkg` | Package bluez is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.1-lsmod_dccp` | lsmod dccp: lsmod \| grep -i dccp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.1-modprobe_dccp` | modprobe dccp: modprobe -n -v dccp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.2-lsmod_TIPC` | lsmod TIPC: lsmod \| grep -i tipc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.2-modprobe_TIPC` | modprobe TIPC: modprobe -n -v tipc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.3-lsmod_RDS` | lsmod RDS: lsmod \| grep -i rds | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.3-modprobe_RDS` | modprobe RDS: modprobe -n -v rds | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.4-lsmod_sctp` | lsmod sctp: lsmod \| grep -i sctp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.2.4-modprobe_sctp` | modprobe sctp: modprobe -n -v sctp | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.1-net.ipv4.ip_forward` | Kernel parameter net.ipv4.ip_forward is 0 | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.1-ip4_forward_conf` | ip4 forward conf: grep net.ipv4.ip_forward /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.conf /usr/… | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.2-net.ipv4.conf.all.forwarding` | Kernel parameter net.ipv4.conf.all.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.2-ip4_all_forwarding` | ip4 all forwarding: grep forwarding /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.conf /usr/local/lib… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.3-net.ipv4.conf.default.forwarding` | Kernel parameter net.ipv4.conf.default.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.3-ip4_default_forwarding` | ip4 default forwarding: grep forwarding /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.conf /usr/local/lib… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.4-net.ipv4.conf.all.send_redirects` | Kernel parameter net.ipv4.conf.all.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.4-ip4_all_send_redirects` | ip4 all send redirects: grep send_redirects /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.conf /usr/local… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.5-net.ipv4.conf.default.send_redirects` | Kernel parameter net.ipv4.conf.default.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.5-ip4_default_send_redirects` | ip4 default send redirects: grep send_redirects /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.conf /usr/local… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.6-net.ipv4.icmp_ignore_bogus_error_respons` | Kernel parameter net.ipv4.icmp_ignore_bogus_error_responses is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.6-ipv4_ignore_bogus` | ipv4 ignore bogus: grep net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf /etc/sysctl.d/\*.conf /ru… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.7-net.ipv4.icmp_echo_ignore_broadcasts` | Kernel parameter net.ipv4.icmp_echo_ignore_broadcasts is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.7-ipv4_echo_ignore_broadcasts` | ipv4 echo ignore broadcasts: grep net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysc… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.8-net.ipv4.conf.all.accept_redirects` | Kernel parameter net.ipv4.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.8-ipv4_all_accept_redirects` | ipv4 all accept redirects: grep net.ipv4.conf.all.accept_redirects /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.9-net.ipv4.conf.default.accept_redirects` | Kernel parameter net.ipv4.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.9-ipv4_default_accept_redirects` | ipv4 default accept redirects: grep net.ipv4.conf.default.accept_redirects /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sy… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.10-net.ipv4.conf.all.secure_redirects` | Kernel parameter net.ipv4.conf.all.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.10-ipv4_all_secure_redirects` | ipv4 all secure redirects: grep net.ipv4.conf.all.secure_redirects /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.11-net.ipv4.conf.default.secure_redirects` | Kernel parameter net.ipv4.conf.default.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.11-ipv4_default_secure_redirects` | ipv4 default secure redirects: grep net.ipv4.conf.default.secure_redirects /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sy… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.12-net.ipv4.conf.all.rp_filter` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.12-ipv4_all_rp_filter` | ipv4 all rp filter: grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.co… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.13-net.ipv4.conf.default.rp_filter` | Kernel parameter net.ipv4.conf.default.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.13-ipv4_default_rp_filter` | ipv4 default rp filter: grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.14-net.ipv4.conf.all.accept_source_route` | Kernel parameter net.ipv4.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.14-ipv4_all_source_routed` | ipv4 all source routed: grep net.ipv4.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sys… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.15-net.ipv4.conf.default.accept_source_rout` | Kernel parameter net.ipv4.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.15-ipv4_default_source_routed` | ipv4 default source routed: grep net.ipv4.conf.default.accept_source_route /etc/sysctl.conf /etc/sysctl.d/\*.conf /run… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.16-net.ipv4.conf.all.log_martians` | Kernel parameter net.ipv4.conf.all.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.16-ipv4_all_log_martians` | ipv4 all log martians: grep net.ipv4.conf.all.log_martians /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.17-net.ipv4.conf.default.log_martians` | Kernel parameter net.ipv4.conf.default.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.17-ipv4_default_log_martians` | ipv4 default log martians: grep net.ipv4.conf.default.log_martians /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.18-net.ipv4.tcp_syncookies` | Kernel parameter net.ipv4.tcp_syncookies is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-3.3.1.18-ipv4_tcp_syn_cookies` | ipv4 tcp syn cookies: grep net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/\*.conf /run/sysctl.d/\*.conf /… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-4.1.1-ufw` | Package ufw is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-4.1.2-ufw-enabled` | Service ufw is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-4.1.2-ufw-running` | Service ufw is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-4.1.3-ufw_incoming_default` | ufw incoming default: ufw status verbose \| awk -F',' '$1~/Default/ {print $1}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-4.1.4-ufw_outgoing_default` | ufw outgoing default: ufw status verbose \| awk -F',' '$1~/Default/ {print $2}' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-4.1.5-ufw_routed_default` | ufw routed default: ufw status verbose \| awk -F',' '$1="Default"{print $3}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.1-sshd_config_perms-attrs` | /etc/ssh/sshd_config: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.2-etc_ssh_ssh_host_prv_key_group` | /etc/ssh/ssh host prv key group: groupkeys=$(sudo find /etc/ssh/ -name '\*_key' -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.2-etc_ssh_ssh_host_prv_key_perms` | /etc/ssh/ssh host prv key perms: keyperms=$(sudo find /etc/ssh/ -name '\*_key' -type f \\( -perm /137 -o \\( -group root -per… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.2-etc_ssh_ssh_host_prv_key_user` | /etc/ssh/ssh host prv key user: userkeys=$(sudo find /etc/ssh/ -name '\*_key' -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.3-etc_ssh_ssh_host_pub_key_group` | /etc/ssh/ssh host pub key group: groupkeys=$(sudo find /etc/ssh/ -name '\*_key.pub' -type f ! -group root ); echo $groupkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.3-etc_ssh_ssh_host_pub_key_perms` | /etc/ssh/ssh host pub key perms: keyperms=$(sudo find /etc/ssh/ -name '\*_key.pub' -type f -perm /133 ); echo $keyperms | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.3-etc_ssh_ssh_host_pub_key_user` | /etc/ssh/ssh host pub key user: userkeys=$(sudo find /etc/ssh/ -name '\*_key.pub' -type f ! -user root ); echo $userkeys | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.4-sshd_access_limited` | sshd access limited: grep -Ei "^(Allow\|Deny)(Users\|Groups)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.5-ssh_banner-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.5-ssh_banner-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.5-ssh_configd_banner` | ssh configd banner: grep -Eis '^\\s\*Banner\\s+"?none\\b' /etc/ssh/sshd_config.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.6-no_weak_ssh_ciphers` | no weak ssh ciphers: sshd -T \| grep -Pi -- '^ciphers\\h+\\"?([^#\\n\\r]+,)?((3des\|blowfish\|cast128\|aes(128\|192\|256… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.7-sshd_clientalive-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.7-sshd_clientalive-content` | /etc/ssh/sshd_config has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.8-sshd_disableforwarding-attrs` | /etc/ssh/sshd_config: exists | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.8-sshd_disableforwarding-content` | /etc/ssh/sshd_config has the expected content (3 rules) | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.9-sshd_gssapiauth-attrs` | /etc/ssh/sshd_config: exists | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.9-sshd_gssapiauth-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.10-ssh_hostbased_auth-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.10-ssh_hostbased_auth-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.11-ssh_rhosts-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.11-ssh_rhosts-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.12-sshd_KEX` | sshd KEX: sshd -T \| grep -Pi -- 'kexalgorithms\\h+([^#\\n\\r]+,)?(diffie-hellman-group1-sha1\|diffie-he… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.13-ssh_logingrace-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.13-ssh_logingrace-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.14-ssh_loglevel-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.14-ssh_loglevel-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.15-sshd_MACS` | sshd MACS: sshd -T \| grep -Pi -- 'macs\\h+([^#\\n\\r]+,)?(hmac-md5\|hmac-md5-96\|hmac-ripemd160\|hmac-sha1… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.16-sshd_authtries-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.16-sshd_authtries-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.17-ssh_maxsessions-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.17-ssh_maxsessions-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.18-ssh_maxstartups-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.18-ssh_maxstartups-content` | /etc/ssh/sshd_config has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.19-ssh_empty_passwd-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.19-ssh_empty_passwd-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.20-ssh_permit_root-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.20-ssh_permit_root-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.21-ssh_userenv-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.21-ssh_userenv-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.22-ssh_usepam-attrs` | /etc/ssh/sshd_config: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.1.22-ssh_usepam-content` | /etc/ssh/sshd_config has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.1-sudo` | Package sudo is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.2-sudoers_use_pty-attrs` | /etc/sudoers: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.2-sudoers_use_pty-content` | /etc/sudoers has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.2-pty_sudoers_d` | pty sudoers d: ls -1 /etc/sudoers.d/\* > /dev/null 2>&1; if [ '$?' = '0' ]; then grep -c '^Defaults\\s\*use… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.3-log_sudoers_d` | log sudoers d: grep -Ec "^Defaults.\*logfile=(\\"\|)/var/log/.\*\\.log(\\"\|)" /etc/sudoers /etc/sudoers.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.4-nopasswd_sudoers_d` | nopasswd sudoers d: grep -R NOPASSWD /etc/sudoers /etc/sudoers.d/\* \| grep -v '.\*\\:#' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.2.5-authenticate_sudoers` | authenticate sudoers: grep -r "^[^#].\*\\!authenticate" /etc/sudoers\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.6-sudo_timeout` | sudo timeout: grep -rP "timestamp_timeout=\\K[0-9]\*" /etc/sudoers\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.7-su_conf-attrs` | /etc/pam.d/su: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.7-su_conf-content` | /etc/pam.d/su has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.2.7-sugroup_etc_group` | sugroup etc group: grep nosugroup /etc/group  \| awk -F':' '{print $NF}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.1.1-libpam-runtime` | Package libpam-runtime is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.1.2-libpam-modules` | Package libpam-modules is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.1.3-libpam-pwquality` | Package libpam-pwquality is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_act-attrs` | /etc/pam.d/common-account: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_act-content` | /etc/pam.d/common-account has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_auth-attrs` | /etc/pam.d/common-auth: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_auth-content` | /etc/pam.d/common-auth has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_password-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_password-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_session-attrs` | /etc/pam.d/common-session: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.1-pam_unix_enabled_common_session-content` | /etc/pam.d/common-session has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.2-pam_faillock_enabled_common_act-attrs` | /etc/pam.d/common-account: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.2-pam_faillock_enabled_common_act-content` | /etc/pam.d/common-account has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.2-pam_faillock_enabled_common_auth-attrs` | /etc/pam.d/common-auth: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.2-pam_faillock_enabled_common_auth-content` | /etc/pam.d/common-auth has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.3-pam_pwquality_enabled_common_passwd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.3-pam_pwquality_enabled_common_passwd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.4-pam_pwhistory_enabled_common_passwd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.2.4-pam_pwhistory_enabled_common_passwd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.1-faillock_attempts_deny-attrs` | /etc/security/faillock.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.1-faillock_attempts_deny-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.1-faillock_attempts_deny_removed` | faillock attempts deny removed: grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?deny\\b' /usr/share/pam-configs/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.2-faillock_unlock_time-attrs` | /etc/security/faillock.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.2-faillock_unlock_time-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.2-faillock_unlock_time_removed` | faillock unlock time removed: grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?unlock_time\\b' /usr/share/pam-configs/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.1.3-faillock_even_root-attrs` | /etc/security/faillock.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.3.3.1.3-faillock_even_root-content` | /etc/security/faillock.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.3.3.1.3-faillock_even_root_removed` | faillock even root removed: grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?(even_deny_root\|root_unlock_time)' /usr/… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.3.3.2.1-passwd_change_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.1-passwd_change_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.1-password_character_changed` | password character changed: grep -Psi -- '^\\h\*difok\\h\*=\\h\*([2-9]\|[1-9][0-9]+)\\b' /etc/security/pwquality.conf /etc/se… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.2-password_minlen` | password minlen: grep -Psi -- '^\\h\*minlen\\h\*=\\h\*(1[4-9]\|[2-9][0-9]\|[1-9][0-9]{2,})\\b' /etc/security/pwqual… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.2-password_minlen_not_pamd` | password minlen not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.3-password_complex` | password complex: grep -Psi -- '^\\h\*(minclass\|[dulo]credit)\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.3-password_complex_not_pamd` | password complex not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.4-consecutive_characters_not_pamd` | consecutive characters not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.4-password_consecutive_characters` | password consecutive characters: grep -Psi -- '^\\h\*maxrepeat\\h\*=\\h\*[1-3]\\b' /etc/security/pwquality.conf /etc/security/pwq… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.5-maxseq_not_pamd` | maxseq not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.5-password_maxseq` | password maxseq: grep -Psi -- '^\\h\*maxsequence\\h\*=\\h\*[1-3]\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.6-dictchk_not_pamd` | dictchk not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.6-password_dictchk` | password dictchk: grep -Psi -- '^\\h\*dictcheck\\s\*=' /etc/security/pwquality.conf /etc/security/pwquality.con… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.7-password_quality_enforce` | password quality enforce: grep -Psi -- '^\\h\*enforcing\\s\*=\\s\*' /etc/security/pwquality.conf /etc/security/pwquality.… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.7-quality_enforce_not_pamd` | quality enforce not pamd: grep -Psi -- '^\\h\*password\\h+[^#\\n\\r]+\\h+pam_pwquality\\.so\\h+([^#\\n\\r]+\\h+)?enforcing=0\\b… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.2.8-password_quality_enforce_root` | password quality enforce root: grep -Psi -- '^\\s\*enforce_for_root\\b' /etc/security/pwquality.conf /etc/security/pwqualit… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.1-pwhistory_remember_common_passwd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.1-pwhistory_remember_common_passwd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.1-pwhistory_remember_pam_configs` | pwhistory remember pam configs: for file in `awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.2-pwhistory_enforce_for_root-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.2-pwhistory_enforce_for_root-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.2-pwhistory_enforce_for_root_pam_configs` | pwhistory enforce for root pam configs: for file in `awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.3-pwhistory_use_authtok-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.3-pwhistory_use_authtok-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.3.3-pwhistory_use_authtok_pam_configs` | pwhistory use authtok pam configs: for file in `awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.4.1-pam_unix_nullok_pam_configs` | pam unix nullok pam configs: grep -PH -- '^\\h\*^\\h\*[^#\\n\\r]+\\h+pam_unix\\.so\\b' /etc/pam.d/common-password /etc/pam.d/co… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.4.2-pam_unix_remember_pam_configs` | pam unix remember pam configs: grep -PH -- '^\\h\*^\\h\*[^#\\n\\r]+\\h+pam_unix\\.so\\b' /etc/pam.d/common-password /etc/pam.d/co… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.4.3-pam_unix_strong_password_pam_configs` | pam unix strong password pam configs: grep -PH -- '^\\h\*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512\|yescrypt)… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.3.3.4.4-pam_unix_use_authtok_pam_configs` | pam unix use authtok pam configs: grep -PH -- '^\\s\*password\\s+([^#\\n\\r]+)\\s+pam_unix\\.so\\s+([^#\\n\\r]+\\s+)?use_authtok\\b' /e… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.1-login_defs_PASS_MAX_DAYS-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.1-login_defs_PASS_MAX_DAYS-content` | /etc/login.defs has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.1-users_max_pw_expire` | users max pw expire: awk -F: '($2~/^\\$.+\\$/) {if($5 > 365 \|\| $5 < 1) print "FAIL: " $1 " PASS_MAX_DAYS: " $5}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.2-login_defs_PASS_MIN_DAYS-attrs` | /etc/login.defs: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.4.1.2-login_defs_PASS_MIN_DAYS-content` | /etc/login.defs has the expected content (3 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.4.1.2-users_min_pw_expire` | users min pw expire: awk -F: '($2~/^\\$.+\\$/) {if($4 < 1) print "FAIL: " $1 " PASS_MIN_DAYS: " $4}' /etc/shadow | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.4.1.3-login_def_PASS_WARN_AGE-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.3-login_def_PASS_WARN_AGE-content` | /etc/login.defs has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.3-user_expire_warn` | user expire warn: awk -F: '($2~/^\\$.+\\$/) {if($6 < 7) print "FAIL: " $1 " PASS_WARN_AGE: " $6}' /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.4-yescrypt_login_defs-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.4-yescrypt_login_defs-content` | /etc/login.defs has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.5-inactive_passwd` | inactive passwd: useradd -D \| grep INACTIVE | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.5-inactive_users` | inactive users: awk -F: '($2~/^\\$.+\\$/) {if($7 == "" \|\| $7 > 45 \|\| $7 < 0) print "FAIL: " $1 " INACTIVE: … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.1.6-passwd_chg_past` | No user has a last password change date in the future | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.1-root_only_uid_0` | root only uid 0: awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.2-root_only_gid_0` | root only gid 0: awk -F: '($1 !~ /^(sync\|shutdown\|halt\|operator)/ && $1 != "root" && $4 == 0) {print $1":"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.3-group_root_only_0` | group root only 0: awk -F: '($3 == 0 && $1 != "root") {print $1":"$3}' /etc/group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.4-root_passwd_set` | root passwd set: passwd -S root \| awk '$2 ~ /^P/ {print "OK Password"}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.5-root_path_check` | root path check: /bin/bash --login -c 'env \| grep ^PATH=' \| sed -e 's/^PATH=//' \| tr ':' '\\n' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.6-root_umask_bash_profile` | root umask bash profile: grep -i umask /root/.bash_profile /root/bashrc | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.7-secure_system_accts` | secure system accts: awk -F: '$3<1000' /etc/passwd \| grep -Ev 'root\|sync\|halt\|shutdown\|nfsnobody\|/sbin/nologin… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.2.8-user_accts_valid_shell` | user accts valid shell: l_valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells \| sed -rn '/^\\//{s,/,\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.3.1-nologin_not_in_shells-attrs` | /etc/shells: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.4.3.1-nologin_not_in_shells-content` | /etc/shells has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-5.4.3.2-check_timeout` | check timeout: grep TMOUT /etc/profile.d/\*.sh /etc/profile /etc/profile.d/\*.sh\| cut -d ":" -f2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-5.4.3.3-umask_profile_scripts` | umask profile scripts: grep -i "^\\s\*umask" /etc/profile /etc/profile.d/\*.sh /etc/login.defs \| cut -d ":" -f 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.1-systemd-journald-enabled` | Service systemd-journald is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.1-systemd-journald-running` | Service systemd-journald is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.2-etc_tmpfiles.d_systemd.conf` | /etc/tmpfiles.d/systemd.conf: echo "Manual - Please check journald default permissions" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.3-log_rotate_journald_conf` | log rotate journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*(SystemMaxUse\|SystemK… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.4-forward_journald_disabled` | forward journald disabled: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*ForwardToSyslog\\h\*=' … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.5-storage_journald_conf` | storage journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*Storage\\h\*=' \| tail -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.1.6-compress_journald_conf` | compress journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*Compress\\h\*=' \| tail … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.1-systemd-journal-remote` | Package systemd-journal-remote is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.2-journal_remote_configured-attrs` | /etc/systemd/journal-upload.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.2-journal_remote_configured-content` | /etc/systemd/journal-upload.conf has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.3-systemd-journal-upload.service-enabled` | Service systemd-journal-upload.service is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.3-systemd-journal-upload.service-running` | Service systemd-journal-upload.service is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.4-systemd-journal-remote.service-running` | Service systemd-journal-remote.service is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.4-systemd-journal-remote.socket-enabled` | Service systemd-journal-remote.socket is not enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.4-systemd-journal-remote.socket-running` | Service systemd-journal-remote.socket is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.4-journald_remote_not_active` | journald remote not active: systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.1.2.4-journald_remote_not_enabled` | journald remote not enabled: systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.1-rsyslog` | Package rsyslog is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.2-rsyslog-enabled` | Service rsyslog is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.2-rsyslog-running` | Service rsyslog is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.3-forward_journald_conf` | forward journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*ForwardToSyslog\\h\*=' … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.4-perms_rsyslog_d` | perms rsyslog d: grep -s ^\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/\*.conf \| cut -f2 -d: | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.5-etc_rsyslog.conf-attrs` | /etc/rsyslog.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.5-etc_rsyslog.conf-content` | /etc/rsyslog.conf has the expected content (14 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.6-remote_syslog` | remote syslog: grep -E "action.\*omfwd.\*target" /etc/rsyslog.conf /etc/rsyslog.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.7-local_syslog_input` | local syslog input: grep -E "imtcp\\" port\|InputTCPServerRun" /etc/rsyslog.conf /etc/rsyslog.d/\*.conf \| grep -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.7-local_syslog_module` | local syslog module: grep "imtcp" /etc/rsyslog.conf /etc/rsyslog.d/\*.conf \| grep -Ev ":#\|port=" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.2.8-rsyslog_logrotate` | rsyslog logrotate: echo "Manual" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.1.3.1-logfile_configured` | logfile configured: find /var/log/ -type f \\( -name 'lastlog' -o -name 'wtmp' -o -name 'btmp' \\) -perm /g+x,o… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.2.1.1-audispd-plugins` | Package audispd-plugins is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.1-audit_packages` | Package auditd is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.2-auditd-enabled` | Service auditd is enabled | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.2-auditd-running` | Service auditd is running | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.3-grub_audit_start-attrs` | /etc/default/grub: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.3-grub_audit_start-content` | /etc/default/grub has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.3-auditd_grub` | auditd grub: grep "^\\s\*linux" /boot/grub/grub.cfg \| grep -Evc "audit=1" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.4-grub_audit_backlog-attrs` | /etc/default/grub: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.4-grub_audit_backlog-content` | /etc/default/grub has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.1.4-auditd_grub_backlog` | auditd grub backlog: grep "^\\s\*linux" /boot/grub/grub.cfg \| grep -Evc "audit_backlog_limit=" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.2.1-auditd_max_log_file` | auditd max log file: grep -E "^max_log_file" /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.2.2-auditd_max_log_action` | auditd max log action: grep -E "^max_log_file_action" /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.2.3-auditd_space_actions-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.2.3-auditd_space_actions-content` | /etc/audit/auditd.conf has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.2.4-auditd_space_actions` | auditd space actions: grep -E "action" /etc/audit/auditd.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.1-auditd_admin_scope_cnf` | auditd admin scope cnf: grep scope /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.1-auditd_admin_scope_live` | auditd admin scope live: auditctl -l \| grep scope | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.2-auditd_sudo_actions` | auditd sudo actions: grep user_emulation /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.2-auditd_sudo_actions_live` | auditd sudo actions live: auditctl -l \| grep user_emulation | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.3-auditd_sudolog_chg` | auditd sudolog chg: grep sudo_log_file /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.3-auditd_sudolog_chg_live` | auditd sudolog chg live: auditctl -l \| grep sudo_log_file | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.4-auditd_time_cnf` | auditd time cnf: grep time-change /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.4-auditd_time_live` | auditd time live: auditctl -l \| grep time-change | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.5-auditd_locale_cnf` | auditd locale cnf: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.5-auditd_locale_live` | auditd locale live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.6-auditd_priv_cmds_cnf` | auditd priv cmds cnf: grep privileged /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.6-auditd_priv_cmds_live` | auditd priv cmds live: auditctl -l \| grep privileged | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.7-auditd_access_cnf` | auditd access cnf: sh -c "grep auid /etc/audit/rules.d/\*.rules" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.7-auditd_access_live` | auditd access live: auditctl -l \| grep access | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.8-auditd_identity_cnf` | auditd identity cnf: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.8-auditd_identity_live` | auditd identity live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.9-auditd_perms_cnf` | auditd perms cnf: grep perm_mod /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.9-auditd_perms_live` | auditd perms live: auditctl -l \| grep perm_mod | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.10-auditd_mounts_cnf` | auditd mounts cnf: grep mounts /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.10-auditd_mounts_live` | auditd mounts live: auditctl -l \| grep mounts | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.11-auditd_session_live` | auditd session live: auditctl -l \| grep -E '(session\|logins)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.11-auditd_sessions_cnf` | auditd sessions cnf: grep -E '(session\|logins)' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.12-auditd_logins_cnf` | auditd logins cnf: grep -R --include="\*.rules" logins /etc/audit/rules.d/ | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.12-auditd_logins_live` | auditd logins live: auditctl -l \| grep logins | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.13-auditd_delete_cnf` | auditd delete cnf: grep delete /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.13-auditd_delete_live` | auditd delete live: auditctl -l \| grep delete | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.14-auditd_MAC_cnf` | auditd MAC cnf: grep MAC-policy /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.14-auditd_MAC_live` | auditd MAC live: auditctl -l \| grep MAC-policy | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.15-chcon_module_cnf` | chcon module cnf: grep chcon /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.15-chcon_module_live` | chcon module live: auditctl -l \| grep chcon | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.16-setfacl_module_cnf` | setfacl module cnf: grep setfacl /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.16-setfacl_module_live` | setfacl module live: auditctl -l \| grep setfacl | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.17-chacl_module_cnf` | chacl module cnf: grep chacl /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.17-chacl_module_live` | chacl module live: auditctl -l \| grep chacl | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.18-usermod_module_cnf` | usermod module cnf: grep usermod /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.18-usermod_module_live` | usermod module live: auditctl -l \| grep usermod | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.19-auditd_admin_module_live` | auditd admin module live: auditctl -l \| grep kernel_module | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.19-auditd_module_cnf` | auditd module cnf: grep kernel_module /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.20-auditd_immutable` | auditd immutable: grep -h -- "-e 2" /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.3.21-auditd_config_match` | auditd config match: augenrules --check | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.1-audit_logfile_perms` | audit logfile perms: d=$(dirname $(grep ^log_file /etc/audit/auditd.conf \| awk '{ print $NF }')); find $d -max… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.2-audit_logfile_owner` | audit logfile owner: d=$(dirname $(grep ^log_file /etc/audit/auditd.conf \| awk '{ print $NF }')); find $d -max… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.3-audit_logfile_group` | audit logfile group: d=$(dirname $(grep ^log_file /etc/audit/auditd.conf \| awk '{ print $NF }')); find $d -max… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.3-audit_logfile_group_setting` | audit logfile group setting: grep log_group /etc/audit/audit\* \| awk '{ print $NF }' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.4-audit_logfile_dir_perms` | audit logfile dir perms: for dir in `dirname \\`grep ^log_file /etc/audit/auditd.conf \| awk '{ print $NF }'\\``; do … | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.5-audit_conf_perms` | audit conf perms: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) -perm /0137 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.6-audit_conf_owner` | audit conf owner: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -user root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.7-audit_conf_group` | audit conf group: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.8-audit_tools_perms` | audit tools perms: find /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenr… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.9-audit_tools_owner` | audit tools owner: find /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenr… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.2.4.10-audit_tools_group` | audit tools group: find /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenr… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-6.3.1-aide` | Package aide is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.3.1-aide-common` | Package aide-common is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.3.2-aide_cron` | aide cron: grep -Prs '^([^#\\n\\r]+\\h+)?(\\/usr\\/s?bin\\/\|^\\h\*)aide(\\.wrapper)?\\h+([^#\\n\\r]+\\h+)?(--(che… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-6.3.3-audit_tools_crypto` | audit tools crypto: grep -P -- '(\\/sbin\\/(audit\|au)\\H\*\\b)' /etc/aide/aide.conf | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU22-7.1.1-passwd_perms-attrs` | /etc/passwd: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.2-passwd-_perms-attrs` | /etc/passwd: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.3-group_perms-attrs` | /etc/group: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.4-group-_perms-attrs` | /etc/group-: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.5-shadow_perms-attrs` | /etc/shadow: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.6-shadow-_perms-attrs` | /etc/shadow-: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.7-gshadow_perms-attrs` | /etc/gshadow: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.8-gshadow-_perms-attrs` | /etc/gshadow-: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.9-etc_shells_perms-attrs` | /etc/shells: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.10-etc_security_opasswd_perms-attrs` | /etc/security/opasswd: mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.11-world_writable` | world writable: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.12-unowned_dirs` | unowned dirs: df --local -P \| awk {'if (NR!=1) print $6'} \| xargs -I '{}' find '{}' -xdev -nouser -o -n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.1.13-audit_sgid` | audit sgid: findmnt -Dkerno fstype,target,options \| awk '($1 !~ /^[[:space:]]\*(nfs\|proc\|smb\|vfat\|iso9… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.1-shadowed_passwds-attrs` | /etc/passwd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.1-shadowed_passwds-content` | /etc/passwd has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.2-passwd_fields_not_empty_shadow-attrs` | /etc/shadow: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.2-passwd_fields_not_empty_shadow-content` | /etc/shadow has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.3-passwd_group_exist` | passwd group exist: awk -F: 'NR==FNR{gid[$3];next} !($4 in gid){print $4}' /etc/group /etc/passwd \| sort -u | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.4-shadow_group_empty-attrs` | /etc/group: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.4-shadow_group_empty-content` | /etc/group has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.5-no_dup_uid` | no dup uid: cat /etc/passwd \| cut -d: -f3 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.6-no_dup_gid` | no dup gid: cat /etc/group \| cut -d: -f3 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.7-no_dup_username` | no dup username: cat /etc/passwd \| cut -d: -f1 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.8-no_dup_groupname` | no dup groupname: cat /etc/group \| cut -d: -f1 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.9-home_dirs_exist` | home dirs exist: for i in `cat /etc/passwd \| grep -Ev "halt\|sync\|shutdown\|nfsnobody\|nologin\|false" \| cut -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.9-home_dirs_ownership` | home dirs ownership: getent passwd \| awk -F: '$3 >= 1000 && $3 <= 60000 && $1 != "ftpd" {print $1, $6}' \| whil… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.9-home_dirs_permissions` | home dirs permissions: getent passwd \| awk -F: '$3 >= 1000 && $3 <= 60000 {print $6}' \| while read dir; do [ -d … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.10-bad_dot_files` | bad dot files: find /home/ -name "\\.forward" -o -name "\\.netrc" -o -name "\\.rhosts" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.10-dot_file_bash_history` | dot file bash history: find /home/ -name "\\.bash_history" -perm /go+rwx | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU22-7.2.10-dot_file_perms` | dot file perms: find /home/ -name "\\.\*" -perm /g+w,o+w \| grep -v .bash_history | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |

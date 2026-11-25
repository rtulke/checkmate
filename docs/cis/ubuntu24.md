# CIS Ubuntu 24.04 LTS

Automated checks for 311 recommendations of the CIS Ubuntu 24.04 LTS benchmark (version 2.0.0), converted from the goss audit content of the ansible-lockdown project. Check names describe what is verified; the recommendation number is in the ID and the description. Select profiles with tags, e.g. `--tags cis-level-1+cis-server`.

**Policy:** [`cis/ubuntu24.yml`](https://github.com/rtulke/checkmate/blob/main/cis/ubuntu24.yml) · **Benchmark version:** 2.0.0

```bash
checkmate run cis/ubuntu24.yml --tags cis-level1-server
checkmate run cis/ubuntu24.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-UBUNTU24-1.1.1.1-cramfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.1-cramfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.1-cramfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.1-cramfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.2-freevxfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.2-freevxfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.2-freevxfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.2-freevxfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.3-hfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.3-hfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.3-hfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.3-hfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.4-hfsplus_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.4-hfsplus_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.4-hfsplus_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.4-hfsplus_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.5-jffs2_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.5-jffs2_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.5-jffs2_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.5-jffs2_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.6-overlayfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.6-overlayfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.6-overlayfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.6-overlayfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.7-squashfs_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.7-squashfs_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.7-squashfs_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.7-squashfs_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.8-udf_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.8-udf_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.8-udf_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.8-udf_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.1.9-firewire-core_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.9-firewire-core_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.9-firewire-core_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.9-firewire-core_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.10-usb-storage_blacklist-attrs` | /etc/modprobe.d/blacklist.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.10-usb-storage_blacklist-content` | /etc/modprobe.d/blacklist.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.10-usb-storage_disabled-attrs` | /etc/modprobe.d/CIS.conf: exists | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.10-usb-storage_disabled-content` | /etc/modprobe.d/CIS.conf has the expected content (1 rule) | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.1.11-cve_fs` | cve fs: /var/fs_with_cves.sh | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.1-tmp_mount` | /tmp is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.2-tmp_nodev_options` | /tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.2-tmp_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.2-tmp_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.3-tmp_nosuid_options` | /tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.3-tmp_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.3-tmp_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.4-tmp_noexec_options` | /tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.4-tmp_fstab_noexec_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.1.4-tmp_fstab_noexec_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.1-dev_shm_mount` | /dev/shm is a separate mount | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.2-dev_shm_nodev_options` | /dev/shm is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.2-dev_shm_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.2-dev_shm_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.3-dev_shm_nosuid_options` | /dev/shm is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.3-dev_shm_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.3-dev_shm_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.4-dev_shm_noexec_options` | /dev/shm is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.4-dev_shm_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.2.4-dev_shm_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.3.1-home_mount` | /home is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.2.3.2-home_nodev_options` | /home is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.3.2-home_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.3.2-home_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.3.3-home_nosuid_options` | /home is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.3.3-home_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.3.3-home_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.4.1-var_mount` | /var is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.2.4.2-var_nodev_options` | /var is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.4.2-var_fstab_nodev_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.4.2-var_fstab_nodev_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.4.3-var_nosuid_options` | /var is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.4.3-var_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.4.3-var_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.1-var_tmp_mount` | /var/tmp is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.2.5.2-var_tmp_nodev_options` | /var/tmp is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.2-var_tmp_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.2-var_tmp_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.3-var_tmp_nosuid_options` | /var/tmp is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.3-var_tmp_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.3-var_tmp_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.4-var_tmp_noexec_options` | /var/tmp is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.4-var_tmp_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.5.4-var_tmp_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.1-var_log_mount` | /var/log is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.2.6.2-var_log_nodev_options` | /var/log is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.2-var_log_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.2-var_log_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.3-var_log_nosuid_options` | /var/log is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.3-var_log_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.3-var_log_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.4-var_log_noexec_options` | /var/log is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.4-var_log_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.6.4-var_log_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.1-var_log_audit_mount` | /var/log/audit is a separate mount | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.1.2.7.2-var_log_nodev_audit_options` | /var/log/audit is a separate mount with nodev | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.2-var_log_audit_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.2-var_log_audit_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.3-var_log_audit_options` | /var/log/audit is a separate mount with nosuid | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.3-var_log_audit_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.3-var_log_audit_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.4-var_log_audit_noexec_options` | /var/log/audit is a separate mount with noexec | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.4-var_log_audit_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.1.2.7.4-var_log_audit_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.1-apt_signed_by` | apt signed by: for f in /etc/apt/sources.list /etc/apt/sources.list.d/\*.list /etc/apt/sources.list.d/\*.s… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.2-apt_weak_dependencies` | apt weak dependencies: /usr/bin/apt-config dump \| /usr/bin/grep "APT::Install-" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.2.1.3-apt_gpg_key_perms` | apt gpg key perms: find -L /usr/share/keyrings/ /etc/apt/trusted.gpg.d/ -mount -xdev -type f \\( ! -user root… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.4-apt_trusted_gpg_d-attrs` | /etc/apt/trusted.gpg.d: exists, is a directory, mode 0755 or stricter, owner root, group root | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.5-apt_auth_conf_d-attrs` | /etc/apt/auth.conf.d: exists, is a directory, mode 0755 or stricter, owner root, group root | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.6-apt_auth_conf_d_files` | apt auth conf d files: find -L /etc/apt/auth.conf.d/ -type f \\( ! -user root -o ! -group root -o -perm /0137 \\) … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.7-usr_share_keyrings-attrs` | /usr/share/keyrings: exists, is a directory, mode 0755 or stricter, owner root, group root | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.8-apt_sources_list_d-attrs` | /etc/apt/sources.list.d: exists, is a directory, mode 0755 or stricter, owner root, group root | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.1.9-apt_sources_list_d_files` | apt sources list d files: find -L /etc/apt/sources.list.d/ -type f \\( ! -user root -o ! -group root -o -perm /0133 … | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.2.2.1-check_updates` | check updates: apt --just-print upgrade | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.1-apparmor` | Package apparmor is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.1-apparmor-utils` | Package apparmor-utils is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.2-apparmor_boot_grub-attrs` | /boot/grub/grub.cfg: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.2-apparmor_boot_grub-content` | /boot/grub/grub.cfg has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.2-grub_app_armor-attrs` | /etc/default/grub: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.2-grub_app_armor-content` | /etc/default/grub has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.3-apparmor_enf_only` | apparmor enf only: apparmor_status 2>/dev/null \| grep -E '^[0-9]+ (profiles are loaded\|profiles are in compl… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.3.1.4-kernel.apparmor_restrict_unprivileged_un` | Kernel parameter kernel.apparmor_restrict_unprivileged_unconfined is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.3.1.4-apparmor_restrict_unconfined_conf` | apparmor restrict unconfined conf: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.4.1-bootloader_password_set-attrs` | /etc/grub.d/00_user: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.4.1-bootloader_password_set-content` | /etc/grub.d/00_user has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.4.2-default_grub_perms-attrs` | /boot/grub/grub.cfg: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.1-fs.protected_hardlinks` | Kernel parameter fs.protected_hardlinks is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.1-protected_hardlinks_configured` | protected hardlinks configured: grep "fs\\.protected_hardlinks" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.2-fs.protected_symlinks` | Kernel parameter fs.protected_symlinks is 1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.5.2-protected_symlinks_configured` | protected symlinks configured: grep "fs\\.protected_symlinks" /etc/sysctl.conf /etc/sysctl.d/\* | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-1.5.3-kernel.yama.ptrace_scope` | Kernel parameter kernel.yama.ptrace_scope is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.3-ptrace_restrict_2` | ptrace restrict 2: grep "kernel\\.yama\\.ptrace_scope" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.4-fs.suid_dumpable` | Kernel parameter fs.suid_dumpable is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.4-suid_dumpable_2` | suid dumpable 2: grep "fs\\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.5-kernel.dmesg_restrict` | Kernel parameter kernel.dmesg_restrict is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.5-dmesg_restrict_configured` | dmesg restrict configured: grep "kernel\\.dmesg_restrict" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.6-prelink` | Package prelink is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.7-apport-running` | Service apport is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.7-etc_default_apport-attrs` | /etc/default/apport: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.7-etc_default_apport-content` | /etc/default/apport has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.8-kernel.kptr_restrict` | Kernel parameter kernel.kptr_restrict is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.8-kptr_restrict_configured` | kptr restrict configured: grep "kernel\\.kptr_restrict" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.9-kernel.randomize_va_space` | Kernel parameter kernel.randomize_va_space is 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.9-aslr_enabled_2` | aslr enabled 2: grep "kernel\\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.10-core_file_size_limits` | core file size limits: grep -Psi -- "^\\h\*\\\*\\h+hard\\h+core\\b" /etc/security/limits.conf /etc/security/limits.d/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.11-coredump_processsizemax-attrs` | /etc/systemd/coredump.conf.d/60-coredump.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.11-coredump_processsizemax-content` | /etc/systemd/coredump.conf.d/60-coredump.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.12-coredump_storage-attrs` | /etc/systemd/coredump.conf.d/60-coredump.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.5.12-coredump_storage-content` | /etc/systemd/coredump.conf.d/60-coredump.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-etc_motd_content-attrs` | /etc/motd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-etc_motd_content-content` | /etc/motd has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-pam_motd_dynamic_disabled_login-attrs` | /etc/pam.d/login: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-pam_motd_dynamic_disabled_login-content` | /etc/pam.d/login has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-pam_motd_dynamic_disabled_sshd-attrs` | /etc/pam.d/sshd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-pam_motd_dynamic_disabled_sshd-content` | /etc/pam.d/sshd has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-pam_motd_dynamic_disabled_su-attrs` | /etc/pam.d/su: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-pam_motd_dynamic_disabled_su-content` | /etc/pam.d/su has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.1-motd_static_files_content` | motd static files content: grep -Psi -- "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|\\b$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.2-local_login_banner` | local login banner: grep -Psi "(\\\\\\v\|\\\\\\r\|\\\\\\m\|\\\\\\s\|\\b$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.3-cremote_login_banner-attrs` | /etc/issue.net: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.3-cremote_login_banner-content` | /etc/issue.net has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.4-pam_motd_configured` | pam motd configured: os_id="$(grep '^ID=' /etc/os-release \| cut -d= -f2 \| sed -e 's/"//g')" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.5-sshd_warning_banner_content-attrs` | /etc/issue.net: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.5-sshd_warning_banner_content-content` | /etc/issue.net has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.6-etc_motd_perms` | etc motd perms: find -L /etc/motd /run/motd /usr/lib/motd /etc/motd.d /run/motd.d /usr/lib/motd.d -maxdep… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.7-etc_issue_perms-attrs` | /etc/issue: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.8-etc_issue_net_perms-attrs` | /etc/issue.net: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.9-pam_motd_perms` | pam motd perms: grep -hPo 'motd=\\K\\S+' /etc/pam.d/\* 2>/dev/null \| tr -d "\\"'" \| sort -u \| while IFS= read… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-1.6.10-sshd_banner_perms-attrs` | /etc/issue.net: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.1-autofs_pkg` | Package autofs is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.2-mta_listening_ports` | mta listening ports: ss -plntu \| grep -P -- ':(25\|465\|587)\\b' \| grep -Pv -- '\\h+(127\\.0\\.0\\.1\|\\[?::1\\]?):(25\|4… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.2-mta_postfix_inet_interfaces` | mta postfix inet interfaces: if command -v postconf >/dev/null 2>&1; then | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.3-avahi_pkg` | Package avahi-daemon is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.4-manual_listening_ports` | manual listening ports: echo "Manual!! - Please check only approved services are listening" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.5-kea_ddns_pkg` | Package kea-dhcp-ddns-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.5-kea_dhcp4_pkg` | Package kea-dhcp4-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.5-kea_dhcp6_pkg` | Package kea-dhcp6-server is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.5-kea_pkg` | Package kea is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.6-apache2_pkg` | Package apache2 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.6-nginx_pkg` | Package nginx is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.6-nginx_plus_pkg` | Package nginx-plus is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.7-dns_pkg` | Package bind9 is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.8-ftp_pkg` | Package vsftpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.9-dnsmasq_pkg` | Package dnsmasq is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.10-ldap_pkg` | Package slapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.11-dovecot_imapd_pkg` | Package dovecot-imapd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.11-dovecot_pop3d_pkg` | Package dovecot-pop3d is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.12-nfs_service_masked-masked` | Service nfs-server.service is masked or not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.13-ypserv_pkg` | Package ypserv is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.14-cups_pkg` | Package cups is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.15-rpcbind_service_masked-masked` | Service rpcbind.service is masked or not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.15-rpcbind_socket_masked-masked` | Service rpcbind.socket is masked or not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.16-rsync_pkg` | Package rsync is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.17-samba_pkg` | Package samba is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.18-snmp_pkg` | Package snmpd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.19-telnetd_pkg` | Package telnetd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.20-tftp_pkg` | Package tftpd-hpa is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.21-squid_pkg` | Package squid is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.22-xinetd_pkg` | Package xinetd is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.1.23-xwindow_pkg` | Package xserver-common is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-2.2.1-nis_client` | Package nis is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.2-rsh-client` | Package rsh-client is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.3-talk` | Package talk is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.4-inetutils-telnet` | Package inetutils-telnet is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.4-telnet` | Package telnet is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.5-ldap-utils` | Package ldap-utils is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.6-ftp_client` | Package ftp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.2.6-tnftp_client` | Package tnftp is not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.1.1-chrony` | Package chrony is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.1-chrony_pool-attrs` | /etc/chrony/sources.d/pool.sources: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.1-chrony_pool-content` | /etc/chrony/sources.d/pool.sources has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.1-chrony_timeservers-attrs` | /etc/chrony/sources.d/server.sources: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.1-chrony_timeservers-content` | /etc/chrony/sources.d/server.sources has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.2-chrony_user-attrs` | /etc/chrony/chrony.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.2-chrony_user-content` | /etc/chrony/chrony.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.3-chronyd-enabled` | Service chronyd is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.3.3.3-chronyd-running` | Service chronyd is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.1-cron` | Package cron is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.1-cron-enabled` | Service cron is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.1-cron-running` | Service cron is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.2-crontab_perms-attrs` | /etc/crontab: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.3-cron_hourly_perms-attrs` | /etc/cron.hourly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.4-cron_daily_perms-attrs` | /etc/cron.daily: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.5-cron_weekly_perms-attrs` | /etc/cron.weekly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.6-cron_monthly_perms-attrs` | /etc/cron.monthly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.7-cron_yearly_perms-attrs` | /etc/cron.yearly: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.8-cron_d_perms-attrs` | /etc/cron.d: exists, mode 0700 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.9-etc_cron.allow-attrs` | /etc/cron.allow: exists, mode 0640 or stricter, owner root, group root or crontab | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.1.9-cron_deny_absent-absent` | /etc/cron.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.2.1-etc_at.allow-attrs` | /etc/at.allow: exists, mode 0640 or stricter, owner root, group root or daemon | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-2.4.2.1-at_deny_absent-absent` | /etc/at.deny does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.1.2-wireless_disabled` | wireless disabled: no /sys/class/net/\*/wireless exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.1.3-bluetooth_pkg` | Package bluez is not installed | L1 server, L2 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.1-sys_module_atm-absent` | /sys/module/atm does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.1-modprobe_atm` | modprobe atm: modprobe --showconfig \| grep -P '\\b(install\|blacklist)\\h+atm\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.2-sys_module_can-absent` | /sys/module/can does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.2-modprobe_can` | modprobe can: modprobe --showconfig \| grep -P '\\b(install\|blacklist)\\h+can\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.3-sys_module_dccp-absent` | /sys/module/dccp does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.3-modprobe_dccp` | modprobe dccp: modprobe --showconfig \| grep -P '\\b(install\|blacklist)\\h+dccp\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.4-sys_module_rds-absent` | /sys/module/rds does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.4-modprobe_RDS` | modprobe RDS: modprobe --showconfig \| grep -P '\\b(install\|blacklist)\\h+rds\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.5-sys_module_sctp-absent` | /sys/module/sctp does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.5-modprobe_sctp` | modprobe sctp: modprobe --showconfig \| grep -P '\\b(install\|blacklist)\\h+sctp\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.6-sys_module_tipc-absent` | /sys/module/tipc does not exist | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.2.6-modprobe_TIPC` | modprobe TIPC: modprobe --showconfig \| grep -P '\\b(install\|blacklist)\\h+tipc\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.1-net.ipv4.ip_forward` | Kernel parameter net.ipv4.ip_forward is 0 | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.1-ipv4_ip_forward` | ipv4 ip forward: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.2-net.ipv4.conf.all.forwarding` | Kernel parameter net.ipv4.conf.all.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.2-ipv4_all_forwarding` | ipv4 all forwarding: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.3-net.ipv4.conf.default.forwarding` | Kernel parameter net.ipv4.conf.default.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.3-ipv4_def_forwarding` | ipv4 def forwarding: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.4-net.ipv4.conf.all.send_redirects` | Kernel parameter net.ipv4.conf.all.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.4-ipv4_all_send_redirects` | ipv4 all send redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.5-net.ipv4.conf.default.send_redirects` | Kernel parameter net.ipv4.conf.default.send_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.5-ipv4_def_send_redirects` | ipv4 def send redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.6-net.ipv4.icmp_ignore_bogus_error_respons` | Kernel parameter net.ipv4.icmp_ignore_bogus_error_responses is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.6-ipv4_ignore_bogus` | ipv4 ignore bogus: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.7-net.ipv4.icmp_echo_ignore_broadcasts` | Kernel parameter net.ipv4.icmp_echo_ignore_broadcasts is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.7-ipv4_ignore_broadcasts` | ipv4 ignore broadcasts: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.8-net.ipv4.conf.all.accept_redirects` | Kernel parameter net.ipv4.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.8-ipv4_all_accept_redirects` | ipv4 all accept redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.9-net.ipv4.conf.default.accept_redirects` | Kernel parameter net.ipv4.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.9-ipv4_def_accept_redirects` | ipv4 def accept redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.10-net.ipv4.conf.all.secure_redirects` | Kernel parameter net.ipv4.conf.all.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.10-ipv4_all_secure_redirects` | ipv4 all secure redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.11-net.ipv4.conf.default.secure_redirects` | Kernel parameter net.ipv4.conf.default.secure_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.11-ipv4_def_secure_redirects` | ipv4 def secure redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.12-net.ipv4.conf.all.rp_filter` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.12-ipv4_all_rp_filter` | ipv4 all rp filter: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.13-net.ipv4.conf.default.rp_filter` | Kernel parameter net.ipv4.conf.default.rp_filter is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.13-ipv4_def_rp_filter` | ipv4 def rp filter: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.14-net.ipv4.conf.all.accept_source_route` | Kernel parameter net.ipv4.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.14-ipv4_all_source_route` | ipv4 all source route: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.15-net.ipv4.conf.default.accept_source_rout` | Kernel parameter net.ipv4.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.15-ipv4_def_source_route` | ipv4 def source route: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.16-net.ipv4.conf.all.log_martians` | Kernel parameter net.ipv4.conf.all.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.16-ipv4_all_martians` | ipv4 all martians: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.17-net.ipv4.conf.default.log_martians` | Kernel parameter net.ipv4.conf.default.log_martians is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.17-ipv4_def_martians` | ipv4 def martians: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.18-net.ipv4.tcp_syncookies` | Kernel parameter net.ipv4.tcp_syncookies is 1 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.1.18-ipv4_tcp_syncookies` | ipv4 tcp syncookies: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.1-net.ipv6.conf.all.forwarding` | Kernel parameter net.ipv6.conf.all.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.1-ipv6_all_forwarding` | ipv6 all forwarding: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.2-net.ipv6.conf.default.forwarding` | Kernel parameter net.ipv6.conf.default.forwarding is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.2-ipv6_def_forwarding` | ipv6 def forwarding: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.3-net.ipv6.conf.all.accept_redirects` | Kernel parameter net.ipv6.conf.all.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.3-ipv6_all_accept_redirects` | ipv6 all accept redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.4-net.ipv6.conf.default.accept_redirects` | Kernel parameter net.ipv6.conf.default.accept_redirects is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.4-ipv6_def_accept_redirects` | ipv6 def accept redirects: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.5-net.ipv6.conf.all.accept_source_route` | Kernel parameter net.ipv6.conf.all.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.5-ipv6_all_source_route` | ipv6 all source route: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.6-net.ipv6.conf.default.accept_source_rout` | Kernel parameter net.ipv6.conf.default.accept_source_route is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.6-ipv6_def_source_route` | ipv6 def source route: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.7-net.ipv6.conf.all.accept_ra` | Kernel parameter net.ipv6.conf.all.accept_ra is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.7-ipv6_all_accept_ra` | ipv6 all accept ra: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.8-net.ipv6.conf.default.accept_ra` | Kernel parameter net.ipv6.conf.default.accept_ra is 0 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-3.3.2.8-ipv6_def_accept_ra` | ipv6 def accept ra: { /usr/lib/systemd/systemd-sysctl --cat-config; f=$(awk -F= '/^\\s\*IPT_SYSCTL=/{print $2}'… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.1-ufw` | Package ufw is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.2-ufw-enabled` | Service ufw is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.2-ufw-running` | Service ufw is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.2-etc_ufw_ufw.conf-attrs` | /etc/ufw/ufw.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.2-etc_ufw_ufw.conf-content` | /etc/ufw/ufw.conf has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.2-ufw_status_active` | ufw status active: ufw status | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.3-ufw_incoming_default` | ufw incoming default: ufw status verbose \| grep Default: | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-4.1.4-ufw_outgoing_default` | ufw outgoing default: ufw status verbose \| grep Default: | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-4.1.5-ufw_routed_default` | ufw routed default: ufw status verbose \| grep Default: | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.1-sshd_config_perms-attrs` | /etc/ssh/sshd_config: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.1-sshd_config_d_perms` | sshd config d perms: find /etc/ssh/sshd_config.d/ -xdev -type f -name '\*.conf' \\( -perm /077 -o ! -user root -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.2-etc_ssh_ssh_host_prv_key_group` | /etc/ssh/ssh host prv key group: find /etc/ssh/ -name '\*_key' -type f ! -group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.2-etc_ssh_ssh_host_prv_key_perms` | /etc/ssh/ssh host prv key perms: find /etc/ssh/ -name '\*_key' -type f \\( -perm /137 -o \\( -group root -perm /177 \\) \\) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.2-etc_ssh_ssh_host_prv_key_user` | /etc/ssh/ssh host prv key user: find /etc/ssh/ -name '\*_key' -type f ! -user root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.3-etc_ssh_ssh_host_pub_key_group` | /etc/ssh/ssh host pub key group: find /etc/ssh/ -name '\*_key.pub' -type f ! -group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.3-etc_ssh_ssh_host_pub_key_perms` | /etc/ssh/ssh host pub key perms: find /etc/ssh/ -name '\*_key.pub' -type f -perm /133 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.3-etc_ssh_ssh_host_pub_key_user` | /etc/ssh/ssh host pub key user: find /etc/ssh/ -name '\*_key.pub' -type f ! -user root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.4-sshd_access_limited-attrs` | /etc/ssh/sshd_config.d/00-cis-sshd.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.4-sshd_access_limited-content` | /etc/ssh/sshd_config.d/00-cis-sshd.conf has the expected content (4 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.5-ssh_banner` | ssh banner: sshd -T 2>/dev/null \| grep -Ei '^(banner) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.5-ssh_configd_banner` | ssh configd banner: grep -Eis '^\\s\*Banner\\s+"?none\\b' /etc/ssh/sshd_config.d/\*.conf | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.6-sshd_ciphers` | sshd ciphers: sshd -T \| grep -Pi -- '^ciphers\\h+\\"?([^#\\n\\r]+,)?((3des\|blowfish\|cast128\|aes(128\|192\|256… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.7-sshd_clientalive` | sshd clientalive: sshd -T 2>/dev/null \| grep -Ei '^(clientaliveinterval\|clientalivecountmax) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.8-sshd_disableforwarding` | sshd disableforwarding: sshd -T 2>/dev/null \| grep -Ei '^(disableforwarding) ' | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.9-sshd_gssapiauth` | sshd gssapiauth: sshd -T 2>/dev/null \| grep -Ei '^(gssapiauthentication) ' | L2 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.10-ssh_hostbased_auth` | ssh hostbased auth: sshd -T 2>/dev/null \| grep -Ei '^(hostbasedauthentication) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.11-ssh_rhosts` | ssh rhosts: sshd -T 2>/dev/null \| grep -Ei '^(ignorerhosts) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.12-sshd_KEX` | sshd KEX: sshd -T \| grep -Pi -- 'kexalgorithms\\h+([^#\\n\\r]+,)?(diffie-hellman-group1-sha1\|diffie-he… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.13-ssh_logingrace` | ssh logingrace: sshd -T 2>/dev/null \| grep -Ei '^(logingracetime) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.14-ssh_loglevel` | ssh loglevel: sshd -T 2>/dev/null \| grep -Ei '^(loglevel) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.15-sshd_MACS` | sshd MACS: sshd -T \| grep -Pi -- 'macs\\h+([^#\\n\\r]+,)?(hmac-md5\|hmac-md5-96\|hmac-ripemd160\|hmac-sha1… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.16-sshd_authtries` | sshd authtries: sshd -T 2>/dev/null \| grep -Ei '^(maxauthtries) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.17-ssh_maxstartups` | ssh maxstartups: sshd -T 2>/dev/null \| grep -Ei '^(maxstartups) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.18-ssh_maxsessions` | ssh maxsessions: sshd -T 2>/dev/null \| grep -Ei '^(maxsessions) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.19-ssh_empty_passwd` | ssh empty passwd: sshd -T 2>/dev/null \| grep -Ei '^(permitemptypasswords) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.20-ssh_permit_root` | ssh permit root: sshd -T 2>/dev/null \| grep -Ei '^(permitrootlogin) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.21-ssh_userenv` | ssh userenv: sshd -T 2>/dev/null \| grep -Ei '^(permituserenvironment) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.22-ssh_usepam` | ssh usepam: sshd -T 2>/dev/null \| grep -Ei '^(usepam) ' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.1.23-sshd_pqc_kex` | sshd pqc kex: l_ver=$(sshd -V 2>&1 \| grep -Eio 'openssh_[0-9]+\\.[0-9]+' \| head -1 \| cut -d_ -f2) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.1-sudo` | Package sudo is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.2-sudoers_use_pty-attrs` | /etc/sudoers: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.2-sudoers_use_pty-content` | /etc/sudoers has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.2-pty_sudoers_d` | pty sudoers d: grep -rPi -- '^\\h\*Defaults\\h+([^#\\n\\r]+,\\h\*)?!use_pty\\b' /etc/sudoers /etc/sudoers.d/ | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.3-log_sudoers_d` | log sudoers d: grep -rPsi '^\\h\*Defaults\\h+([^#]+,\\h\*)?logfile\\h\*=\\h\*(\\"\|\\x27)?\\H+' /etc/sudoers /etc/sud… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.4-nopasswd_sudoers_d` | nopasswd sudoers d: grep -rhs -- '^[^#]\*NOPASSWD' /etc/sudoers /etc/sudoers.d \| awk '$1 !~ /^(#\|ec2-user\|vagr… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.2.5-authenticate_sudoers` | authenticate sudoers: grep -r "^[^#].\*\\!authenticate" /etc/sudoers\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.6-sudo_timeout` | sudo timeout: grep -rP "timestamp_timeout=\\K[0-9]\*" /etc/sudoers\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.7-su_conf-attrs` | /etc/pam.d/su: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.7-su_conf-content` | /etc/pam.d/su has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.7-sugroup_etc_group-attrs` | /etc/group: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.2.7-sugroup_etc_group-content` | /etc/group has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.1-libpam-runtime` | Package libpam-runtime is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.1-libpam_runtime_upgradable` | libpam runtime upgradable: apt list --upgradable 2>/dev/null \| grep -P '^libpam-runtime\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.2-libpam-modules` | Package libpam-modules is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.2-libpam_modules_upgradable` | libpam modules upgradable: apt list --upgradable 2>/dev/null \| grep -P '^libpam-modules\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.3-libpam-pwquality` | Package libpam-pwquality is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.3-libpam_pwquality_upgradable` | libpam pwquality upgradable: apt list --upgradable 2>/dev/null \| grep -P '^libpam-pwquality\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.4-cracklib-runtime` | Package cracklib-runtime is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.1.4-cracklib_runtime_upgradable` | cracklib runtime upgradable: apt list --upgradable 2>/dev/null \| grep -P '^cracklib-runtime\\b' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_act-attrs` | /etc/pam.d/common-account: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_act-content` | /etc/pam.d/common-account has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_auth-attrs` | /etc/pam.d/common-auth: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_auth-content` | /etc/pam.d/common-auth has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_password-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_password-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_session-attrs` | /etc/pam.d/common-session: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_session-content` | /etc/pam.d/common-session has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_session_nonint-attrs` | /etc/pam.d/common-session-noninteractive: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.1-pam_unix_enabled_common_session_nonint-content` | /etc/pam.d/common-session-noninteractive has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.2-pam_faillock_enabled_common_act-attrs` | /etc/pam.d/common-account: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.2-pam_faillock_enabled_common_act-content` | /etc/pam.d/common-account has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.2-pam_faillock_enabled_common_auth-attrs` | /etc/pam.d/common-auth: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.2-pam_faillock_enabled_common_auth-content` | /etc/pam.d/common-auth has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.3-pam_pwquality_enabled_common_passwd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.3-pam_pwquality_enabled_common_passwd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.4-pam_pwhistory_enabled_common_passwd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.2.4-pam_pwhistory_enabled_common_passwd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.1-faillock_attempts_deny-attrs` | /etc/security/faillock.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.1-faillock_attempts_deny-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.1-faillock_attempts_deny_removed` | faillock attempts deny removed: grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?deny\\b' /usr/share/pam-configs/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.2-faillock_unlock_time-attrs` | /etc/security/faillock.conf: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.2-faillock_unlock_time-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.2-faillock_unlock_time_removed` | faillock unlock time removed: grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?unlock_time\\b' /usr/share/pam-configs/\* | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.1.3-faillock_even_root-attrs` | /etc/security/faillock.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.3.3.1.3-faillock_even_root-content` | /etc/security/faillock.conf has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.3.3.1.3-faillock_even_root_removed` | faillock even root removed: grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?(even_deny_root\|root_unlock_time)' /usr/… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.3.3.2.1-passwd_change_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.1-passwd_change_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.1-password_character_changed` | password character changed: grep -Psi -- '^\\h\*difok\\h\*=\\h\*([2-9]\|[1-9][0-9]+)\\b' /etc/security/pwquality.conf /etc/se… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.2-password_minlen_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.2-password_minlen_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.2-password_minlen` | password minlen: grep -Psi -- '^\\h\*minlen\\h\*=\\h\*(1[4-9]\|[2-9][0-9]\|[1-9][0-9]{2,})\\b' /etc/security/pwqual… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.3-password_complex_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.3-password_complex_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.3-password_complex` | password complex: grep -Psi -- '^\\h\*(minclass\|[dulo]credit)\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.4-consecutive_characters_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.4-consecutive_characters_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.4-password_consecutive_characters` | password consecutive characters: grep -Psi -- '^\\h\*maxrepeat\\h\*=\\h\*[1-3]\\b' /etc/security/pwquality.conf /etc/security/pwq… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.5-maxseq_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.5-maxseq_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.5-password_maxseq` | password maxseq: grep -Psi -- '^\\h\*maxsequence\\h\*=\\h\*[1-3]\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.6-dictchk_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.6-dictchk_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.6-password_dictchk` | password dictchk: grep -Psi -- '^\\h\*dictcheck\\s\*=' /etc/security/pwquality.conf /etc/security/pwquality.con… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.7-quality_enforce_not_pamd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.7-quality_enforce_not_pamd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.7-password_quality_enforce` | password quality enforce: grep -Psi -- '^\\h\*enforcing\\s\*=\\s\*' /etc/security/pwquality.conf /etc/security/pwquality.… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.2.8-password_quality_enforce_root` | password quality enforce root: grep -Psi -- '^\\s\*enforce_for_root\\b' /etc/security/pwquality.conf /etc/security/pwqualit… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.1-pwhistory_remember_common_passwd-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.1-pwhistory_remember_common_passwd-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.1-pwhistory_remember_pam_configs` | pwhistory remember pam configs: for file in `awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.2-pwhistory_enforce_for_root-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.2-pwhistory_enforce_for_root-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.2-pwhistory_enforce_for_root_pam_configs` | pwhistory enforce for root pam configs: for file in `awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.3-pwhistory_use_authtok-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.3-pwhistory_use_authtok-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.3.3-pwhistory_use_authtok_pam_configs` | pwhistory use authtok pam configs: for file in `awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\\… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.4.1-pam_unix_nullok_pam_configs` | pam unix nullok pam configs: grep -PH -- '^\\h\*^\\h\*[^#\\n\\r]+\\h+pam_unix\\.so\\b' /etc/pam.d/common-password /etc/pam.d/co… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.4.2-pam_unix_remember_pam_configs` | pam unix remember pam configs: grep -PH -- '^\\h\*^\\h\*[^#\\n\\r]+\\h+pam_unix\\.so\\b' /etc/pam.d/common-password /etc/pam.d/co… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.4.3-pam_unix_strong_password_pam_configs` | pam unix strong password pam configs: grep -PH -- '^\\h\*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512\|yescrypt)… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.4.4-pam_unix_use_authtok_pam_configs-attrs` | /etc/pam.d/common-password: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.3.3.4.4-pam_unix_use_authtok_pam_configs-content` | /etc/pam.d/common-password has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.1-login_defs_PASS_MAX_DAYS-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.1-login_defs_PASS_MAX_DAYS-content` | /etc/login.defs has the expected content (3 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.1-users_max_pw_expire` | users max pw expire: awk -F: -v pu="" '($1 != pu && $2~/^\\$.+\\$/) {if($5 > 365 \|\| $5 < 1) print "FAIL: " $1 " … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.2-login_defs_PASS_MIN_DAYS-attrs` | /etc/login.defs: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.4.1.2-login_defs_PASS_MIN_DAYS-content` | /etc/login.defs has the expected content (3 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.4.1.2-users_min_pw_expire` | users min pw expire: awk -F: -v pu="" '($1 != pu && $2~/^\\$.+\\$/) {if($4 < 1) print "FAIL: " $1 " PASS_MIN_DAY… | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.4.1.3-login_def_PASS_WARN_AGE-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.3-login_def_PASS_WARN_AGE-content` | /etc/login.defs has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.3-user_expire_warn` | user expire warn: awk -F: '($2~/^\\$.+\\$/) {if($6 < 7) print "FAIL: " $1 " PASS_WARN_AGE: " $6}' /etc/shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.4-yescrypt_login_defs-attrs` | /etc/login.defs: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.4-yescrypt_login_defs-content` | /etc/login.defs has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.5-inactive_passwd` | inactive passwd: useradd -D \| grep INACTIVE | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.5-inactive_users` | inactive users: awk -F: '($2~/^\\$.+\\$/) {if($7 == "" \|\| $7 > 45 \|\| $7 < 0) print "FAIL: " $1 " INACTIVE: … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.1.6-passwd_chg_past` | No user has a last password change date in the future | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.1-root_only_uid_0` | root only uid 0: awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.2-root_only_gid_0` | root only gid 0: awk -F: '($1 !~ /^(sync\|shutdown\|halt\|operator)/ && $1 != "root" && $4 == 0) {print $1":"… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.3-group_root_only_0` | group root only 0: awk -F: '($3 == 0 && $1 != "root") {print $1":"$3}' /etc/group | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.4-root_passwd_set` | root passwd set: passwd -S root \| awk '$2 ~ /^(P\|L)/ {print "OK Password"}' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.5-root_path_check` | root path check: /bin/bash --login -c 'env \| grep ^PATH=' \| sed -e 's/^PATH=//' \| tr ':' '\\n' | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.6-root_umask_profile` | root umask profile: grep -Psi -- '^\\h\*umask\\h+((\\d{1,2}(\\d[^7]\|[^2-7]\\d)\\b)\|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.7-secure_system_accts` | secure system accts: uid_min=$(awk '/^[[:space:]]\*UID_MIN/ {print $2}' /etc/login.defs) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.2.8-test_valid_shells` | test valid shells: bash -c 'valid=$(awk -F/ "\\$NF != \\"nologin\\" && /^\\// {print}" /etc/shells) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.3.1-nologin_not_in_shells-attrs` | /etc/shells: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.4.3.1-nologin_not_in_shells-content` | /etc/shells has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-5.4.3.2-check_timeout` | check timeout: grep TMOUT /etc/profile.d/\*.sh /etc/profile /etc/profile.d/\*.sh\| cut -d ":" -f2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-5.4.3.3-umask_profile_scripts` | umask profile scripts: grep -i "^\\s\*umask" /etc/profile /etc/profile.d/\*.sh /etc/login.defs \| cut -d ":" -f 2 | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.1-systemd-journald-enabled` | Service systemd-journald is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.1-systemd-journald-running` | Service systemd-journald is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.2-systemd-journal-remote.service-masked` | Service systemd-journal-remote.service is masked or not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.2-systemd-journal-remote.service-running` | Service systemd-journal-remote.service is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.2-systemd-journal-remote.socket-masked` | Service systemd-journal-remote.socket is masked or not installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.2-systemd-journal-remote.socket-running` | Service systemd-journal-remote.socket is not running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.4-journald_tmpfiles_perms` | journald tmpfiles perms: for l_conf in /etc/tmpfiles.d/systemd.conf /usr/lib/tmpfiles.d/systemd.conf; do | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.5-log_rotate_journald_conf` | log rotate journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*(SystemMaxUse\|SystemK… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.6-storage_journald_conf` | storage journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*Storage\\h\*=' \| tail -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.1.1.7-compress_journald_conf` | compress journald conf: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*Compress\\h\*=' \| tail … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.3.1-logfile_configured` | logfile configured: find -L /var/log -type f \\( \\ | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.1.3.1-logfile_ownership_configured` | logfile ownership configured: bash -c 'find -L /var/log -type f \\( ! -user root -o ! -group root \\) -print0 \| while IFS… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.2.1.1-audispd-plugins` | Package audispd-plugins is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.1-audit_packages` | Package auditd is installed | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.2-auditd-enabled` | Service auditd is enabled | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.2-auditd-running` | Service auditd is running | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.3-grub_audit_start-attrs` | /etc/default/grub: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.3-grub_audit_start-content` | /etc/default/grub has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.3-auditd_grub` | auditd grub: grep "^\\s\*linux" /boot/grub/grub.cfg \| grep -Evc "audit=1" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.4-grub_audit_backlog-attrs` | /etc/default/grub: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.4-grub_audit_backlog-content` | /etc/default/grub has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.1.4-auditd_grub_backlog` | auditd grub backlog: grep "^\\s\*linux" /boot/grub/grub.cfg \| grep -Evc "audit_backlog_limit=" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.1-auditd_max_log_file-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.1-auditd_max_log_file-content` | /etc/audit/auditd.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.2-auditd_max_log_action-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.2-auditd_max_log_action-content` | /etc/audit/auditd.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.3-auditd_space_actions-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.3-auditd_space_actions-content` | /etc/audit/auditd.conf has the expected content (2 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.4-auditd_space_left_actions-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.2.4-auditd_space_left_actions-content` | /etc/audit/auditd.conf has the expected content (4 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.1-auditd_admin_scope_cnf` | auditd admin scope cnf: grep scope /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.1-auditd_admin_scope_live` | auditd admin scope live: auditctl -l \| grep scope | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.2-auditd_sudo_actions` | auditd sudo actions: grep user_emulation /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.2-auditd_sudo_actions_live` | auditd sudo actions live: auditctl -l \| grep user_emulation | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.3-auditd_sudolog_chg` | auditd sudolog chg: grep sudo_log_file /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.3-auditd_sudolog_chg_live` | auditd sudolog chg live: auditctl -l \| grep sudo_log_file | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.4-auditd_time_cnf` | auditd time cnf: grep time-change /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.4-auditd_time_live` | auditd time live: auditctl -l \| grep time-change | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.5-auditd_5_config` | auditd 5 config: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.5-auditd_5_live` | auditd 5 live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.6-auditd_6_config` | auditd 6 config: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.6-auditd_6_live` | auditd 6 live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.7-auditd_7_config` | auditd 7 config: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.7-auditd_7_live` | auditd 7 live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.8-auditd_8_config` | auditd 8 config: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.8-auditd_8_live` | auditd 8 live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.9-auditd_9_config` | auditd 9 config: grep system-locale /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.9-auditd_9_live` | auditd 9 live: auditctl -l \| grep system-locale | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.10-auditd_priv_cmds_cnf` | auditd priv cmds cnf: grep privileged /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.10-auditd_priv_cmds_live` | auditd priv cmds live: auditctl -l \| grep privileged | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.11-auditd_12_config` | auditd 12 config: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.11-auditd_12_live` | auditd 12 live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.12-auditd_13_config` | auditd 13 config: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.12-auditd_13_live` | auditd 13 live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.13-auditd_14_config` | auditd 14 config: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.13-auditd_14_live` | auditd 14 live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.14-auditd_15_config` | auditd 15 config: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.14-auditd_15_live` | auditd 15 live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.15-auditd_16_config` | auditd 16 config: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.15-auditd_16_live` | auditd 16 live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.16-auditd_17_config` | auditd 17 config: grep identity /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.16-auditd_17_live` | auditd 17 live: auditctl -l \| grep identity | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.17-auditd_access_cnf` | auditd access cnf: sh -c "grep auid /etc/audit/rules.d/\*.rules" | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.17-auditd_access_live` | auditd access live: auditctl -l \| grep access | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.18-auditd_perms_cnf` | auditd perms cnf: grep perm_mod /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.18-auditd_perms_live` | auditd perms live: auditctl -l \| grep perm_mod | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.19-auditd_mounts_cnf` | auditd mounts cnf: grep mounts /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.19-auditd_mounts_live` | auditd mounts live: auditctl -l \| grep mounts | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.20-auditd_session_live` | auditd session live: auditctl -l \| grep -E '(session\|logins)' | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.20-auditd_sessions_cnf` | auditd sessions cnf: grep -E '(session\|logins)' /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.21-auditd_logins_cnf` | auditd logins cnf: grep -R --include="\*.rules" logins /etc/audit/rules.d/ | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.21-auditd_logins_live` | auditd logins live: auditctl -l \| grep logins | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.22-auditd_delete_cnf` | auditd delete cnf: grep delete /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.22-auditd_delete_live` | auditd delete live: auditctl -l \| grep delete | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.23-auditd_MAC_cnf` | auditd MAC cnf: grep MAC-policy /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.23-auditd_MAC_live` | auditd MAC live: auditctl -l \| grep MAC-policy | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.24-chcon_module_cnf` | chcon module cnf: grep chcon /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.24-chcon_module_live` | chcon module live: auditctl -l \| grep chcon | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.25-setfacl_module_cnf` | setfacl module cnf: grep setfacl /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.25-setfacl_module_live` | setfacl module live: auditctl -l \| grep setfacl | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.26-chacl_module_cnf` | chacl module cnf: grep chacl /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.26-chacl_module_live` | chacl module live: auditctl -l \| grep chacl | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.27-usermod_module_cnf` | usermod module cnf: grep usermod /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.27-usermod_module_live` | usermod module live: auditctl -l \| grep usermod | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.28-auditd_admin_module_live` | auditd admin module live: auditctl -l \| grep kernel_module | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.28-auditd_module_cnf` | auditd module cnf: grep kernel_module /etc/audit/rules.d/\*.rules | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.29-auditd_immutable` | auditd immutable: grep -Ph -- '^\\h\*-e\\h+2\\b' /etc/audit/rules.d/\*.rules \| tail -1 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.3.30-auditd_config_match` | auditd config match: augenrules --check | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.1-audit_logfile_dir_perms-attrs` | The audit log directory: exists, is a directory, mode 0750 or stricter | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.2-audit_logfile_perms` | audit logfile perms: find "$d" -type f -perm /0137 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.3-audit_logfile_owner` | audit logfile owner: find "$d" -type f ! -user root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.4-audit_logfile_group_setting-attrs` | /etc/audit/auditd.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.4-audit_logfile_group_setting-content` | /etc/audit/auditd.conf has the expected content (1 rule) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.4-audit_logfile_group` | audit logfile group: find -L "$d" -maxdepth 1 -type f ! -group root ! -group adm | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_audisp-remote.conf-attrs` | /etc/audit/audisp-remote.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_audit-stop.rules-attrs` | /etc/audit/audit-stop.rules: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_audit.rules-attrs` | /etc/audit/audit.rules: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_auditd.conf-attrs` | /etc/audit/auditd.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_plugins.d_af_unix.conf-attrs` | /etc/audit/plugins.d/af_unix.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_plugins.d_au-remote.conf-attrs` | /etc/audit/plugins.d/au-remote.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_plugins.d_audispd-zos-remote.conf-attrs` | /etc/audit/plugins.d/audispd-zos-remote.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_plugins.d_syslog.conf-attrs` | /etc/audit/plugins.d/syslog.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_rules.d_audit.rules-attrs` | /etc/audit/rules.d/audit.rules: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms-etc_audit_zos-remote.conf-attrs` | /etc/audit/zos-remote.conf: mode 0640 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.5-audit_conf_perms` | audit conf perms: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) -perm /0137 | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_audisp-remote.conf-attrs` | /etc/audit/audisp-remote.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_audit-stop.rules-attrs` | /etc/audit/audit-stop.rules: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_audit.rules-attrs` | /etc/audit/audit.rules: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_auditd.conf-attrs` | /etc/audit/auditd.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_plugins.d_af_unix.conf-attrs` | /etc/audit/plugins.d/af_unix.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_plugins.d_au-remote.conf-attrs` | /etc/audit/plugins.d/au-remote.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_plugins.d_audispd-zos-remote.conf-attrs` | /etc/audit/plugins.d/audispd-zos-remote.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_plugins.d_syslog.conf-attrs` | /etc/audit/plugins.d/syslog.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_rules.d_audit.rules-attrs` | /etc/audit/rules.d/audit.rules: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner-etc_audit_zos-remote.conf-attrs` | /etc/audit/zos-remote.conf: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.6-audit_conf_owner` | audit conf owner: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -user root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_audisp-remote.conf-attrs` | /etc/audit/audisp-remote.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_audit-stop.rules-attrs` | /etc/audit/audit-stop.rules: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_audit.rules-attrs` | /etc/audit/audit.rules: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_auditd.conf-attrs` | /etc/audit/auditd.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_plugins.d_af_unix.conf-attrs` | /etc/audit/plugins.d/af_unix.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_plugins.d_au-remote.conf-attrs` | /etc/audit/plugins.d/au-remote.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_plugins.d_audispd-zos-remote.conf-attrs` | /etc/audit/plugins.d/audispd-zos-remote.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_plugins.d_syslog.conf-attrs` | /etc/audit/plugins.d/syslog.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_rules.d_audit.rules-attrs` | /etc/audit/rules.d/audit.rules: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group-etc_audit_zos-remote.conf-attrs` | /etc/audit/zos-remote.conf: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.7-audit_conf_group` | audit conf group: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -group root | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_auditctl-attrs` | /sbin/auditctl: mode 0755 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_auditd-attrs` | /sbin/auditd: mode 0755 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_augenrules-attrs` | /sbin/augenrules: mode 0755 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_aureport-attrs` | /sbin/aureport: mode 0755 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_ausearch-attrs` | /sbin/ausearch: mode 0755 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.8-audit_tools_perms-sbin_autrace-attrs` | /sbin/autrace: mode 0755 or stricter, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.9-audit_tools_owner-sbin_auditctl-attrs` | /sbin/auditctl: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.9-audit_tools_owner-sbin_auditd-attrs` | /sbin/auditd: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.9-audit_tools_owner-sbin_augenrules-attrs` | /sbin/augenrules: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.9-audit_tools_owner-sbin_aureport-attrs` | /sbin/aureport: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.9-audit_tools_owner-sbin_ausearch-attrs` | /sbin/ausearch: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.9-audit_tools_owner-sbin_autrace-attrs` | /sbin/autrace: owner root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.10-audit_tools_group-sbin_auditctl-attrs` | /sbin/auditctl: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.10-audit_tools_group-sbin_auditd-attrs` | /sbin/auditd: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.10-audit_tools_group-sbin_augenrules-attrs` | /sbin/augenrules: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.10-audit_tools_group-sbin_aureport-attrs` | /sbin/aureport: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.10-audit_tools_group-sbin_ausearch-attrs` | /sbin/ausearch: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.2.4.10-audit_tools_group-sbin_autrace-attrs` | /sbin/autrace: group root, if it exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.3.1-aide` | Package aide is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.3.1-aide-common` | Package aide-common is installed | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.3.2-dailyaidecheck.timer-enabled` | Service dailyaidecheck.timer is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.3.2-dailyaidecheck.timer-running` | Service dailyaidecheck.timer is running | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.3.2-dailyaidecheck_service-enabled` | Service dailyaidecheck.service is enabled | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-6.3.3-audit_tools_crypto-attrs` | /etc/aide/aide.conf: exists | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-6.3.3-audit_tools_crypto-content` | /etc/aide/aide.conf has the expected content (6 rules) | L2 server, L2 workstation | <span class="sev sev-low">low</span> |
| `CIS-UBUNTU24-7.1.1-passwd_perms-attrs` | /etc/passwd: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.2-passwd-_perms-attrs` | /etc/passwd-: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.3-group_perms-attrs` | /etc/group: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.4-group-_perms-attrs` | /etc/group-: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.5-shadow_perms-attrs` | /etc/shadow: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.6-shadow-_perms-attrs` | /etc/shadow-: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.7-gshadow_perms-attrs` | /etc/gshadow: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.8-gshadow-_perms-attrs` | /etc/gshadow-: exists, mode 0640 or stricter, owner root, group root or shadow | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.9-etc_shells_perms-attrs` | /etc/shells: exists, mode 0644 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.10-etc_security_opasswd_old_perms-attrs` | /etc/security/opasswd.old: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.10-etc_security_opasswd_perms-attrs` | /etc/security/opasswd: exists, mode 0600 or stricter, owner root, group root | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.11-world_writable` | world writable: df --local -P \| awk '{if (NR!=1) print $6}' \| xargs -I '{}' find '{}' -xdev -type f -perm… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.12-unowned_dirs` | unowned dirs: df --local -P \| awk {'if (NR!=1) print $6'} \| xargs -I '{}' find '{}' -xdev -nouser -o -n… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.1.13-audit_sgid` | audit sgid: findmnt -Dkerno fstype,target,options \| awk '($1 !~ /^[[:space:]]\*(nfs\|proc\|smb\|vfat\|iso9… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.1-shadowed_passwds-attrs` | /etc/passwd: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.1-shadowed_passwds-content` | /etc/passwd has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.2-passwd_fields_not_empty_shadow-attrs` | /etc/shadow: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.2-passwd_fields_not_empty_shadow-content` | /etc/shadow has the expected content (1 rule) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.3-passwd_group_exist` | passwd group exist: awk -F: 'FILENAME==ARGV[1]{g[$3];next} !($4 in g){print $1":"$4}' /etc/group /etc/passwd | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.4-shadow_group_empty-attrs` | /etc/group: exists | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.4-shadow_group_empty-content` | /etc/group has the expected content (2 rules) | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.4-shadow_group_primary` | shadow group primary: awk -F: -v g="$(getent group shadow \| cut -d: -f3)" '(g != "" && $4 == g) {print $1}' /et… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.5-no_dup_uid` | no dup uid: cat /etc/passwd \| cut -d: -f3 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.6-no_dup_gid` | no dup gid: cat /etc/group \| cut -d: -f3 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.7-no_dup_username` | no dup username: cat /etc/passwd \| cut -d: -f1 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.8-no_dup_groupname` | no dup groupname: cat /etc/group \| cut -d: -f1 \| sort \| uniq -d | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.9-home_dirs_exist` | home dirs exist: for i in `cat /etc/passwd \| grep -Ev "halt\|sync\|shutdown\|nfsnobody\|nologin\|false" \| cut -… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.9-home_dirs_ownership` | home dirs ownership: getent passwd \| awk -F: '$3 >= 1000 && $3 <= 60000 && $1 != "ftpd" {print $1, $6}' \| whil… | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.9-home_dirs_permissions` | home dirs permissions: getent passwd \| awk -F: '$3 >= 1000 && $3 <= 60000 {print $6}' \| while read dir; do [ -d … | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.10-bad_dot_files` | bad dot files: find /home/ -name "\\.forward" -o -name "\\.netrc" -o -name "\\.rhosts" | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.10-dot_file_bash_history` | dot file bash history: find /home/ -name "\\.bash_history" -perm /go+rwx | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |
| `CIS-UBUNTU24-7.2.10-dot_file_perms` | dot file perms: find /home/ -name "\\.\*" -perm /g+w,o+w \| grep -v .bash_history | L1 server, L1 workstation | <span class="sev sev-medium">medium</span> |

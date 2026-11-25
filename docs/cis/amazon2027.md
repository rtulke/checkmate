# CIS Amazon Linux 2027

Automated checks for 309 recommendations of the CIS Amazon Linux 2027 benchmark (version 0.0.1), converted from the goss audit content of the ansible-lockdown project. Check names describe what is verified; the recommendation number is in the ID and the description. Select profiles with tags, e.g. `--tags cis-level-1+cis-server`.

**Policy:** [`cis/amazon2027.yml`](https://github.com/rtulke/checkmate/blob/main/cis/amazon2027.yml) · **Benchmark version:** 0.0.1

```bash
checkmate run cis/amazon2027.yml --tags cis-level1-server
checkmate run cis/amazon2027.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-AMAZON2027-1.1.1.1-sys_module_overlay-absent` | /sys/module/overlay does not exist | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.1.1-modprobe_overlay` | modprobe overlay: modprobe --showconfig \| grep -P -- '\\b(install\|blacklist)\\h+overlay\\b' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.1.2-sys_module_squashfs-absent` | /sys/module/squashfs does not exist | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.1.2-modprobe_squashfs` | modprobe squashfs: modprobe --showconfig \| grep -P -- '\\b(install\|blacklist)\\h+squashfs\\b' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.1.3-sys_module_udf-absent` | /sys/module/udf does not exist | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.1.3-modprobe_udf` | modprobe udf: modprobe --showconfig \| grep -P -- '\\b(install\|blacklist)\\h+udf\\b' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.1.4-sys_module_usb_storage-absent` | /sys/module/usb_storage does not exist | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.1.4-modprobe_usb_storage` | modprobe usb storage: modprobe --showconfig \| grep -P -- '\\b(install\|blacklist)\\h+usb_storage\\b' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.1.5-unused_fs_kernel_modules` | unused fs kernel modules: l_search="$(readlink -e /usr/lib/modules/ \|\| readlink -e /lib/modules/)" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.1-tmp_mount` | /tmp is a separate mount | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.1-tmp_mount_unit_enabled` | tmp mount unit enabled: systemctl is-enabled tmp.mount | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.2-tmp_nodev_options` | /tmp is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.2-tmp_nodev_persistent_options` | tmp nodev persistent options: if [ "$(systemctl show tmp.mount -p SourcePath --value)" = "/etc/fstab" ]; then | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.3-tmp_nosuid_options` | /tmp is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.3-tmp_nosuid_persistent_options` | tmp nosuid persistent options: if [ "$(systemctl show tmp.mount -p SourcePath --value)" = "/etc/fstab" ]; then | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.4-tmp_noexec_options` | /tmp is a separate mount with noexec | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.1.4-tmp_noexec_persistent_options` | tmp noexec persistent options: if [ "$(systemctl show tmp.mount -p SourcePath --value)" = "/etc/fstab" ]; then | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.1-dev_shm_mount` | /dev/shm is a separate mount | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.2-dev_shm_nodev_options` | /dev/shm is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.2-dev_shm_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.2-dev_shm_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.3-dev_shm_nosuid_options` | /dev/shm is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.3-dev_shm_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.3-dev_shm_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.4-dev_shm_noexec_options` | /dev/shm is a separate mount with noexec | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.4-dev_shm_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.2.4-dev_shm_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.3.1-home_mount` | /home is a separate mount | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.2.3.2-home_nodev_options` | /home is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.3.2-home_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.3.2-home_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.3.3-home_nosuid_options` | /home is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.3.3-home_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.3.3-home_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.4.1-var_mount` | /var is a separate mount | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.2.4.2-var_nodev_options` | /var is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.4.2-var_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.4.2-var_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.4.3-var_nosuid_options` | /var is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.4.3-var_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.4.3-var_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.1-var_tmp_mount` | /var/tmp is a separate mount | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.2.5.2-var_tmp_nodev_options` | /var/tmp is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.2-var_tmp_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.2-var_tmp_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.3-var_tmp_nosuid_options` | /var/tmp is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.3-var_tmp_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.3-var_tmp_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.4-var_tmp_noexec_options` | /var/tmp is a separate mount with noexec | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.4-var_tmp_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.5.4-var_tmp_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.1-var_log_mount` | /var/log is a separate mount | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.2.6.2-var_log_nodev_options` | /var/log is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.2-var_log_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.2-var_log_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.3-var_log_nosuid_options` | /var/log is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.3-var_log_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.3-var_log_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.4-var_log_noexec_options` | /var/log is a separate mount with noexec | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.4-var_log_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.6.4-var_log_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.1-var_log_audit_mount` | /var/log/audit is a separate mount | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.1.2.7.2-var_log_audit_nodev_options` | /var/log/audit is a separate mount with nodev | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.2-var_log_audit_nodev_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.2-var_log_audit_nodev_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.3-var_log_audit_nosuid_options` | /var/log/audit is a separate mount with nosuid | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.3-var_log_audit_nosuid_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.3-var_log_audit_nosuid_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.4-var_log_audit_noexec_options` | /var/log/audit is a separate mount with noexec | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.4-var_log_audit_noexec_fstab_options-attrs` | /etc/fstab: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.1.2.7.4-var_log_audit_noexec_fstab_options-content` | /etc/fstab has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.1.1-gpg_keys` | gpg keys: rpm -q gpg-pubkey --queryformat '%{VERSION} %{PACKAGER}\\n' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.1.2-gpg_check_repo` | gpg check repo: echo "gpgcheck_disabled_repos=$(grep -Pris -- '^\\h\*(pkg_)?gpgcheck\\h\*=\\h\*(0\|false\|no)\\b' … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.1.2-gpgcheck_dnf_effective` | gpgcheck dnf effective: dnf --dump-main-config 2>/dev/null \| grep -Pi -- '^\\h\*pkg_gpgcheck\\h\*=' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.1.2-gpgcheck_repo_effective` | gpgcheck repo effective: echo "gpgcheck_disabled_repos=$(dnf --dump-repo-config='\*' 2>/dev/null \| grep -Pic -- '^\\… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.1.3-repo_gpgcheck_global` | repo gpgcheck global: dnf --dump-main-config 2>/dev/null \| grep -Pi -- '^\\h\*repo_gpgcheck\\h\*=' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.2.1.4-repos_configured` | repos configured: dnf repolist | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.1.5-dnf_install_weak_deps` | dnf install weak deps: dnf --dump-main-config 2>/dev/null \| grep -Pi -- '^\\h\*install_weak_deps\\h\*=' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.2.2.1-release-updates` | release updates: dnf check-release-update 2>&1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.2.2.1-security-updates` | security updates: dnf check-update | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.1-libselinux` | Package libselinux is installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.2-selinux_disabled_boot` | selinux disabled boot: echo "boot_entries=$(grubby --info=ALL 2>/dev/null \| grep -Pc '^\\h\*args=.\*\\b(selinux\|enfo… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.3-selinux_policy` | selinux policy: grep SELINUXTYPE= /etc/selinux/config | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.3-selinux_sestatus` | selinux sestatus: sestatus \| grep 'Loaded policy' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.4-getenforce_set` | getenforce set: getenforce | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.5-etc_selinux_config-attrs` | /etc/selinux/config: exists | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.3.1.5-etc_selinux_config-content` | /etc/selinux/config has the expected content (1 rule) | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.3.1.5-getenforce_enforcing` | getenforce enforcing: getenforce | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.3.1.6-selinux_unconfined` | selinux unconfined: ps -eZ \| grep unconfined_service_t | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.3.1.7-mctrans` | Package mctrans is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.3.1.8-setroubleshoot` | Package setroubleshoot is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.4.2-efi_boot_opts` | efi boot opts: l_opts="$(awk '$1 !~ /^#/ && $2 == "/boot/efi" {print $4}' /etc/fstab)" | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.4.2-grub_bootloader_files_access` | grub bootloader files access: find /boot -type f \\( -name 'grub\*' -o -name 'user.cfg' \\) -exec stat -Lc '%n %a %U %G' {… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.4.3-rescue_service_sulogin` | rescue service sulogin: systemctl show -p ExecStart --value rescue.service | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.4.4-emergency_service_sulogin` | emergency service sulogin: systemctl show -p ExecStart --value emergency.service | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.4.5-grubby_confirm_spawn` | grubby confirm spawn: echo "boot_entries=$(grubby --info=ALL 2>/dev/null \| grep -Pc '^\\h\*args=.\*\\bsystemd\\.conf… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.1-fs.protected_hardlinks` | Kernel parameter fs.protected_hardlinks is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.1-fs_protected_hardlinks_persistent` | fs protected hardlinks persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*fs[.]protected_hard… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.2-fs.protected_symlinks` | Kernel parameter fs.protected_symlinks is 1 | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.5.2-fs_protected_symlinks_persistent` | fs protected symlinks persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*fs[.]protected_syml… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.5.3-fs.suid_dumpable` | Kernel parameter fs.suid_dumpable is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.3-fs_suid_dumpable_persistent` | fs suid dumpable persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*fs[.]suid_dumpable[… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.4-kernel.dmesg_restrict` | Kernel parameter kernel.dmesg_restrict is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.4-kernel_dmesg_restrict_persistent` | kernel dmesg restrict persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*kernel[.]dmesg_rest… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.5-kernel.kptr_restrict` | Kernel parameter kernel.kptr_restrict matches ^(1\|2)$ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.5-kernel_kptr_restrict_persistent` | kernel kptr restrict persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*kernel[.]kptr_restr… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.6-kernel.randomize_va_space` | Kernel parameter kernel.randomize_va_space is 2 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.6-kernel_randomize_va_space_persistent` | kernel randomize va space persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*kernel[.]randomize_… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.7-kernel.yama.ptrace_scope` | Kernel parameter kernel.yama.ptrace_scope matches ^(1\|2\|3)$ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.7-kernel_yama_ptrace_scope_persistent` | kernel yama ptrace scope persistent: /usr/lib/systemd/systemd-sysctl --cat-config \| grep -Eo '^[[:space:]]\*kernel[.]yama[.]ptr… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.8-hard_core_limit` | hard core limit: grep -Pshi -- '^\\h\*[^#\\n\\r]+\\h+hard\\h+core\\b' /etc/security/limits.conf /etc/security/lim… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.9-coredump_processsizemax_effective` | coredump processsizemax effective: systemd-analyze cat-config systemd/coredump.conf \| grep -E '^[[:space:]]\*ProcessSizeMax[[… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.5.10-coredump_storage_effective` | coredump storage effective: systemd-analyze cat-config systemd/coredump.conf \| grep -E '^[[:space:]]\*Storage[[:space:… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.1-crypto_policies_config` | crypto policies config: cat /etc/crypto-policies/config | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.2-crypto_policies_no_sha1_current-attrs` | /etc/crypto-policies/state/CURRENT.pol: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.2-crypto_policies_no_sha1_current-content` | /etc/crypto-policies/state/CURRENT.pol has the expected content (3 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.2-crypto_policies_no_sha1_scopes` | crypto policies no sha1 scopes: echo "sha1_nonexempt_scopes=$(grep -Pi -- '^\\h\*(hash\|sign)@\\S+\\h\*=.\*SHA-?1\\b' /etc/crypto… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.3-crypto_policies_no_weakmacs-attrs` | /etc/crypto-policies/state/CURRENT.pol: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.3-crypto_policies_no_weakmacs-content` | /etc/crypto-policies/state/CURRENT.pol has the expected content (2 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.4-crypto_policies_no_ssh_cbc` | crypto policies no ssh cbc: f=/etc/crypto-policies/state/CURRENT.pol | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.5-crypto_policies_no_ssh_chacha20` | crypto policies no ssh chacha20: f=/etc/crypto-policies/state/CURRENT.pol | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.6-crypto_policies_no_ssh_etm` | crypto policies no ssh etm: f=/etc/crypto-policies/state/CURRENT.pol | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.6.7-crypto_policies_pq` | crypto policies pq: echo "policy:$(cat /etc/crypto-policies/config 2>/dev/null \| xargs)" | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-1.7.1-motd_no_system_info` | motd no system info: l_os="$(grep -Po '^ID="?\\K[^"]+' /etc/os-release)\|$(grep -Po '^NAME="?\\K[^"]+' /etc/os-re… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.2-etc_issue_banner-attrs` | /etc/issue: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.2-etc_issue_banner-content` | /etc/issue has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.2-etc_issue_no_system_info` | etc issue no system info: os_id=$(. /etc/os-release; echo "$ID") | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.3-etc_issue_net_no_system_info` | etc issue net no system info: os_id=$(. /etc/os-release; echo "$ID") | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.4-etc_motd_access` | etc motd access: if [ -e /etc/motd ]; then stat -Lc '%a %U %G' /etc/motd; else echo motd_absent; fi | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.5-etc_issue_access` | etc issue access: if [ -e /etc/issue ]; then stat -Lc '%a %U %G' /etc/issue; else echo issue_absent; fi | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-1.7.6-etc_issue_net_access` | etc issue net access: if [ -e /etc/issue.net ]; then stat -Lc '%a %U %G' /etc/issue.net; else echo issue_net_ab… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.1-cis_2_1_1_autofs_pkg` | Package autofs is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.2-cis_2_1_2_avahi_pkg` | Package avahi is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.3-cis_2_1_3_bind_pkg` | Package bind is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.4-cis_2_1_4_dnsmasq_pkg` | Package dnsmasq is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.5-cis_2_1_5_samba_pkg` | Package samba is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.6-cis_2_1_6_vsftpd_pkg` | Package vsftpd is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.7-cis_2_1_7_dovecot_pkg` | Package dovecot is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.9-cis_2_1_9_cups_pkg` | Package cups is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.11-cis_2_1_11_rsync_daemon_pkg` | Package rsync-daemon is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.12-cis_2_1_12_net_snmp_pkg` | Package net-snmp is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.13-cis_2_1_13_telnet_server_pkg` | Package telnet-server is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.14-cis_2_1_14_tftp_server_pkg` | Package tftp-server is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.15-cis_2_1_15_squid_pkg` | Package squid is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.16-cis_2_1_16_httpd_pkg` | Package httpd is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.16-cis_2_1_16_nginx_pkg` | Package nginx is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.17-cis_2_1_17_mta_listening_ports` | cis 2 1 17 mta listening ports: ss -plntu \| grep -P -- ':(25\|465\|587)\\b' \| grep -Pv -- '\\h+(127\\.0\\.0\\.1\|\\[?::1\\]?):(25\|4… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.17-cis_2_1_17_postfix_inet_interfaces` | cis 2 1 17 postfix inet interfaces: if command -v postconf >/dev/null 2>&1; then | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.1.18-cis_2_1_18_gdm_pkg` | Package gdm is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.18-cis_2_1_18_gnome-shell_pkg` | Package gnome-shell is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.18-cis_2_1_18_tigervnc-server_pkg` | Package tigervnc-server is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.18-cis_2_1_18_default_target` | cis 2 1 18 default target: systemctl get-default | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.19-cis_2_1_19_tigervnc-server-minimal_pkg` | Package tigervnc-server-minimal is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.19-cis_2_1_19_xorg-x11-server-common_pkg` | Package xorg-x11-server-common is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.20-cis_2_1_20_xwayland_pkg` | Package xorg-x11-server-Xwayland is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.1.21-manual_listening_ports` | manual listening ports: echo "Manual!! - Please check only approved services are listening" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.2.1-cis_2_2_1_ftp_pkg` | Package ftp is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.2.1-cis_2_2_1_lftp_pkg` | Package lftp is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.2.2-cis_2_2_2_openldap_clients_pkg` | Package openldap-clients is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-2.2.3-cis_2_2_3_telnet_pkg` | Package telnet is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.2.4-cis_2_2_4_tftp_pkg` | Package tftp is not installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.3.1-chrony_installed` | Package chrony is installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.3.2-cis_2_3_2_chrony_sources` | cis 2 3 2 chrony sources: grep -Ph -- '^\\h\*(server\|pool\|refclock)\\h+\\H+' /etc/chrony.conf 2>/dev/null | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.3.3-cis_2_3_3_chronyd_sysconfig-attrs` | /etc/sysconfig/chronyd: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.3.3-cis_2_3_3_chronyd_sysconfig-content` | /etc/sysconfig/chronyd has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.3.3-cis_2_3_3_chrony_user_root` | cis 2 3 3 chrony user root: grep -PHsi -- '^\\h\*user\\h+root\\b' /etc/chrony.conf /etc/chrony.d/\*.conf \|\| true | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.3.3-cis_2_3_3_chronyd_process_user` | cis 2 3 3 chronyd process user: ps -C chronyd -o user= \|\| true | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.1-cis_2_4_1_1_crond-enabled` | Service crond.service is enabled | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.1-cis_2_4_1_1_crond-running` | Service crond.service is running | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.2-cis_2_4_1_2_crontab-attrs` | /etc/crontab: exists, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.3-cis_2_4_1_3_cron_hourly-attrs` | /etc/cron.hourly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.4-cis_2_4_1_4_cron_daily-attrs` | /etc/cron.daily: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.5-cis_2_4_1_5_cron_weekly-attrs` | /etc/cron.weekly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.6-cis_2_4_1_6_cron_monthly-attrs` | /etc/cron.monthly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.7-cis_2_4_1_7_cron_yearly-attrs` | /etc/cron.yearly: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.8-cis_2_4_1_8_cron_d-attrs` | /etc/cron.d: exists, is a directory, mode 0700 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.9-cis_2_4_1_9_cron_allow-attrs` | /etc/cron.allow: exists, mode 0640 or stricter, owner root, group root or crontab | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.1.9-cis_2_4_1_9_cron_deny-absent` | /etc/cron.deny does not exist | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.2.1-cis_2_4_2_1_at_allow-attrs` | /etc/at.allow: exists, mode 0640 or stricter, owner root, group root or daemon | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-2.4.2.1-cis_2_4_2_1_at_deny-absent` | /etc/at.deny does not exist | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.1.1-cis_3_1_1_ipv6_required` | cis 3 1 1 ipv6 required: if [ `grep 0 /proc/sys/net/ipv6/conf/all/disable_ipv6` ] \|\| [ `grep 0 /proc/sys/net/ipv6/… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.1.2-cis_3_1_2_bluez_pkg` | Package bluez is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-3.2.1-cis_3_2_1_rds_not_available` | cis 3 2 1 rds not available: l_mod="rds" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.2.2-cis_3_2_2_sctp_not_available` | cis 3 2 2 sctp not available: l_mod="sctp" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.2.3-cis_3_2_3_can_not_available` | cis 3 2 3 can not available: l_mod="can" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.1-net.ipv4.ip_forward` | Kernel parameter net.ipv4.ip_forward is 0 | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-3.3.1.1-cis_3_3_1_1_sysctl_conf` | cis 3 3 1 1 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-3.3.1.2-net.ipv4.conf.all.forwarding` | Kernel parameter net.ipv4.conf.all.forwarding is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.2-cis_3_3_1_2_sysctl_conf` | cis 3 3 1 2 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.3-net.ipv4.conf.default.forwarding` | Kernel parameter net.ipv4.conf.default.forwarding is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.3-cis_3_3_1_3_sysctl_conf` | cis 3 3 1 3 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.4-net.ipv4.conf.all.send_redirects` | Kernel parameter net.ipv4.conf.all.send_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.4-cis_3_3_1_4_sysctl_conf` | cis 3 3 1 4 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.5-net.ipv4.conf.default.send_redirects` | Kernel parameter net.ipv4.conf.default.send_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.5-cis_3_3_1_5_sysctl_conf` | cis 3 3 1 5 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.6-net.ipv4.icmp_ignore_bogus_error_respons` | Kernel parameter net.ipv4.icmp_ignore_bogus_error_responses is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.6-cis_3_3_1_6_sysctl_conf` | cis 3 3 1 6 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.7-net.ipv4.icmp_echo_ignore_broadcasts` | Kernel parameter net.ipv4.icmp_echo_ignore_broadcasts is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.7-cis_3_3_1_7_sysctl_conf` | cis 3 3 1 7 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.8-net.ipv4.conf.all.accept_redirects` | Kernel parameter net.ipv4.conf.all.accept_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.8-cis_3_3_1_8_sysctl_conf` | cis 3 3 1 8 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.9-net.ipv4.conf.default.accept_redirects` | Kernel parameter net.ipv4.conf.default.accept_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.9-cis_3_3_1_9_sysctl_conf` | cis 3 3 1 9 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.10-net.ipv4.conf.all.secure_redirects` | Kernel parameter net.ipv4.conf.all.secure_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.10-cis_3_3_1_10_sysctl_conf` | cis 3 3 1 10 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.11-net.ipv4.conf.default.secure_redirects` | Kernel parameter net.ipv4.conf.default.secure_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.11-cis_3_3_1_11_sysctl_conf` | cis 3 3 1 11 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.12-net.ipv4.conf.all.rp_filter` | Kernel parameter net.ipv4.conf.all.rp_filter is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.12-cis_3_3_1_12_sysctl_conf` | cis 3 3 1 12 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.13-net.ipv4.conf.default.rp_filter` | Kernel parameter net.ipv4.conf.default.rp_filter is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.13-cis_3_3_1_13_sysctl_conf` | cis 3 3 1 13 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.14-net.ipv4.conf.all.accept_source_route` | Kernel parameter net.ipv4.conf.all.accept_source_route is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.14-cis_3_3_1_14_sysctl_conf` | cis 3 3 1 14 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.15-net.ipv4.conf.default.accept_source_rout` | Kernel parameter net.ipv4.conf.default.accept_source_route is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.15-cis_3_3_1_15_sysctl_conf` | cis 3 3 1 15 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.16-net.ipv4.conf.all.log_martians` | Kernel parameter net.ipv4.conf.all.log_martians is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.16-cis_3_3_1_16_sysctl_conf` | cis 3 3 1 16 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.17-net.ipv4.conf.default.log_martians` | Kernel parameter net.ipv4.conf.default.log_martians is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.17-cis_3_3_1_17_sysctl_conf` | cis 3 3 1 17 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.18-net.ipv4.tcp_syncookies` | Kernel parameter net.ipv4.tcp_syncookies is 1 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.18-cis_3_3_1_18_sysctl_conf` | cis 3 3 1 18 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.19-net.ipv4.conf.all.route_localnet` | Kernel parameter net.ipv4.conf.all.route_localnet is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.19-cis_3_3_1_19_sysctl_conf` | cis 3 3 1 19 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.20-net.ipv4.conf.default.route_localnet` | Kernel parameter net.ipv4.conf.default.route_localnet is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.1.20-cis_3_3_1_20_sysctl_conf` | cis 3 3 1 20 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.1-cis_3_3_2_1_force_forwarding` | cis 3 3 2 1 force forwarding: sysctl -a 2>/dev/null \| grep -P -- '^net\\.ipv6\\.conf\\.\\S+\\.force_forwarding\\h\*=\\h\*1\\b' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.2-net.ipv6.conf.all.forwarding` | Kernel parameter net.ipv6.conf.all.forwarding is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.2-cis_3_3_2_2_sysctl_conf` | cis 3 3 2 2 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.3-net.ipv6.conf.default.forwarding` | Kernel parameter net.ipv6.conf.default.forwarding is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.3-cis_3_3_2_3_sysctl_conf` | cis 3 3 2 3 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.4-net.ipv6.conf.all.accept_redirects` | Kernel parameter net.ipv6.conf.all.accept_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.4-cis_3_3_2_4_sysctl_conf` | cis 3 3 2 4 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.5-net.ipv6.conf.default.accept_redirects` | Kernel parameter net.ipv6.conf.default.accept_redirects is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.5-cis_3_3_2_5_sysctl_conf` | cis 3 3 2 5 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.6-net.ipv6.conf.all.accept_source_route` | Kernel parameter net.ipv6.conf.all.accept_source_route is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.6-cis_3_3_2_6_sysctl_conf` | cis 3 3 2 6 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.7-net.ipv6.conf.default.accept_source_rout` | Kernel parameter net.ipv6.conf.default.accept_source_route is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.7-cis_3_3_2_7_sysctl_conf` | cis 3 3 2 7 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.8-net.ipv6.conf.all.accept_ra` | Kernel parameter net.ipv6.conf.all.accept_ra is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.8-cis_3_3_2_8_sysctl_conf` | cis 3 3 2 8 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.9-net.ipv6.conf.default.accept_ra` | Kernel parameter net.ipv6.conf.default.accept_ra is 0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-3.3.2.9-cis_3_3_2_9_sysctl_conf` | cis 3 3 2 9 sysctl conf: l_sysctl="$(readlink -e /usr/lib/systemd/systemd-sysctl \|\| readlink -e /lib/systemd/syste… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-4.1.1-firewalld` | Package firewalld is installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.2-etc_firewalld_firewalld.conf-attrs` | /etc/firewalld/firewalld.conf: exists | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.2-etc_firewalld_firewalld.conf-content` | /etc/firewalld/firewalld.conf has the expected content (1 rule) | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.3-firewalld-enabled` | Service firewalld is enabled | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.3-firewalld-running` | Service firewalld is running | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.5-cis_4_1_5_loopback_zone_target` | cis 4 1 5 loopback zone target: l_zone="$(firewall-cmd --get-zone-of-interface=lo 2>&1 \| xargs)" | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.6-cis_4_1_6_loopback_rich_rules` | cis 4 1 6 loopback rich rules: l_zone="$(firewall-cmd --get-zone-of-interface=lo 2>/dev/null \| xargs)" | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.7-firewall_drop_unncessary_ports_manual` | firewall drop unncessary ports manual: echo "Manual test" | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.8-cis_4_1_8_default_zone_drop` | cis 4 1 8 default zone drop: firewall-cmd --get-default-zone | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.9-iptables-services` | Package iptables-services is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.9-ufw` | Package ufw is not installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.9-cis_4_1_9_nftables_service-enabled` | Service nftables is not enabled | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.9-cis_4_1_9_nftables_service-running` | Service nftables is not running | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.10-cis_4_1_10_log_denied` | cis 4 1 10 log denied: firewall-cmd --get-log-denied | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-4.1.11-cis_4_1_11_icmp_timestamp` | cis 4 1 11 icmp timestamp: l_fail="" | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.1.1-sshd_config_perms-attrs` | /etc/ssh/sshd_config: exists, mode 0600 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.1-sshd_config_d_conf_perms` | sshd config d conf perms: find /etc/ssh/sshd_config.d/ -type f -name '\*.conf' \\( -perm /177 -o ! -user root -o ! -g… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.2-sshd_config_d_dir_perms` | sshd config d dir perms: find /etc/ssh/sshd_config.d/ -maxdepth 0 \\( ! -user root -o ! -group root -o -perm /077 \\… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.3-ssh_host_private_key_access` | ssh host private key access: l_ssh_group="" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.4-ssh_host_public_key_access` | ssh host public key access: sshd -T 2>/dev/null \| awk 'tolower($1)=="hostkey"{print $2}' \| while IFS= read -r l_key; … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.5-no_weak_ssh_ciphers` | no weak ssh ciphers: l_offered="$(sshd -T 2>/dev/null \| awk 'tolower($1)=="ciphers"{print $2}')" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.6-no_weak_ssh_kex` | no weak ssh kex: l_offered="$(sshd -T 2>/dev/null \| awk 'tolower($1)=="kexalgorithms"{print $2}')" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.7-no_weak_ssh_macs` | no weak ssh macs: l_offered="$(sshd -T 2>/dev/null \| awk 'tolower($1)=="macs"{print $2}')" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.8-sshd_access_limited` | SSH access is limited with AllowUsers, AllowGroups, DenyUsers or DenyGroups | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.9-sshd_banner_content` | sshd banner content: l_banner="$(sshd -T 2>/dev/null \| awk 'tolower($1) == "banner" {print $2}')" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.9-sshd_banner_live` | sshd banner live: sshd -T 2>/dev/null \| grep -Pi -- '^banner\\h+\\/\\H+' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.10-sshd_clientalive_live` | sshd clientalive live: sshd -T 2>/dev/null \| grep -Pi -- '^(clientaliveinterval\|clientalivecountmax)\\h' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.11-ssh_disable_forward_live` | ssh disable forward live: sshd -T 2>/dev/null \| grep -i -- '^disableforwarding\\s' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.1.12-ssh_gssapi_live` | ssh gssapi live: sshd -T 2>/dev/null \| grep -i -- '^gssapiauthentication\\s' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.1.13-ssh_hostbased_auth_live` | ssh hostbased auth live: sshd -T 2>/dev/null \| grep -i -- '^hostbasedauthentication\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.14-ssh_rhosts_live` | ssh rhosts live: sshd -T 2>/dev/null \| grep -i -- '^ignorerhosts\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.15-ssh_logingrace_live` | ssh logingrace live: sshd -T 2>/dev/null \| grep -i -- '^logingracetime\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.16-ssh_loglevel_live` | ssh loglevel live: sshd -T 2>/dev/null \| grep -i -- '^loglevel\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.17-sshd_authtries_live` | sshd authtries live: sshd -T 2>/dev/null \| grep -i -- '^maxauthtries\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.18-ssh_maxstartups_live` | ssh maxstartups live: sshd -T 2>/dev/null \| awk 'tolower($1) == "maxstartups" {split($2, a, ":"); if (a[1] > 10… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.19-ssh_maxsessions_config` | ssh maxsessions config: grep -Psi -- '^\\h\*MaxSessions\\h+\\"?(1[1-9]\|[2-9][0-9]\|[1-9][0-9][0-9]+)\\b' /etc/ssh/sshd_… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.19-ssh_maxsessions_live` | ssh maxsessions live: sshd -T 2>/dev/null \| grep -i -- '^maxsessions\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.20-ssh_empty_passwd_live` | ssh empty passwd live: sshd -T 2>/dev/null \| grep -i -- '^permitemptypasswords\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.21-ssh_permit_root_live` | ssh permit root live: sshd -T 2>/dev/null \| grep -i -- '^permitrootlogin\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.22-ssh_userenv_live` | ssh userenv live: sshd -T 2>/dev/null \| grep -i -- '^permituserenvironment\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.1.23-ssh_usepam_live` | ssh usepam live: sshd -T 2>/dev/null \| grep -i -- '^usepam\\s' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.1-sudo` | Package sudo is installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.2-sudoers_files_access` | sudoers files access: find /etc/sudoers /etc/sudoers.d/ -type f \\( -perm /0337 -o ! -user root -o ! -group root… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.3-sudoers_d_dir_access` | sudoers d dir access: find /etc/sudoers.d -maxdepth 0 -type d \\( -perm /0027 -o ! -user root -o ! -group root \\… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.4-pty_sudoers_d_not_disabled` | pty sudoers d not disabled: grep -rPi -- '^\\h\*Defaults\\h+([^#\\n\\r]+,\\h\*)?!use_pty\\b' /etc/sudoers /etc/sudoers.d/ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.5-log_sudoers_d` | log sudoers d: grep -rPsi -- '^\\h\*Defaults\\h+([^#\\n\\r]+,\\h\*)?logfile\\h\*=\\h\*\\S+' /etc/sudoers /etc/sudoer… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.6-nopasswd_sudoers_d` | nopasswd sudoers d: grep -r "^[^#].\*NOPASSWD" /etc/sudoers /etc/sudoers.d/ | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.2.7-authenticate_sudoers` | authenticate sudoers: grep -r '^[^#].\*!authenticate' /etc/sudoers /etc/sudoers.d/ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.8-sudo_pwfeedback` | sudo pwfeedback: grep -rPi -- '^\\h\*Defaults\\h+([^#\\n\\r]+,\\h\*)?pwfeedback\\b' /etc/sudoers /etc/sudoers.d/ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.9-sudo_visiblepw` | sudo visiblepw: grep -rPi -- '^\\h\*Defaults\\h+([^#\\n\\r]+,\\h\*)?visiblepw\\b' /etc/sudoers /etc/sudoers.d/ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.10-sudo_timeout` | sudo timeout: grep -rhoPi -- '^[^#\\n\\r]\*timestamp_timeout\\h\*=\\h\*\\K-?[0-9.]+' /etc/sudoers /etc/sudoers.… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.11-sudo_timestamp_type` | sudo timestamp type: grep -rPi -- 'timestamp_type\\h\*=\\h\*global' /etc/sudoers /etc/sudoers.d/ | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.12-restrict_su-attrs` | /etc/pam.d/su: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.12-restrict_su-content` | /etc/pam.d/su has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.2.12-sugroup_etc_group` | The group that pam_wheel allows to use su has no members | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.1.1-pam_version` | pam version: l_inst="$(rpm -q --qf '%{VERSION}-%{RELEASE}' pam)" && [ "$(printf '%s\\n%s\\n' '1.5.1-8' "… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.1.3-libpwquality_version` | libpwquality version: l_inst="$(rpm -q --qf '%{VERSION}-%{RELEASE}' libpwquality)" && [ "$(printf '%s\\n%s\\n' '1… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.2.5-pam_unix_enabled_password_auth-attrs` | /etc/pam.d/password-auth: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.2.5-pam_unix_enabled_password_auth-content` | /etc/pam.d/password-auth has the expected content (4 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.2.5-pam_unix_enabled_system_auth-attrs` | /etc/pam.d/system-auth: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.2.5-pam_unix_enabled_system_auth-content` | /etc/pam.d/system-auth has the expected content (4 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.1-faillock_attempts_deny-attrs` | /etc/security/faillock.conf: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.1-faillock_attempts_deny-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.1-faillock_attempts_deny_pam` | faillock attempts deny pam: grep -Pi -- '^\\h\*auth\\h+(requisite\|required\|sufficient)\\h+pam_faillock\\.so\\h+([^#\\n\\r]+\\h… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.2-faillock_unlock_time-attrs` | /etc/security/faillock.conf: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.2-faillock_unlock_time-content` | /etc/security/faillock.conf has the expected content (2 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.2-faillock_unlock_time_pam` | faillock unlock time pam: grep -Pi -- '^\\h\*auth\\h+(requisite\|required\|sufficient)\\h+pam_faillock\\.so\\h+([^#\\n\\r]+\\h… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.1.3-faillock_even_root-attrs` | /etc/security/faillock.conf: exists | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.3.3.1.3-faillock_even_root-content` | /etc/security/faillock.conf has the expected content (2 rules) | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.3.3.1.3-faillock_even_root_pam` | faillock even root pam: grep -Pi -- '^\\h\*auth\\h+([^#\\n\\r]+\\h+)pam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?root_unlock_time\\… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.3.3.2.1-passwd_change_not_pamd` | passwd change not pamd: grep -Psi -- '^\\s\*password\\s+(requisite\|required\|sufficient)\\s+pam_pwquality\\.so\\s+([^#\\n… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.1-password_character_changed` | password character changed: grep -Psi -- '^\\h\*difok\\h\*=\\h\*([2-9]\|[1-9][0-9]+)\\b' /etc/security/pwquality.conf /etc/se… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.2-password_minlen` | password minlen: grep -Psi -- '^\\h\*minlen\\h\*=\\h\*(1[4-9]\|[2-9][0-9]\|[1-9][0-9]{2,})\\b' /etc/security/pwqual… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.2-password_minlen_not_pamd` | password minlen not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.3-password_complex` | password complex: grep -Psi -- '^\\h\*(minclass\|[dulo]credit)\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.3-password_complex_not_pamd` | password complex not pamd: grep -Psi -- '^\\s\*password\\s+(requisite\|required\|sufficient)\\s+pam_pwquality\\.so\\s+([^#\\n… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.4-consecutive_characters_not_pamd` | consecutive characters not pamd: grep -Psi -- '^\\s\*password\\s+(requisite\|required\|sufficient)\\s+pam_pwquality\\.so\\s+([^#\\n… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.4-password_consecutive_characters` | password consecutive characters: grep -Psi -- '^\\s\*maxrepeat\\s\*=\\s\*[1-3]\\b' /etc/security/pwquality.conf /etc/security/pwq… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.5-maxseq_not_pamd` | maxseq not pamd: grep -Psi -- '^\\s\*password\\s+(requisite\|required\|sufficient)\\s+pam_pwquality\\.so\\s+([^#\\n… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.5-password_maxseq` | password maxseq: grep -Psi -- '^\\s\*maxsequence\\s\*=\\s\*[1-3]\\b' /etc/security/pwquality.conf /etc/security/p… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.6-dictchk_not_pamd` | dictchk not pamd: grep -Psi -- '^\\h\*password\\h+(requisite\|required\|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.6-password_dictchk` | password dictchk: grep -Psi -- '^\\h\*dictcheck\\h\*=\\h\*0\\b' /etc/security/pwquality.conf /etc/security/pwquali… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.3.3.2.7-password_quality_enforce_root` | password quality enforce root: grep -Psi -- '^\\s\*enforce_for_root\\b' /etc/security/pwquality.conf /etc/security/pwqualit… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.1-login_defs_max_days-attrs` | /etc/login.defs: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.1-login_defs_max_days-content` | /etc/login.defs has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.2-login_defs_min_days-attrs` | /etc/login.defs: exists | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.4.1.2-login_defs_min_days-content` | /etc/login.defs has the expected content (1 rule) | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.4.1.3-login_defs_warn_age-attrs` | /etc/login.defs: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.3-login_defs_warn_age-content` | /etc/login.defs has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.3-check_users_warn_age` | check users warn age: awk -F: '($2~/^\\$.+\\$/) {if($6 < 7) print "FAIL: " $1 " PASS_WARN_AGE: " $6}' /etc/shadow | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.4-login_defs_hashing-attrs` | /etc/login.defs: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.4-login_defs_hashing-content` | /etc/login.defs has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.5-inactive_passwd` | inactive passwd: useradd -D \| grep INACTIVE | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.5-inactive_users` | inactive users: awk -F: '($2~/^\\$.+\\$/) {if($7 == "" \|\| $7 > 45 \|\| $7 < 0) print "FAIL: " $1 " INACTIVE: … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.1.6-passwd_chg_past` | passwd chg past: awk -F: -v l_today="$(( $(date +%s) / 86400 ))" '($2~/^\\$.+\\$/ && $3 > l_today) {print "F… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.2.3-group_root_only_0` | group root only 0: awk -F: '($3 == 0 && $1 == "root") {print "root_ok"} ($3 == 0 && $1 != "root") {print "FA… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.2.4-root_passwd_set` | root passwd set: passwd -S root \| awk '$2 ~ /^(P\|L)/ {print "root_status_ok " $2}' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.2.5-root_path_check` | root path check: l_root_path="$(su - root -c 'printf "%s" "$PATH"')" | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.2.6-root_umask_effective` | root umask effective: su - root -c 'umask' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.3.1-nologin_not_in_shells-attrs` | /etc/shells: exists | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.4.3.1-nologin_not_in_shells-content` | /etc/shells has the expected content (1 rule) | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-5.4.3.2-check_timeout` | check timeout: l_set=0 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.3.3-login_defs_umask-attrs` | /etc/login.defs: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.3.3-login_defs_umask-content` | /etc/login.defs has the expected content (1 rule) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-5.4.3.4-umask_profile_scripts` | umask profile scripts: l_floor=23 | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.1.1-systemd-journald-running` | Service systemd-journald is running | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.1.2-journald_remote_not_in_use` | journald remote not in use: systemctl show -p Id -p UnitFileState -p ActiveState systemd-journal-remote.socket system… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.1.3-journald_forward_to_syslog` | journald forward to syslog: systemd-analyze cat-config systemd/journald.conf \| grep -Pi -- '^\\h\*ForwardToSyslog\\h\*=' … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.1.4-journald_rotation` | journald rotation: systemd-analyze cat-config systemd/journald.conf \| grep -Psi -- '^\\h\*(SystemMaxUse\|System… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.1.5-journald_journal_file_mode` | journald journal file mode: find /var/log/journal /run/log/journal -type f -name '\*.journal\*' -perm /0137 2>/dev/null… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.1.5-journald_tmpfiles_journal_mode` | journald tmpfiles journal mode: systemd-tmpfiles --cat-config \| grep -P -- '^\\h\*[^#\\h]+\\h+/var/log/journal/\\S\*\\.journal' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.1-rsyslog` | Package rsyslog is installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.2-rsyslog-enabled` | Service rsyslog is enabled | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.2-rsyslog-running` | Service rsyslog is running | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.3-rsyslog_file_create_mode` | rsyslog file create mode: grep -Psih -- '^\\h\*(\\$FileCreateMode\\h+\|[^#]\*\\btype\\h\*=\\h\*"?omfile"?[^#]\*\\bfileCreateMode… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.4-rsyslog_conf_file_access` | rsyslog conf file access: { find /etc/rsyslog.conf -not -type l \\( ! -user root -o ! -group root -o -perm /0137 \\) … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.5-rsyslog_d_dir_access` | rsyslog d dir access: find /etc/rsyslog.d/ -maxdepth 0 -type d \\( ! -user root -o ! -group root -o -perm /0022 … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.6-rsyslog_workdir_access` | rsyslog workdir access: d=$(grep -Psoh -- '^[^#]\*(\\$WorkDirectory\\h+\|workDirectory\\h\*=\\h\*"?)\\K[^"\\h)]+' /etc/rsys… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.7-rsyslog_not_log_server` | rsyslog not log server: grep -Psi -- '^\\h\*module\\(load="?(imtcp\|imudp\|imptcp\|imrelp)"?' /etc/rsyslog.conf /etc/rs… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.8-etc_rsyslog.conf-attrs` | /etc/rsyslog.conf: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.8-etc_rsyslog.conf-content` | /etc/rsyslog.conf has the expected content (13 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.14-etc_logrotate.conf-attrs` | /etc/logrotate.conf: exists | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.2.14-etc_logrotate.conf-content` | /etc/logrotate.conf has the expected content (2 rules) | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.1.3.1-logfile_access_configured` | logfile access configured: find -L /var/log -type f \\( -perm /0137 -o ! -user root -o ! -group root \\) -exec stat -L… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.2.1.1-audit` | Package audit is installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.1-audit-libs` | Package audit-libs is installed | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.2-audit_default_grub` | audit default grub: grep -Psoi -- '^\\h\*GRUB_CMDLINE_LINUX="([^#\\n\\r]+\\h+)?audit=1\\b' /etc/default/grub | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.2-grubby_audit_1` | grubby audit 1: grubby --info=ALL \| grep '^args=' \| grep -vc '\\baudit=1\\b' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.3-audit_backlog_default_grub` | audit backlog default grub: grep -Po -- '^\\h\*GRUB_CMDLINE_LINUX="([^#\\n\\r]+\\h+)?\\baudit_backlog_limit=\\K\\d+' /etc/def… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.3-audit_backlog_grubby` | audit backlog grubby: grubby --info=ALL \| grep '^args=' \| awk '{ if (match($0, /audit_backlog_limit=[0-9]+/)) {… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.4-auditd-enabled` | Service auditd is enabled | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.1.4-auditd-running` | Service auditd is running | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.2.1-max_log_auditd_conf` | max log auditd conf: grep max_log_file /etc/audit/auditd.conf | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.2.2-max_log_action_auditd_conf` | max log action auditd conf: grep max_log_file_action /etc/audit/auditd.conf | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.2.3-logs_full_auditd_conf` | logs full auditd conf: grep -E "disk.\*action" /etc/audit/auditd.conf | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.2.4-logs_low_space_auditd_conf` | logs low space auditd conf: grep space_left_action /etc/audit/auditd.conf | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.1-auditd_6_2_3_1_cnf` | auditd 6 2 3 1 cnf: grep -Phs -- '\\bsudoers(\\.d)?\\b' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.1-auditd_6_2_3_1_live` | auditd 6 2 3 1 live: auditctl -l \| grep -P -- '\\bsudoers(\\.d)?\\b' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.2-auditd_6_2_3_2_cnf` | auditd 6 2 3 2 cnf: grep -Phs -- 'execve' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.2-auditd_6_2_3_2_live` | auditd 6 2 3 2 live: auditctl -l \| grep -P -- 'execve' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.3-auditd_6_2_3_3_cnf` | auditd 6 2 3 3 cnf: grep -Phs -- 'sudo.log' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.3-auditd_6_2_3_3_live` | auditd 6 2 3 3 live: auditctl -l \| grep -P -- 'sudo.log' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.3-auditd_6_2_3_3_sudoers_logfile` | auditd 6 2 3 3 sudoers logfile: grep -rPsih -- '^\\h\*Defaults\\h+([^#]+,\\h\*)?logfile\\h\*=' /etc/sudoers /etc/sudoers.d | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.4-auditd_6_2_3_4_cnf` | auditd 6 2 3 4 cnf: grep -Phs -- '(adjtimex\|settimeofday\|clock_settime\|/etc/localtime)' /etc/audit/rules.d/\*.… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.4-auditd_6_2_3_4_live` | auditd 6 2 3 4 live: auditctl -l \| grep -P -- '(adjtimex\|settimeofday\|clock_settime\|/etc/localtime)' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.5-auditd_6_2_3_5_cnf` | auditd 6 2 3 5 cnf: grep -Phs -- 'sethostname' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.5-auditd_6_2_3_5_live` | auditd 6 2 3 5 live: auditctl -l \| grep -P -- 'sethostname' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.6-auditd_6_2_3_6_cnf` | auditd 6 2 3 6 cnf: grep -Phs -- '/etc/issue' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.6-auditd_6_2_3_6_live` | auditd 6 2 3 6 live: auditctl -l \| grep -P -- '/etc/issue' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.7-auditd_6_2_3_7_cnf` | auditd 6 2 3 7 cnf: grep -Phs -- '/etc/host' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.7-auditd_6_2_3_7_live` | auditd 6 2 3 7 live: auditctl -l \| grep -P -- '/etc/host' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.8-auditd_6_2_3_8_cnf` | auditd 6 2 3 8 cnf: grep -Phs -- 'sysconfig/network' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.8-auditd_6_2_3_8_live` | auditd 6 2 3 8 live: auditctl -l \| grep -P -- 'sysconfig/network' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.8-auditd_6_2_3_8_nm_cnf` | auditd 6 2 3 8 nm cnf: grep -Phs -- 'system-connections' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.8-auditd_6_2_3_8_nm_live` | auditd 6 2 3 8 nm live: auditctl -l \| grep -P -- 'system-connections' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.9-auditd_6_2_3_9_cnf` | auditd 6 2 3 9 cnf: grep -Phs -- '/etc/systemd/network' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.9-auditd_6_2_3_9_live` | auditd 6 2 3 9 live: auditctl -l \| grep -P -- '/etc/systemd/network' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.10-auditd_6_2_3_10_priv_cmds` | auditd 6 2 3 10 priv cmds: UID_MIN=$(awk '/^\\s\*UID_MIN/ {print $2}' /etc/login.defs) | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.11-auditd_6_2_3_11_cnf` | auditd 6 2 3 11 cnf: grep -Phs -- '(EACCES\|EPERM)' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.11-auditd_6_2_3_11_live` | auditd 6 2 3 11 live: auditctl -l \| grep -P -- '(EACCES\|EPERM)' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.12-auditd_6_2_3_12_cnf` | auditd 6 2 3 12 cnf: grep -Phs -- '/etc/group( \|/? )' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.12-auditd_6_2_3_12_live` | auditd 6 2 3 12 live: auditctl -l \| grep -P -- '/etc/group( \|/? )' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.13-auditd_6_2_3_13_cnf` | auditd 6 2 3 13 cnf: grep -Phs -- '/etc/passwd( \|/? )' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.13-auditd_6_2_3_13_live` | auditd 6 2 3 13 live: auditctl -l \| grep -P -- '/etc/passwd( \|/? )' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.14-auditd_6_2_3_14_cnf` | auditd 6 2 3 14 cnf: grep -Phs -- 'shadow' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.14-auditd_6_2_3_14_live` | auditd 6 2 3 14 live: auditctl -l \| grep -P -- 'shadow' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.15-auditd_6_2_3_15_cnf` | auditd 6 2 3 15 cnf: grep -Phs -- 'opasswd' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.15-auditd_6_2_3_15_live` | auditd 6 2 3 15 live: auditctl -l \| grep -P -- 'opasswd' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.16-auditd_6_2_3_16_cnf` | auditd 6 2 3 16 cnf: grep -Phs -- 'nsswitch' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.16-auditd_6_2_3_16_live` | auditd 6 2 3 16 live: auditctl -l \| grep -P -- 'nsswitch' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.17-auditd_6_2_3_17_cnf` | auditd 6 2 3 17 cnf: grep -Phs -- '/etc/pam' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.17-auditd_6_2_3_17_live` | auditd 6 2 3 17 live: auditctl -l \| grep -P -- '/etc/pam' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.18-auditd_6_2_3_18_cnf` | auditd 6 2 3 18 cnf: grep -Phs -- 'chmod' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.18-auditd_6_2_3_18_live` | auditd 6 2 3 18 live: auditctl -l \| grep -P -- 'chmod' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.19-auditd_6_2_3_19_cnf` | auditd 6 2 3 19 cnf: grep -Phs -- 'chown' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.19-auditd_6_2_3_19_live` | auditd 6 2 3 19 live: auditctl -l \| grep -P -- 'chown' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.20-auditd_6_2_3_20_cnf` | auditd 6 2 3 20 cnf: grep -Phs -- 'xattr' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.20-auditd_6_2_3_20_live` | auditd 6 2 3 20 live: auditctl -l \| grep -P -- 'xattr' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.21-auditd_6_2_3_21_cnf` | auditd 6 2 3 21 cnf: grep -Phs -- 'mount' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.21-auditd_6_2_3_21_live` | auditd 6 2 3 21 live: auditctl -l \| grep -P -- 'mount' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.22-auditd_6_2_3_22_cnf` | auditd 6 2 3 22 cnf: grep -Phs -- '(utmp\|wtmp\|btmp)' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.22-auditd_6_2_3_22_live` | auditd 6 2 3 22 live: auditctl -l \| grep -P -- '(utmp\|wtmp\|btmp)' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.23-auditd_6_2_3_23_faillock_cnf` | auditd 6 2 3 23 faillock cnf: grep -Phs -- 'faillock' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.23-auditd_6_2_3_23_faillock_live` | auditd 6 2 3 23 faillock live: auditctl -l \| grep -P -- 'faillock' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.23-auditd_6_2_3_23_lastlog_cnf` | auditd 6 2 3 23 lastlog cnf: grep -Phs -- 'lastlog' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.23-auditd_6_2_3_23_lastlog_live` | auditd 6 2 3 23 lastlog live: auditctl -l \| grep -P -- 'lastlog' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.24-auditd_6_2_3_24_cnf` | auditd 6 2 3 24 cnf: grep -Phs -- 'unlink' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.24-auditd_6_2_3_24_live` | auditd 6 2 3 24 live: auditctl -l \| grep -P -- 'unlink' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.25-auditd_6_2_3_25_cnf` | auditd 6 2 3 25 cnf: grep -Phs -- 'rename' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.25-auditd_6_2_3_25_live` | auditd 6 2 3 25 live: auditctl -l \| grep -P -- 'rename' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.26-auditd_6_2_3_26_cnf` | auditd 6 2 3 26 cnf: grep -Phs -- 'selinux' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.26-auditd_6_2_3_26_live` | auditd 6 2 3 26 live: auditctl -l \| grep -P -- 'selinux' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.27-auditd_6_2_3_27_cnf` | auditd 6 2 3 27 cnf: grep -Phs -- 'chcon' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.27-auditd_6_2_3_27_live` | auditd 6 2 3 27 live: auditctl -l \| grep -P -- 'chcon' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.28-auditd_6_2_3_28_cnf` | auditd 6 2 3 28 cnf: grep -Phs -- 'setfacl' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.28-auditd_6_2_3_28_live` | auditd 6 2 3 28 live: auditctl -l \| grep -P -- 'setfacl' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.29-auditd_6_2_3_29_cnf` | auditd 6 2 3 29 cnf: grep -Phs -- 'chacl' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.29-auditd_6_2_3_29_live` | auditd 6 2 3 29 live: auditctl -l \| grep -P -- 'chacl' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.30-auditd_6_2_3_30_cnf` | auditd 6 2 3 30 cnf: grep -Phs -- 'usermod' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.30-auditd_6_2_3_30_live` | auditd 6 2 3 30 live: auditctl -l \| grep -P -- 'usermod' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.31-auditd_6_2_3_31_cnf` | auditd 6 2 3 31 cnf: grep -Phs -- '/usr/bin/kmod' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.31-auditd_6_2_3_31_live` | auditd 6 2 3 31 live: auditctl -l \| grep -P -- '/usr/bin/kmod' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.32-auditd_6_2_3_32_cnf` | auditd 6 2 3 32 cnf: grep -Phs -- 'init_module' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.32-auditd_6_2_3_32_live` | auditd 6 2 3 32 live: auditctl -l \| grep -P -- 'init_module' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.33-auditd_6_2_3_33_cnf` | auditd 6 2 3 33 cnf: grep -Phs -- 'delete_module' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.33-auditd_6_2_3_33_live` | auditd 6 2 3 33 live: auditctl -l \| grep -P -- 'delete_module' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.34-auditd_6_2_3_34_cnf` | auditd 6 2 3 34 cnf: grep -Phs -- '^\\h\*-[aA]\\h\*(task,never\|never,task)\\b' /etc/audit/rules.d/\*.rules | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.34-auditd_6_2_3_34_live` | auditd 6 2 3 34 live: auditctl -l \| grep -P -- '^-a\\h+never,task\\b' | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.35-auditd_6_2_3_35_continue_on_error` | auditd 6 2 3 35 continue on error: grep -Ph -- '^\\h\*-c\\b' /etc/audit/rules.d/\*.rules \| tail -1 | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.36-auditd_6_2_3_36_immutable` | auditd 6 2 3 36 immutable: grep -Ph -- '^\\h\*-e\\h+2\\b' /etc/audit/rules.d/\*.rules \| tail -1 | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.3.37-auditd_conf_vs_live` | auditd conf vs live: /usr/sbin/augenrules --check | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.1-audit_logfile_dir_mode` | audit logfile dir mode: stat -Lc '%a' "$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}' /etc/audit/auditd.conf … | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.2-audit_logfile_mode` | audit logfile mode: find "$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}' /etc/audit/auditd.conf \| xargs)"… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.3-audit_logfile_owner` | audit logfile owner: find "$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}' /etc/audit/auditd.conf \| xargs)"… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.4-audit_logfile_group` | audit logfile group: find "$(dirname "$(awk -F= '/^\\s\*log_file\\s\*/{print $2}' /etc/audit/auditd.conf \| xargs)"… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.4-audit_logfile_group_setting` | audit logfile group setting: grep -Po '^\\s\*log_group\\s\*=\\s\*\\K\\S+' /etc/audit/auditd.conf | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.5-audit_conf_mode` | audit conf mode: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) -perm /0137 \| wc -l | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.6-audit_conf_owner` | audit conf owner: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -user root \| wc -l | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.7-audit_conf_group` | audit conf group: find /etc/audit/ -type f \\( -name '\*.conf' -o -name '\*.rules' \\) ! -group root \| wc -l | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.8-audit_tools_mode` | audit tools mode: find -L /usr/bin/auditctl /usr/bin/aureport /usr/bin/ausearch /usr/bin/auditd /usr/bin/au… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.9-audit_tools_owner` | audit tools owner: stat -Lc '%n %U' /usr/bin/auditctl /usr/bin/aureport /usr/bin/ausearch /usr/bin/auditd /u… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.2.4.10-audit_tools_group` | audit tools group: stat -Lc '%n %G' /usr/bin/auditctl /usr/bin/aureport /usr/bin/ausearch /usr/bin/auditd /u… | L2 server | <span class="sev sev-low">low</span> |
| `CIS-AMAZON2027-6.3.1-aide_installed` | Package aide is installed | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.3.2-aide_scheduled_check` | aide scheduled check: grep -rEi 'aide[[:space:]]+(--check\|--update)' /var/spool/cron/ /etc/crontab /etc/cron.d … | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.3.3-audit_bins_crypto_aide` | audit bins crypto aide: grep -E '^\\s\*/usr/bin/au' /etc/aide.conf | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-6.3.4-aide_report_url_syslog` | aide report url syslog: grep -P '^\\h\*report_url' /etc/aide.conf | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.1-cis_7_1_1_passwd-attrs` | /etc/passwd: exists, mode 0644 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.2-cis_7_1_2_passwd_backup-attrs` | /etc/passwd-: exists, mode 0644 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.3-cis_7_1_3_group-attrs` | /etc/group: exists, mode 0644 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.4-cis_7_1_4_group_backup-attrs` | /etc/group-: exists, mode 0644 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.5-cis_7_1_5_shadow-attrs` | /etc/shadow: exists, mode 0000 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.6-cis_7_1_6_shadow_backup-attrs` | /etc/shadow-: exists, mode 0000 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.7-cis_7_1_7_gshadow-attrs` | /etc/gshadow: exists, mode 0000 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.8-cis_7_1_8_gshadow_backup-attrs` | /etc/gshadow-: exists, mode 0000 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.9-cis_7_1_9_shells-attrs` | /etc/shells: exists, mode 0644 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.10-cis_7_1_10_opasswd-attrs` | /etc/security/opasswd: exists, mode 0600 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.10-cis_7_1_10_opasswd_old-attrs` | /etc/security/opasswd.old: exists, mode 0600 or stricter, owner root, group root | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.11-world_writable_secured` | world writable secured: findmnt -Dkerno fstype,target \| awk '($1 !~ /^[[:space:]]\*(nfs\|proc\|cifs\|smb\|vfat\|iso9660… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.12-unowned_ungrouped_dirs` | unowned ungrouped dirs: findmnt -Dkerno fstype,target \| awk '($1 !~ /^[[:space:]]\*(nfs\|proc\|cifs\|smb\|vfat\|iso9660… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.1.13-audit_sgid_suid` | audit sgid suid: findmnt -Dkerno fstype,target,options \| awk '($1 !~ /^[[:space:]]\*(nfs\|proc\|smb\|vfat\|iso9… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.1-accts_use_shadowed` | accts use shadowed: awk -F: '($2 != "x") { print "FAIL: " $1 " is not set to shadowed passwords" }' /etc/pass… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.2-nopasswd_shadow` | nopasswd shadow: awk -F: '($2 == "") { print "FAIL: " $1 " does not have a password" }' /etc/shadow | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.3-passwd_group_exist` | passwd group exist: awk -F: 'NR == FNR { gid[$3]; next } !($4 in gid) { print "FAIL: " $1 " has GID " $4 " wh… | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.4-no_dup_uid` | no dup uid: cut -d: -f3 /etc/passwd \| sort \| uniq -d \| sed 's/^/FAIL: duplicate UID /' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.5-no_dup_gid` | no dup gid: cut -d: -f3 /etc/group \| sort \| uniq -d \| sed 's/^/FAIL: duplicate GID /' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.6-no_dup_username` | no dup username: cut -d: -f1 /etc/passwd \| sort \| uniq -d \| sed 's/^/FAIL: duplicate user name /' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.7-no_dup_groupname` | no dup groupname: cut -d: -f1 /etc/group \| sort \| uniq -d \| sed 's/^/FAIL: duplicate group name /' | L1 server | <span class="sev sev-medium">medium</span> |
| `CIS-AMAZON2027-7.2.8-home_dirs_configured` | home dirs configured: l_valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells \| sed -rn '/^\\//p' \| p… | L1 server | <span class="sev sev-medium">medium</span> |

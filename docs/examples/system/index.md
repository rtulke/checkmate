# System

Users, sudo, SSH, PAM, services, kernel, boot, time, logging, packages, cron and mandatory access control.

| Example | Description | Checks |
|---|---|---|
| [Boot security](boot.md) | Bootloader configuration permissions and password, Secure Boot and authentication for rescue and emergency mode. | 5 |
| [cron and systemd timers](cron.md) | Permissions of cron files, access control, an allowlist for root's crontab and for scheduled jobs in /etc/cron.d and systemd timers. | 5 |
| [Kernel hardening](kernel.md) | Kernel parameters (sysctl), unused kernel modules and the running kernel version. | 23 |
| [Logging and auditing](logging.md) | journald persistence, syslog forwarding, auditd and its rules, and the permissions of log files. | 12 |
| [Packages and updates](packages.md) | Pending updates, forbidden and required packages, minimum versions and package integrity. | 17 |
| [PAM, password quality and account lockout](pam.md) | Account lockout with pam_faillock, password quality with pam_pwquality and integrity of the PAM packages. | 5 |
| [SELinux and AppArmor](security-modules.md) | Mandatory access control: SELinux on the RHEL family, AppArmor on Debian, Ubuntu and SUSE. | 7 |
| [systemd services](services.md) | Required services must run, unwanted services must be neither active nor enabled, and the system must boot into a non-graphical target. | 19 |
| [OpenSSH server](ssh.md) | Hardening of sshd based on its effective configuration (`sshd -T`), which already resolves Include files, defaults and the case-insensitive, first-value-wins semantics of sshd_config. | 17 |
| [sudo](sudo.md) | sudo configuration: syntax, file permissions, dangerous rules, logging and an allowlist of approved sudoers files by SHA-256 checksum. | 8 |
| [Time synchronisation](time.md) | Clock synchronisation with chrony or systemd-timesyncd, the allowed clock offset and the configured time zone. | 5 |
| [Users and groups](users.md) | Account hygiene on Linux: privileged accounts, password hashes, duplicate IDs, login shells of system accounts and home directory permissions. | 14 |

# MITRE ATT&CK

Traces and mitigations of MITRE ATT&CK techniques, tagged with technique and tactic IDs. `--export attack` turns the results into an ATT&CK Navigator layer.

| Example | Description | Checks |
|---|---|---|
| [MITRE ATT&CK Linux](linux.md) | Checks for traces and mitigations of MITRE ATT&CK techniques on Linux: persistence (cron, systemd, shell profiles, rc scripts, udev, PAM, SSH keys, kernel modules), privilege escalation (SUID files, sudo, PATH, container escape), credential access (shadow file, private keys, credential files) and impairing defenses (preloaded libraries, disabled history, audit, firewall, logs). | 31 |
| [MITRE ATT&CK macOS](macos.md) | Checks for traces and mitigations of MITRE ATT&CK techniques on macOS: persistence (launch agents and daemons, emond, login hooks, shell profiles, cron, SSH keys), stealth (preloaded libraries, hidden users and files, processes from temporary folders) and impairing defenses (Gatekeeper, System Integrity Protection, firewall, Guest account, remote access). | 18 |
| [MITRE ATT&CK Windows](windows.md) | Checks for traces and mitigations of MITRE ATT&CK techniques on Windows: persistence (Run keys, startup folders, scheduled tasks, WMI event subscriptions, services, IFEO debuggers, accessibility binaries, Winlogon, AppInit DLLs, LSA packages, COM hijacking, Office test, BITS jobs), credential access (LSA protection, WDigest, SAM permissions) and impairing defenses (firewall, event log, Defender, PowerShell logging, UAC). | 26 |

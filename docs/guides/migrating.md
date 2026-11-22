# Migrating from checkmate 1.x

checkmate 1.x was a Python 2 tool with one module per check. Version 2 replaces the modules with policies: the logic of each module becomes a command and an expectation. The [Managed RHEL baseline](../examples/compliance/managed-rhel.md) is a complete port of the 1.x checks and the best starting point.

## What changes

| 1.x | 2.x |
|---|---|
| Python module per check in `checkmate/modules/` | A check in a YAML policy |
| Settings in `config.py` | `vars` and `vars_files` |
| Flags `__compliance__`, `__quality__`, `__itslc__`, `__full__`, `__limited__` | `tags` |
| `-c -f` | `--tags compliance+full` |
| `-c -q -l` | `--tags compliance+limited,quality+limited` |
| `-a` | no tag filter |
| `-I check_ssh` / `-E check_cron` | `--id 'MRH-SSH-*'` / `--skip-tags …` or `--id` |
| `--checksum <sudoers file>` | `sha256sum <file>`, added to the allowlist file |
| Report written to a fixed log directory | `--export json -o <dir or file>`, plus HTML, PDF, CSV, syslog, ... |
| PyInstaller binary, RHEL 6/7 | Static Go binary, any Linux, macOS, Windows |

## Behavioral differences

These were gaps in 1.x and are fixed in the port:

- **Exit code**: 1.x always exited with 0. 2.x exits with 1 when the run is not compliant.
- **Crashing checks**: a module that raised an exception disappeared from the results and the run could still be reported as compliant. In 2.x, a check that cannot be evaluated is an ERROR, and errors always count.
- **N/A results** counted as compliant in 1.x. Not-applicable checks in 2.x are reported separately and do not hide errors.
- **Selection**: modules without a type flag (PAM, hostname, reboot, repositories) only ran with `-a`. In 2.x, every check carries explicit tags.
- **sudoers checksums** ignored lines starting with `#`, which hid `#<uid>` rules and `#include` directives. 2.x compares exact checksums.
- **SUID**: 1.x ignored SGID files and file capabilities; 2.x checks both.
- **Puppet**: 1.x ran `puppet agent -t`, which applied the catalog. 2.x reads the last run summary and never changes the system.
- **Package signatures**: 1.x only checked packages from a reference list. 2.x checks all installed packages.

## Step by step

1. Copy `examples/compliance/managed-rhel.yml` and its `vars/` directory.
2. Move the values from your `config.py` into `vars/managed-rhel.yml`: Puppet servers, allowed volumes, file system types, free space limits.
3. Create the allowlists `vars/trusted-sudoers.sha256`, `vars/trusted-pam.sha256` and `vars/trusted-cron.sha256` from a reference system:

    ```bash
    sha256sum /etc/sudoers /etc/sudoers.d/* > vars/trusted-sudoers.sha256
    find /etc/pam.d -type f -exec sha256sum {} + > vars/trusted-pam.sha256
    sha256sum /etc/crontab /etc/cron.d/* /etc/cron.*/* > vars/trusted-cron.sha256
    ```

4. Validate and run on a test system:

    ```bash
    checkmate validate managed-rhel.yml
    checkmate run managed-rhel.yml --tags compliance+full -v
    ```

5. Roll out with a threshold first (`--fail-on high`), then tighten it.

# Roadmap

What is planned, what is being considered, and what was decided against. Nothing here is a promise or a date; the order within a section is the order of work.

## Next

### Trust in policies

Checkmate says where a policy comes from and can require signatures, see [Where a policy comes from](../reference/trust.md). Open:

- **Signed releases.** A signature over `SHA256SUMS` of every release, so that the binary the built-in policy hashes live in can be verified itself.
- **Requiring signatures system-wide.** `--require-signed` is an option of a run. A setting in a file that only root can change would make it binding for everyone on a machine.
- **Protected private keys.** The key file of `checkmate sign` is not encrypted; keys with a passphrase or in a hardware token.

### Secrets on remote hosts

`no_log` keeps a secret out of reports, see [Secrets](../reference/checks.md#secrets). Over SSH the variables of a check still travel on the command line of the remote shell, and with `become` into the sudo log of the host. They need a way to the host that appears in neither.

## Later

### Remote runs

- **Files next to the policy.** Checks that compare with a reference file (`{{ policy_dir }}`, relative paths) work locally but not over SSH, because the file is not on the host. Until then the content has to be in a variable.
- **Devices that are down.** A device cannot be asked anything before the first check, so a device that is down shows up as ERROR on its checks instead of as an unreachable host.
- **Timeouts without `timeout`.** On Windows hosts and on hosts without `timeout(1)`, only the connection is ended; the command may keep running on the host.
- **Run again what could not be checked.** `--limit` to the hosts that were unreachable in the last run, read from its report.
- **Progress.** A live view of the hosts being checked, instead of one line per finished host.

### Checks

- **`loop` together with `loop_run`**: a fixed list times the answer of the host. Waiting for a concrete case; a `loop_run` command can already print combinations itself.
- **`register` on a `loop_run` check**: the outcome of a group of checks as one name.
- **`stdin`** for commands that read their input.

### Platforms

- **Job objects with kill-on-close** as an option, for checks that must not leave anything running.

## Decided against

- **Modules per kind of check.** A check is a command and an expectation. Whatever a module could do, a command can do, and a command can be copied into a terminal.
- **Passing data from one check to another.** A check may decide whether others run (`register`), but it never hands them its output. Every check collects its own data, so it stays understandable and repeatable on its own.
- **A resident agent.** checkmate runs, reports and ends. Schedules belong to cron, systemd timers or the CI system.
- **Reading Ansible inventories.** Plugins, dynamic sources and the INI syntax bring more special cases than the small YAML inventory is worth.
- **Aliases for what exists** (`and`/`or` next to `all`/`any`). Two spellings for one thing double the documentation and the tests.
- **Fixing findings.** checkmate reports and explains (`remediation`); changing a system is the job of configuration management.

## Done recently

| Version | |
|---|---|
| 2.4 | Remote runs over SSH (`--host`, `--inventory`) for Linux, macOS, BSD, Windows and devices, with `list` as a preview of what would run where; reports and exit code for hosts that cannot be checked; origin and hashes of policy files in every run and report, signatures and `--require-signed`; `no_log`; `loop_run`, `register`, `cases`; rationale and remediation on every example check; job objects, UTF-8 and policy file checks on Windows |
| 2.3 | `rationale` on every CIS and STIG check; checks stop on SIGTERM; export targets are checked before the run |

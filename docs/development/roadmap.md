# Roadmap

What is planned, what is being considered, and what was decided against. Nothing here is a promise or a date; the order within a section is the order of work.

## Next

### Know where a policy comes from

A policy is code that runs as root, with an inventory on many hosts at once. checkmate should say what it is about to run and where that came from.

1. **Provenance of shipped policies.** Done, see [Where a policy comes from](../reference/trust.md): the hashes of all shipped policies are built into the binary, and every run and report says which files are shipped, modified or your own.
2. **Signatures for your own policies.** Done: `checkmate keygen`, `sign` and `verify`, a file of trusted keys, and `--require-signed`, which refuses everything that is neither shipped nor signed. Still open: a system-wide setting that users without root cannot turn off, and private keys that are encrypted or held in a hardware token.
3. **Signed releases.** A signature over `SHA256SUMS` of every release, so that the binary the hashes of step 1 live in can be verified itself.

### Keep secrets out of reports

The command and the output of every check are part of the report. A password that is rendered into a command ends up in JSON, HTML, PDF and syslog.

- `no_log: true` on a check keeps its command, output and messages out of every report and off the console.
- Values from the environment of the machine checkmate runs on, instead of from the command line.

### See what would run, before it runs

`checkmate list --inventory hosts.yml` shows, per host, which checks would run and with which command, without running any of them. It asks every host for its facts, since they decide which variant of a command applies, and nothing else.

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
| 2.4 | Remote runs over SSH (`--host`, `--inventory`) for Linux, macOS, BSD, Windows and devices; reports and exit code for hosts that cannot be checked; `loop_run`, `register`, `cases`; job objects and UTF-8 on Windows |
| 2.3 | `rationale` on every CIS and STIG check; checks stop on SIGTERM; export targets are checked before the run |

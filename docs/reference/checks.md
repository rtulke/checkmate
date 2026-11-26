# Check keys

```yaml
- id: SSH-CIPHERS                                  # required, unique, no spaces
  name: sshd offers no weak ciphers                # shown in reports (defaults to id)
  description: Longer text for reports.
  tags: [system, ssh, crypto]                      # for --tags / --skip-tags
  severity: high                                   # info, low, medium, high, critical
  when: facts.is_root                              # Jinja2 expression
  only_if: command -v sshd                         # command; skip if it fails
  loop: [a, b, c]                                  # expand into one check per item
  loop_run: ls /etc/ssh/sshd_config.d              # or: one check per line of output
  register: sshd_ciphers                           # later checks may ask: sshd_ciphers.passed
  run: sshd -T | awk '$1 == "ciphers" {print $2}'  # required
  expect: "!~ (cbc|arcfour)"                       # required
  as: auto                                         # auto, number, version, string
  allow_rc: [0]                                    # accepted exit codes for output checks
  timeout: 30s
  shell: bash
  rationale: Weak ciphers let an attacker decrypt recorded sessions.
  remediation: Remove weak ciphers from sshd_config.
  reference: https://docs.example.net/ssh#ciphers
```

| Key | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier. May use templates, which is required inside loops (e.g. `"PKG-{{ item }}"`). |
| `name` | | Human-readable title. Defaults to the id. |
| `description` | | Free text, included in JSON reports. |
| `tags` | | List of tags for selection with `--tags` and `--skip-tags`. |
| `severity` | | `info`, `low`, `medium` (default), `high`, `critical`. Controls `fail_on` and the score. |
| `when` | | Jinja2 expression, or a list of expressions that must all be true. Uses facts and variables, no command. |
| `only_if` | | A command (same forms as `run`). The check is skipped if it exits non-zero. |
| `loop` | | List, mapping or `"{{ variable }}"`. See [Loops](templating.md#loops). |
| `loop_run` | | A command (same forms as `run`); one check per line it prints. See [Loops over command output](templating.md#loops-over-command-output). |
| `register` | | A name under which later checks see the outcome of this check in `when`. See [Checks that depend on other checks](templating.md#checks-that-depend-on-other-checks). |
| `no_log` | | `true` keeps the command, its output, the expectation and the messages out of every report and off the console. For checks that handle a secret. See [Secrets](#secrets). |
| `run` | yes | A command string, platform variants or a snippet reference. See [Platforms](platforms.md). |
| `expect` | yes | The condition. See [expect operators](expect.md). |
| `as` | | How values are compared: `auto` (default), `number`, `version`, `string`. |
| `allow_rc` | | Exit codes that are acceptable when `expect` inspects the output. Default `[0]`. `any` accepts every exit code (except 126/127), so the exit code can be judged in `expect`, e.g. `[{ rc: "== 0" }, "~ pattern"]`. |
| `timeout` | | Go duration (`500ms`, `30s`, `5m`). Default from `defaults.timeout`, else 30s. |
| `shell` | | `bash`, `sh`, `zsh`, `pwsh`, `powershell` or `cmd`. Default: bash (or sh) on POSIX systems, pwsh (or powershell) on Windows. |
| `rationale` | | Why the check matters: the risk it guards against. Shown with `-vv` and in the HTML, PDF, CSV, JSON and XCCDF reports. |
| `remediation` | | How to fix a failure; shown with `-vv` and in every report. |
| `reference` | | A link to background documentation. |

## run forms

```yaml
# 1. A plain command
run: systemctl is-active sshd

# 2. A block for anything longer or containing ": "
run: |
  awk -F: '$3 == 0 {print $1}' /etc/passwd

# 3. Platform variants (first matching key wins)
run:
  rhel: rpm -q openssh-server
  debian,ubuntu: dpkg -s openssh-server
  macos: echo "not applicable"

# 4. A snippet reference
run: { use: pkg_installed, arg: openssh-server }
```

`only_if` accepts the same forms.

## Secrets

The command and the output of every check are part of the result: they are shown with `-vv` and stored in the JSON, HTML and PDF reports, in JUnit files and in syslog events. A check that handles a password or a token has to say so:

```yaml
- id: DB-REPLICATION-USER
  name: The replication account cannot log in from everywhere
  no_log: true
  run: PGPASSWORD="$REPL_PASSWORD" psql -h db01.example.net -U repl -Atc "select count(*) from pg_hba_file_rules where user_name @> '{repl}' and address = '0.0.0.0'"
  expect: "0"
```

With `no_log: true` a result keeps what happened and drops everything that could contain the secret:

| Kept | Dropped |
|---|---|
| status, exit code, duration | the commands of `run`, `only_if` and `loop_run` |
| id, name, severity, tags | standard output and standard error |
| `rationale`, `remediation`, `reference` | the expectation |
| | the messages that quote any of these: a failure reads `the expectation does not hold (details hidden by no_log)` |

`checkmate list -v` does not show the command either.

Three things `no_log` cannot do:

- **Where the secret comes from.** Do not write it into the policy or pass it with `-e`: both end up in files and shell histories. Locally, a command sees the environment of checkmate, so `REPL_PASSWORD=... checkmate run ...` or a secrets manager that sets the variable works without any template.
- **The process list.** A secret that is part of a command line is visible to other users of the machine while the command runs. Pass it in an environment variable or a file, as above, not as an argument.
- **Remote hosts.** Over SSH the variables of a check travel on the command line of the remote shell, and with `become` the command is written to the sudo log of the host. Do not use checks with secrets over `--host` and `--inventory` yet.

The id and the name of a check are never hidden; keep secrets out of them, also where they come from a `loop_run` item.

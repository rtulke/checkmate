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

---
hide:
  - navigation
  - toc
---

# checkmate

**Compliance checks as commands.** Every check is a shell command and a condition on its result: written in YAML, readable by anyone who knows a shell, and runnable on Linux, macOS, Windows and against network devices.

```yaml
- id: SSH-001
  name: Root login over SSH is disabled
  severity: high
  run: sshd -T | awk '$1 == "permitrootlogin" {print $2}'
  expect: "== no"
```

```console
$ checkmate run baseline.yml
PASS   SSH-001   Root login over SSH is disabled
FAIL   FS-001    /tmp has at least 500 MB free  [high]
       expected stdout >= "500", got "312"

2 checks · 1 passed · 1 failed · 0 warnings · 0 errors · 0 skipped · 0 n/a · 42ms
Score  █████████████████░░░░░░░░░░░░░ 58.8%
Result NOT COMPLIANT
```

<div class="grid cards" markdown>

-   :material-console-line: **Just commands**

    ---

    No plugin per check type. If you can test it in a shell, you can turn it into a check, and copy any command straight into a terminal to debug it.

-   :material-code-braces: **Ansible-style YAML**

    ---

    Jinja2 variables, loops, snippets and facts. One definition can expand into dozens of checks across distributions.

-   :material-shield-check: **Fail-closed**

    ---

    A check that cannot be evaluated is an error, never a pass. Errors always make a run non-compliant.

-   :material-monitor-multiple: **Every platform**

    ---

    One static binary for Linux, macOS and Windows. Platform variants pick the right command for RHEL, Debian, SUSE, macOS or PowerShell.

-   :material-gauge: **Severity and score**

    ---

    Choose which severities fail a run, see warnings for the rest, and track a weighted compliance score.

-   :material-file-chart: **Reports for humans and machines**

    ---

    Colored terminal output, JSON for dashboards and JUnit XML for CI pipelines.

</div>

## Where to go next

| I want to… | Read |
|---|---|
| install checkmate and run a first policy | [Getting started](getting-started/index.md) |
| look up a key, an operator or a CLI flag | [Reference](reference/index.md) |
| write checks that work everywhere | [Writing robust checks](guides/writing-checks.md) |
| copy a check for SSH, sudo, Docker, a Cisco switch… | [Examples](examples/index.md) |

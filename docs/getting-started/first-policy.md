# Your first policy

Create a file `first.yml`:

```yaml title="first.yml"
name: My first policy
description: A few checks to get to know checkmate.

checks:
  - id: FIRST-001
    name: /etc/hosts exists
    tags: [demo]
    run: test -f /etc/hosts
    expect: true

  - id: FIRST-002
    name: At least 500 MB free in /tmp
    tags: [demo]
    run: df -Pm /tmp | awk 'NR == 2 {print $4}'
    expect: ">= 500"

  - id: FIRST-003
    name: The kernel is 5.x or newer
    tags: [demo]
    run: uname -r | cut -d. -f1
    expect: ">= 5"
```

Run it:

```console
$ checkmate run first.yml
checkmate 2.4.0 · My first policy · myhost (Ubuntu 24.04 LTS)
Policy: 1 file of your own

PASS   FIRST-001  /etc/hosts exists
PASS   FIRST-002  At least 500 MB free in /tmp
PASS   FIRST-003  The kernel is 5.x or newer

3 checks · 3 passed · 0 failed · 0 warnings · 0 errors · 0 skipped · 0 n/a · 12ms
Score  ██████████████████████████████ 100.0%
Result COMPLIANT (failures of severity low and above count; errors always count)
```

## What happened

Every check has three essential parts:

| Key | Meaning |
|---|---|
| `id` | A unique, stable identifier, used for filtering and in reports. |
| `run` | The command. It runs in `bash -o pipefail` with `LC_ALL=C`. |
| `expect` | The condition. `true` means "exit code 0"; `">= 500"` compares the output. |

The line `Policy: 1 file of your own` says where the policy comes from. For a policy that is shipped with checkmate it reads `shipped with checkmate, unchanged`; see [Where a policy comes from](../reference/trust.md).

## Make it fail

Change `">= 500"` to `">= 999999"` and run again. By default, every check is one line with status, ID and name; `-v` adds the severity and the reason:

```console
$ checkmate run first.yml
FAIL   FIRST-002  At least 500 MB free in /tmp

$ checkmate run first.yml -v
FAIL   FIRST-002  At least 500 MB free in /tmp  [medium]  expected stdout >= "999999", got "48211"
```

`-vv` also shows the command, its exit code and output, and the remediation; `-vvv` (or `--debug`) shows everything checkmate knows about every check. See [Output levels](../reference/cli.md#output-levels).

The exit code is now `1`, so `checkmate run first.yml && echo ok` would not print `ok`.

## Look before you run

`list -v` shows the exact command each check runs on this host, after variables and platform variants are resolved:

```bash
checkmate list -v first.yml
```

`validate` checks the policy for errors without running anything:

```bash
checkmate validate first.yml
```

## Next steps

- Use [variables, loops and snippets](../reference/templating.md) to avoid repetition.
- Make checks work on several distributions with [platform variants](../reference/platforms.md).
- Say why a check matters and how to fix a failure with [`rationale` and `remediation`](../reference/checks.md); both appear with `-vv` and in every report.
- Read [Writing robust checks](../guides/writing-checks.md) before writing larger policies.
- Run the policy on [other hosts over SSH](../guides/remote.md), without installing anything there.

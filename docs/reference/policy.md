# Policy file

A policy is a YAML file. All top-level keys are optional except `checks`, and unknown keys are rejected to catch typos.

```yaml
name: Web server baseline          # shown in reports
version: 1.2.0
description: Baseline for public web servers.

include:                            # load other policies first
  - common/linux.yml
  - common/ssh.yml

vars_files:                         # variables from YAML files
  - vars/production.yml

vars:                               # inline variables (override vars_files)
  min_free_mb: 1024
  allowed_ports: [22, 80, 443]

env:                                # extra environment for every command
  HTTPS_PROXY: http://proxy.example.net:3128

defaults:
  timeout: 30s                      # per command
  severity: medium                  # for checks without severity
  fail_on: low                      # lowest severity that fails a run
  shell: bash                       # bash, sh, zsh, pwsh, powershell, cmd
  when: facts.os == "linux"         # added to every check of this file

snippets:                           # reusable commands
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg -s {{ arg }} >/dev/null 2>&1

checks:
  - id: WEB-001
    name: nginx is installed
    run: { use: pkg_installed, arg: nginx }
    expect: true
```

## Keys

| Key | Type | Description |
|---|---|---|
| `name` | string | Title of the policy in reports. |
| `version` | string | Free-form version of the policy. |
| `description` | string | Longer description. |
| `include` | list of paths | Policies to load first. Their checks run before the checks of this file; their snippets must not clash. Paths are relative to this file. |
| `vars_files` | list of paths | YAML files with variables. |
| `vars` | mapping | Inline variables. |
| `env` | mapping | Environment variables for all commands. |
| `defaults` | mapping | `timeout`, `severity`, `fail_on`, `shell`, and `when` (a condition or list of conditions added to every check **of this file**, e.g. to limit a policy to one distribution). Other defaults of an including file override those of included files. |
| `snippets` | mapping | Named, reusable commands. See [Templating](templating.md#snippets). |
| `waivers` | list | Accepted deviations: checks whose failure is known and accepted for a reason, until a date. See [Waivers](waivers.md). |
| `checks` | list | The checks. See [Check keys](checks.md). |

## Precedence of variables

From lowest to highest:

1. `vars_files` and `vars` of included policies
2. `vars_files` of this policy
3. `vars` of this policy
4. `-e key=value` on the command line

## Working directory

Each command runs in the directory of the policy file that defines the check. Relative paths such as `grep -vxFf trusted-sudoers.sha256` therefore refer to files next to the policy, and the directory is also available as `{{ policy_dir }}`.

## Splitting large policies

A common layout:

```text
policies/
├── baseline.yml          # include: [common/*.yml] + site-specific checks
├── common/
│   ├── ssh.yml
│   ├── users.yml
│   └── packages.yml
└── vars/
    ├── production.yml
    └── staging.yml
```

Select the variables per environment with `-e` or by using one top-level policy per environment that includes the common files.

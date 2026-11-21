# checkmate

[![CI](https://github.com/rtulke/checkmate/actions/workflows/ci.yml/badge.svg)](https://github.com/rtulke/checkmate/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-rtulke.github.io%2Fcheckmate-3f51b5)](https://rtulke.github.io/checkmate/)

**Compliance checks as commands.** Every check is a shell command and a condition on its result, written in YAML. checkmate runs on Linux, macOS and Windows and can check network devices and remote servers from a management host.

[Deutsche Version](README_de.md) · [Documentation](https://rtulke.github.io/checkmate/) · [Examples](https://rtulke.github.io/checkmate/examples/)

![checkmate: show a policy, run it, fix a finding, run it with a severity threshold, list checks, JSON summary](docs/assets/demo.gif)

```yaml
- id: SSH-001
  name: Root login over SSH is disabled
  severity: high
  run: sshd -T | awk '$1 == "permitrootlogin" {print $2}'
  expect: "== no"
```

```console
$ checkmate run baseline.yml -v
PASS   SSH-001   Root login over SSH is disabled
FAIL   FS-001    /tmp has at least 500 MB free    [high]  expected stdout >= "500", got "312"

2 checks · 1 passed · 1 failed · 0 warnings · 0 errors · 0 skipped · 0 n/a · 42ms
Score  █████████████████░░░░░░░░░░░░░ 58.8%
Result NOT COMPLIANT
```

## Why

Most compliance tools need a plugin or module for every kind of check. checkmate needs one thing: a command. If you can test it in a shell, you can turn it into a check, and you can copy any check straight into a terminal to see what it does.

- **Readable**: YAML with Jinja2 variables, loops and reusable snippets, familiar from Ansible.
- **Portable**: one static binary; platform variants pick the right command for RHEL, Debian, SUSE, Alpine, macOS or PowerShell.
- **Fail-closed**: a check that cannot be evaluated (timeout, missing tool, unexpected exit code) is an error, and errors always make a run non-compliant.
- **Prioritized**: severities, a `--fail-on` threshold with warnings below it, and a weighted compliance score.
- **Ready for pipelines**: exit codes, colored text, JSON and JUnit XML.

## Install

Download a binary from the [releases](https://github.com/rtulke/checkmate/releases), or:

```bash
go install github.com/rtulke/checkmate/cmd/checkmate@latest
```

## Quick start

```bash
checkmate run examples/getting-started.yml  # run a policy
checkmate list -v examples/system/ssh.yml   # show the commands for this host
checkmate validate my-policy.yml            # check a policy without running it
checkmate run baseline.yml -v               # with severity and reasons (-vv details, -vvv debug)
checkmate run baseline.yml --tags ssh --fail-on high --junit-out junit.xml
```

## A policy in one minute

```yaml
name: Web server baseline

vars:
  required_services: [nginx, chronyd]

snippets:
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg -s {{ arg }} >/dev/null 2>&1

checks:
  - id: "SVC-{{ item }}"                     # one check per loop item
    name: "{{ item }} is running"
    loop: "{{ required_services }}"
    run: systemctl is-active {{ item }}
    expect: "== active"

  - id: PKG-TELNET
    name: telnet is not installed
    severity: high
    run: { use: pkg_installed, arg: telnet }
    expect: false

  - id: DISK-TMP
    name: /tmp has at least 500 MB free
    run: df -Pm /tmp | awk 'NR == 2 {print $4}'
    expect: ">= 500"

  - id: NO-NOPASSWD
    name: No passwordless sudo rules
    when: facts.is_root
    run: grep -rh 'NOPASSWD' /etc/sudoers /etc/sudoers.d
    allow_rc: [0, 1]                         # grep exits 1 when nothing matches
    expect: empty
```

`expect` understands `true`/`false` (exit code), `==`, `!=`, `>`, `>=`, `<`, `<=`, `!>`, `!<`, regular expressions (`~`, `!~`), lists (`in`, `!in`), `empty`, line counts and stderr. These building blocks combine with `all`, `any`, `not`, per-line checks (`each`, `some`, `none`) and conditional expectations:

```yaml
expect: { each: "< 90" }                     # every line of the output
expect: { none: "~ ^permitrootlogin yes" }   # no line may match
expect:
  if: { stdout: "~ ^ubuntu" }                # a different rule per distribution
  then: "~ 24\\."
  else: "~ 12"
```

See the [reference](https://rtulke.github.io/checkmate/reference/expect/).

Findings that are real but accepted go into a waiver file with a reason and an
expiry date. Waived checks still run and stay visible as `WAIVED`, but do not
fail the run; after `until` they count again:

```yaml
waivers:
  - id: SSH-PORT
    reason: Port 2222 by decision of the network team (ticket SEC-1234)
    until: 2027-06-30
```

```bash
checkmate run baseline.yml --waivers waivers.yml
```

See [waivers](https://rtulke.github.io/checkmate/reference/waivers/).

## Examples

Nearly 50 tested policies with over 750 checks, organized like the documentation:

| Category | Contents |
|---|---|
| [Platforms](examples/platforms) | generic Linux, RHEL family, Debian/Ubuntu, SUSE, macOS, Windows |
| [System](examples/system) | users, sudo, SSH, PAM, services, kernel, boot, time, logging, packages, cron, SELinux/AppArmor |
| [Files](examples/files) | permissions, content, integrity, searches, mounts, disk space |
| [Network](examples/network) | interfaces, ports, firewalls, DNS, TLS |
| [Hardware](examples/hardware) | CPU, memory, disks, RAID, virtualization, IPMI |
| [Network devices](examples/network-devices) | Cisco IOS, Juniper Junos, Arista EOS, SNMP |
| [Remote hosts](examples/remote) | Linux servers over SSH |
| [Applications](examples/applications) | Docker, Kubernetes, nginx/Apache, PostgreSQL, MySQL, Redis, web endpoints |
| [Cloud](examples/cloud) | AWS, Azure and Google Cloud instances: metadata service, agents, credentials |
| [Server validation](examples/validation) | goss-style validation of a server role: users, packages, ports, files, HTTP |
| [Compliance](examples/compliance) | BSI IT-Grundschutz (SYS.1.1, SYS.1.3), Si001 IT-Grundschutz of the Swiss Federal Administration, a broad Linux hardening baseline modelled on OpenSCAP and CIS, a managed-RHEL baseline |

Every example is validated and syntax-checked for each platform, and executed on Rocky Linux 8/9, Debian 12, Ubuntu 24.04, openSUSE Leap and Alpine in CI.

Security standards ready to run: [CIS Benchmarks](cis/) for 17 Linux
distributions, macOS, PostgreSQL and Apache, [DISA STIGs](stig/), BSI
IT-Grundschutz and Si001 (Switzerland). See the
[overview](https://rtulke.github.io/checkmate/standards/).

## Development

```bash
make build          # bin/checkmate
make test           # unit tests, example validation, escape tests
make lint           # gofmt and go vet
make test-linux     # run all examples in Linux containers (docker)
make docs-serve     # documentation on http://127.0.0.1:8000 (mkdocs-material)
vhs docs/demo.tape  # re-record the terminal demo (vhs, docker)
make dist           # binaries for Linux, macOS and Windows
```

The project layout:

```text
cmd/checkmate/     command line interface
internal/          engine, policy loader, expectations, runner, reports, facts
examples/          example policies (also the source of the documentation pages)
docs/              documentation site (MkDocs Material)
tools/gendocs/     generates the example pages from examples/
test/linux/        container-based test harness for the examples
```

## License

Apache License 2.0, see [LICENSE](LICENSE).

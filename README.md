# checkmate

[![CI](https://github.com/rtulke/checkmate/actions/workflows/ci.yml/badge.svg)](https://github.com/rtulke/checkmate/actions/workflows/ci.yml)
[![Release](https://github.com/rtulke/checkmate/actions/workflows/release.yml/badge.svg)](https://github.com/rtulke/checkmate/actions/workflows/release.yml)
[![Docs](https://img.shields.io/badge/docs-rtulke.github.io%2Fcheckmate-3f51b5)](https://rtulke.github.io/checkmate/)

**Compliance checks as commands.** Every check is a shell command and a condition on its result, written in YAML. checkmate runs on Linux, macOS and Windows, checks network devices and remote servers from a management host, and ships more than **14,900 checks** for CIS Benchmarks, DISA STIGs, BSI IT-Grundschutz, Si001 and MITRE ATT&CK.

[Deutsche Version](README_de.md) · [Documentation](https://rtulke.github.io/checkmate/) · [Security standards](https://rtulke.github.io/checkmate/standards/) · [Examples](https://rtulke.github.io/checkmate/examples/)

![checkmate: show a policy, run it, fix a finding, run it with a severity threshold, show the details of one check, JSON summary](docs/assets/demo.gif)

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

- **Readable**: YAML with Jinja2 variables, loops and reusable snippets, familiar from Ansible. A loop can also run over the output of a command (one check per account, mount point or virtual host), and the outcome of one check can decide whether others run.
- **Portable**: one static binary; platform variants pick the right command for RHEL, Debian, SUSE, Alpine, macOS or PowerShell.
- **Agentless**: the same policy runs locally or on other hosts over SSH, on one host or on a whole inventory. Nothing is installed on the hosts.
- **Fail-closed**: a check that cannot be evaluated (timeout, missing tool, unexpected exit code) is an error, and errors always make a run non-compliant.
- **Prioritized**: severities, a `--fail-on` threshold with warnings below it, a weighted compliance score, and waivers for accepted deviations.
- **Independent checks**: every check collects its own data; no shared scans or caches between checks. A check can steer other checks, but never hands its output to them.
- **Reports for everyone**: HTML and PDF for auditors, CSV for spreadsheets, JSON Lines and syslog for SIEMs, Prometheus metrics, JUnit for CI, XCCDF/ARF for SCAP tools and ATT&CK Navigator layers; reports of many hosts merge into one, and `checkmate diff` shows what changed.

## Install

| Method | Command |
|---|---|
| Debian, Ubuntu | `sudo apt install ./checkmate_<version>-1_<arch>.deb` |
| Fedora, RHEL/Rocky/Alma/Oracle, openSUSE | `sudo dnf install ./checkmate-<version>-1.<arch>.rpm` (`zypper install` on openSUSE) |
| Homebrew (macOS, Linux) | `brew tap rtulke/checkmate https://github.com/rtulke/checkmate && brew install checkmate` |
| Binary (Linux, macOS, Windows) | download from the [releases](https://github.com/rtulke/checkmate/releases) |
| Go | `go install github.com/rtulke/checkmate/cmd/checkmate@latest` |

The `.deb` and `.rpm` packages exist for amd64 and arm64 and are installed and run on Debian 12/13, Ubuntu 24.04/26.04, Fedora 43/44, EL 9/10 and openSUSE Leap 16.0/Tumbleweed before every release. Packages and Homebrew install the man pages `checkmate(1)` and `checkmate-policy(5)` and all policies below `/usr/share/checkmate/` (Homebrew: `$(brew --prefix)/share/checkmate/`). See [installation](https://rtulke.github.io/checkmate/getting-started/installation/).

## Quick start

```bash
sudo checkmate run /usr/share/checkmate/cis/rhel9.yml --tags cis-level1-server
checkmate run examples/getting-started.yml  # run a policy
checkmate list -v examples/system/ssh.yml   # show the commands for this host
checkmate validate my-policy.yml            # check a policy without running it
checkmate run baseline.yml -v               # with severity and reasons (-vv details, -vvv debug)
checkmate run baseline.yml --tags ssh --fail-on high --export junit,html -o report
```

## Security standards

| Standard | Platforms | Policies | Rules | Checks | Coverage |
|---|---|---:|---:|---:|---|
| [CIS Benchmarks Linux](https://rtulke.github.io/checkmate/cis/) | RHEL 7–10, Debian 11–13, Ubuntu 18.04–26.04, SUSE 15/16, Amazon Linux 2/2023/2027 | 17 | 4,727 | 8,338 | every automated recommendation of the Ansible Lockdown audits, Level 1/2, server/workstation |
| [CIS Benchmarks Windows](https://rtulke.github.io/checkmate/cis/) | Windows 11, Windows Server 2019/2022/2025 | 4 | 1,780 | 1,921 | every automated recommendation, member server, domain controller, standalone; not Server 2016 |
| [CIS Benchmarks macOS](https://rtulke.github.io/checkmate/cis/) | macOS 14, 15, 26 | 3 | 275 | 341 | every CIS rule of the macOS Security Compliance Project with an automated check |
| [CIS PostgreSQL](https://rtulke.github.io/checkmate/cis/postgresql/) | PostgreSQL 12 and later | 1 | 46 | 51 | automatable recommendations; privilege design and backups need a review |
| [CIS Apache HTTP Server](https://rtulke.github.io/checkmate/cis/apache/) | Apache 2.4 (RHEL, Debian, SUSE) | 1 | 70 | 70 | automatable recommendations, Level 1/2 |
| [DISA STIG](https://rtulke.github.io/checkmate/stig/) | RHEL 7–10, Ubuntu 22.04/24.04, Amazon Linux 2023 | 7 | 1,912 | 3,011 | every automated rule of the Ansible Lockdown audits, CAT I–III |
| [BSI IT-Grundschutz](https://rtulke.github.io/checkmate/examples/compliance/bsi-grundschutz/) | Linux servers (SYS.1.1, SYS.1.3) | 1 | | 53 | host-verifiable requirements, Basis/Standard/Hoch |
| [Si001 IT-Grundschutz Bund (CH)](https://rtulke.github.io/checkmate/examples/compliance/si001/) | Linux, macOS and Windows clients | 1 | | 35 | host-verifiable requirements, Grundschutz and increased protection (Schuban) |
| [MITRE ATT&CK](https://rtulke.github.io/checkmate/examples/attack/) | Linux, Windows, macOS | 3 | 63 techniques | 75 | traces and mitigations of selected techniques, ATT&CK Navigator layers |
| **Total** | | **38** | | **13,895** | |

Rules are recommendations, STIG rules or techniques; one rule can need several checks. Rules that cannot be automated (organizational measures, manual reviews) are not included. NIST SP 800-53, NIST 800-171 and CMMC are covered through the mappings of the STIG and macOS policies (`--tags nist-800-53r5-moderate`). Accepted deviations go into [waivers](https://rtulke.github.io/checkmate/reference/waivers/), not into the policies.

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
    rationale: telnet sends passwords in clear text.
    remediation: Remove the telnet package.

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

Two more keys cover what a fixed list cannot. `loop_run` creates one check per line a command prints, and `register` lets later checks ask in `when` how a check turned out:

```yaml
  - id: NGINX-INSTALLED
    severity: info                           # not a finding, only a question
    register: nginx
    run: command -v nginx
    expect: true

  - id: "NGINX-VHOST-{{ item }}"             # one check per enabled site
    name: "{{ item }} redirects HTTP to HTTPS"
    when: nginx.passed
    loop_run: ls /etc/nginx/sites-enabled
    run: grep -c 'return 301 https://' "/etc/nginx/sites-enabled/$CHECKMATE_ITEM"
    allow_rc: [0, 1]
    expect: ">= 1"
```

The items of a `loop_run` come from the host, so commands read them from the environment variable `CHECKMATE_ITEM` instead of having them pasted into the command line.

`rationale` says why a check matters and `remediation` how to fix a failure; both appear with `-vv` and in the reports. Every bundled CIS and STIG check carries both.

`expect` understands `true`/`false` (exit code), `==`, `!=`, `>`, `>=`, `<`, `<=`, `!>`, `!<`, regular expressions (`~`, `!~`), lists (`in`, `!in`), `empty`, line counts and stderr. These building blocks combine with `all`, `any`, `not`, per-line checks (`each`, `some`, `none`) and conditional expectations:

```yaml
expect: { each: "< 90" }                     # every line of the output
expect: { none: "~ ^permitrootlogin yes" }   # no line may match
expect:
  if: { stdout: "~ ^ubuntu" }                # a different rule per distribution
  then: "~ 24\\."
  else: "~ 12"
expect:
  cases:                                     # the first case that applies decides
    - { if: "~ ^ubuntu", then: "~ 24\\." }
    - { if: "~ ^debian", then: "~ 1[2-9]" }
  else: "~ ^alpine"
```

See the [reference](https://rtulke.github.io/checkmate/reference/expect/) and `man checkmate-policy`.

Findings that are real but accepted go into a waiver file with a reason and an expiry date. Waived checks still run and stay visible as `WAIVED`, but do not fail the run; after `until` they count again:

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

## Many hosts

A policy runs on other hosts over SSH without installing anything there. The facts are those of each host, so the same file checks RHEL, Debian and Windows side by side.

```bash
checkmate run baseline.yml --host audit@web01.example.net --become   # one host
checkmate run baseline.yml -i hosts.yml                              # every host of an inventory
checkmate run baseline.yml -i hosts.yml -l web --export html,pdf -o reports/
```

```yaml
# hosts.yml
defaults: { user: audit, become: true }      # become: sudo -n
groups:
  web:
    vars: { role: web }
    hosts: [web01.example.net, web02.example.net]
  windows:
    become: false
    hosts: [win01.example.net]
  switches:
    device: ios                              # no shell: commands are sent as written
    become: false
    hosts: [sw-core-01.example.net]
```

- checkmate uses the `ssh` program, so `~/.ssh/config`, agents, jump hosts and `known_hosts` apply. It never asks for a password.
- Linux, macOS, BSD and Windows hosts (OpenSSH, PowerShell) are recognized by asking them; switches and firewalls are marked with `device`.
- The console shows an overview of all hosts and groups, and every export format contains all of them.
- A host that cannot be reached is neither compliant nor non-compliant: it is listed as unreachable, left out of totals and score, and the run ends with exit code 3 if nothing else failed.

See [checking remote systems](https://rtulke.github.io/checkmate/guides/remote/) and the [inventory reference](https://rtulke.github.io/checkmate/reference/inventory/).

## Reports and exports

One flag writes any number of formats next to the console output; `checkmate export` converts and merges saved JSON reports, `checkmate diff` compares reports or policies.

```bash
checkmate run baseline.yml --export html,pdf,json -o reports/      # reports/checkmate-<host>-<time>.*
checkmate run baseline.yml -q --export prom,syslog:tls://siem.example.com -o /var/lib/checkmate/latest
checkmate export -f html,pdf,csv -o fleet reports/*.json           # one report for all hosts
checkmate diff monday.json tuesday.json                            # new problems, fixed checks, score
checkmate diff baseline-1.4.yml baseline-1.5.yml                   # added, removed, changed checks
```

| Format | For |
|---|---|
| `text`, `html`, `pdf` | people: console, filterable single-file HTML page, printable PDF (built in, no external tools) |
| `json`, `csv` | archives, scripts and spreadsheets |
| `jsonl`, `syslog` | SIEMs: one JSON event per check, to a file or to syslog (local, UDP, TCP, TLS) |
| `prom` | Prometheus via the node_exporter textfile collector |
| `junit` | test views of GitLab, GitHub, Jenkins and Azure DevOps |
| `xccdf`, `arf` | SCAP tools; valid for OpenSCAP, which renders them like its own results |
| `attack` | MITRE ATT&CK Navigator layer |

See [reports and exports](https://rtulke.github.io/checkmate/reference/exports/).

## Examples

66 tested policies with 1,194 checks, organized like the documentation:

| Category | Policies | Checks | Contents |
|---|---:|---:|---|
| [Getting started](examples/getting-started.yml) | 1 | 11 | a first policy |
| [Platforms](examples/platforms) | 6 | 60 | generic Linux, RHEL family, Debian/Ubuntu, SUSE, macOS, Windows |
| [System](examples/system) | 12 | 137 | users, sudo, SSH, PAM, services, kernel, boot, time, logging, packages, cron, SELinux/AppArmor |
| [Files](examples/files) | 6 | 63 | permissions, content, integrity, searches, mounts, disk space |
| [Network](examples/network) | 5 | 36 | interfaces, ports, firewalls, DNS, TLS |
| [Hardware](examples/hardware) | 3 | 19 | CPU, memory, disks, RAID, virtualization, IPMI |
| [Network devices](examples/network-devices) | 4 | 42 | Cisco IOS, Juniper Junos, Arista EOS, SNMP |
| [Remote hosts](examples/remote) | 1 | 12 | Linux servers over SSH |
| [Applications](examples/applications) | 11 | 145 | Docker, Kubernetes, nginx, Apache, PHP, PostgreSQL, MySQL, Redis, MongoDB, web endpoints |
| [Linux services](examples/services) | 8 | 75 | Postfix, NFS, FTP (vsftpd, ProFTPD), BIND, DHCP (Kea, ISC dhcpd), Dovecot, Samba, OpenLDAP |
| [Cloud](examples/cloud) | 1 | 9 | AWS, Azure and Google Cloud instances: metadata service, agents, credentials |
| [Server validation](examples/validation) | 1 | 19 | goss-style validation of a server role: users, packages, ports, files, HTTP |
| [Compliance](examples/compliance) | 4 | 491 | BSI IT-Grundschutz, Si001, a broad Linux hardening baseline modelled on OpenSCAP and CIS, a managed-RHEL baseline |
| [MITRE ATT&CK](examples/attack) | 3 | 75 | traces and mitigations of ATT&CK techniques on Linux, Windows and macOS |

## Platforms and testing

| | Runs on | Tested in CI |
|---|---|---|
| Linux | any distribution with a POSIX shell (bash or sh, also BusyBox) | examples on Rocky Linux 8/9, Debian 12, Ubuntu 24.04, openSUSE Leap 15, Alpine; CIS and STIG policies on 16 distributions in containers; hardened PostgreSQL and Apache servers; Postfix, NFS, vsftpd, BIND, Kea, Dovecot, Samba and OpenLDAP in default and hardened configuration; planted ATT&CK artifacts; XCCDF/ARF validated with OpenSCAP, metrics with promtool, syslog with rsyslog |
| Windows | Windows 10/11, Windows Server 2016 and later (PowerShell 5.1 or 7) | CIS and ATT&CK policies on real Windows Server 2022 and 2025, each with PowerShell 7 and Windows PowerShell 5.1; every PowerShell command through the PowerShell parser |
| macOS | macOS 13 and later | unit tests and Homebrew installation on macOS runners |
| Remote hosts | Linux, macOS, BSD and Windows over SSH (`--host`, `--inventory`); switches and firewalls as devices | Linux and Windows over a real SSH connection, every result compared with a local run; devices with a stand-in for ssh |
| HTTP and SNMP systems | from a management host, with `curl` or `snmpget` in the command | syntax of every command |

## Development

```bash
make build          # bin/checkmate
make test           # unit tests, example validation, escape tests
make lint           # gofmt and go vet
make test-linux     # run all examples in Linux containers (docker)
make test-cis       # run every CIS and STIG policy on its platform (docker)
make docs-serve     # documentation on http://127.0.0.1:8000 (mkdocs-material)
make dist           # binaries for Linux, macOS and Windows
make packages       # .deb and .rpm for amd64 and arm64
make cis-import     # regenerate the CIS policies (gh)
make stig-import    # regenerate the STIG policies (gh)
vhs docs/demo.tape  # re-record the terminal demo (vhs, docker)
```

The project layout:

```text
cmd/checkmate/      command line interface
internal/           engine, policy loader, expectations, runner, reports, facts
cis/, stig/         generated CIS and STIG policies, hand-written PostgreSQL and Apache
examples/           example policies, BSI, Si001, MITRE ATT&CK (also the source of the docs)
docs/               documentation site (MkDocs Material)
packaging/          man pages, nfpm package description, install tests
Formula/            Homebrew formula (tap rtulke/checkmate)
tools/              cis-import (CIS, STIG, Windows), mscp-import (macOS), gendocs
test/               container harnesses for Linux, Windows analysis and attack simulations
```

## References

### Supported standards

| Standard | Publisher | In checkmate |
|---|---|---|
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | Center for Internet Security | `cis/`: Linux, Windows, macOS, PostgreSQL, Apache httpd |
| [CIS Controls v8](https://www.cisecurity.org/controls) | Center for Internet Security | named in the descriptions of the CIS Linux checks |
| [DISA STIGs](https://public.cyber.mil/stigs/) | US Defense Information Systems Agency | `stig/`: RHEL, Ubuntu, Amazon Linux |
| [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | NIST | control IDs in the CIS, STIG and macOS checks; tags `nist-800-53r5-*` (macOS) |
| [NIST SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r3/final) | NIST | tag `nist-800-171` (macOS) |
| [CMMC](https://dodcio.defense.gov/CMMC/) | US Department of Defense | tags `cmmc-level-1`, `cmmc-level-2` (macOS) |
| [IT-Grundschutz-Kompendium](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/IT-Grundschutz-Bausteine/Bausteine_Download_Edition_node.html), Edition 2023 | BSI (Germany) | `examples/compliance/bsi-grundschutz.yml`: SYS.1.1, SYS.1.3 |
| [Si001 IT-Grundschutz in der Bundesverwaltung](https://www.sepos.admin.ch/de/sicherheitsverfahren), V5.1, and the [Schutzbedarfsanalyse (Schuban)](https://www.bacs.admin.ch/de/beurteilung-des-schutzbedarfs) | SEPOS (formerly BACS), Switzerland | `examples/compliance/si001.yml` |
| [MITRE ATT&CK](https://attack.mitre.org/) Enterprise 20.1 | The MITRE Corporation | `examples/attack/`, `--export attack` |

### Sources of the checks

| Source | Used for | License |
|---|---|---|
| [Ansible Lockdown](https://github.com/ansible-lockdown) CIS audits: [RHEL7](https://github.com/ansible-lockdown/RHEL7-CIS-Audit), [RHEL8](https://github.com/ansible-lockdown/RHEL8-CIS-Audit), [RHEL9](https://github.com/ansible-lockdown/RHEL9-CIS-Audit), [RHEL10](https://github.com/ansible-lockdown/RHEL10-CIS-Audit), [DEBIAN11](https://github.com/ansible-lockdown/DEBIAN11-CIS-Audit), [DEBIAN12](https://github.com/ansible-lockdown/DEBIAN12-CIS-Audit), [DEBIAN13](https://github.com/ansible-lockdown/DEBIAN13-CIS-Audit), [UBUNTU20](https://github.com/ansible-lockdown/UBUNTU20-CIS-Audit), [UBUNTU22](https://github.com/ansible-lockdown/UBUNTU22-CIS-Audit), [UBUNTU24](https://github.com/ansible-lockdown/UBUNTU24-CIS-Audit), [UBUNTU26](https://github.com/ansible-lockdown/UBUNTU26-CIS-Audit), [SUSE15](https://github.com/ansible-lockdown/SUSE15-CIS-Audit), [SUSE16](https://github.com/ansible-lockdown/SUSE16-CIS-Audit), [AMAZON2](https://github.com/ansible-lockdown/AMAZON2-CIS-Audit), [AMAZON2023](https://github.com/ansible-lockdown/AMAZON2023-CIS-Audit), [AMAZON2027](https://github.com/ansible-lockdown/AMAZON2027-CIS-Audit), [UBUNTU18](https://github.com/ansible-lockdown/UBUNTU18-CIS-Audit) | CIS Linux policies, converted by `tools/cis-import` | MIT |
| Ansible Lockdown Windows audits: [Windows-11](https://github.com/ansible-lockdown/Windows-11-CIS-Audit), [Windows-2019](https://github.com/ansible-lockdown/Windows-2019-CIS-Audit), [Windows-2022](https://github.com/ansible-lockdown/Windows-2022-CIS-Audit), [Windows-2025](https://github.com/ansible-lockdown/Windows-2025-CIS-Audit) | CIS Windows policies | MIT |
| Ansible Lockdown STIG audits: [RHEL7](https://github.com/ansible-lockdown/RHEL7-STIG-Audit), [RHEL8](https://github.com/ansible-lockdown/RHEL8-STIG-Audit), [RHEL9](https://github.com/ansible-lockdown/RHEL9-STIG-Audit), [RHEL10](https://github.com/ansible-lockdown/RHEL10-STIG-Audit), [UBUNTU22](https://github.com/ansible-lockdown/UBUNTU22-STIG-Audit), [UBUNTU24](https://github.com/ansible-lockdown/UBUNTU24-STIG-Audit), [AMAZON2023](https://github.com/ansible-lockdown/AMAZON2023-STIG-Audit) | DISA STIG policies | MIT |
| Ansible Lockdown roles [POSTGRES-12-CIS](https://github.com/ansible-lockdown/POSTGRES-12-CIS), [APACHE-2.4-CIS](https://github.com/ansible-lockdown/APACHE-2.4-CIS) | requirements and levels of the hand-written PostgreSQL and Apache policies | MIT |
| [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) ([documentation](https://pages.nist.gov/macos_security/)) | CIS macOS policies, converted by `tools/mscp-import` | CC BY 4.0 |
| BSI IT-Grundschutz-Kompendium, building blocks SYS.1.1 and SYS.1.3 | requirement IDs of the BSI policy (own wording) | BSI terms of use |
| Si001 V5.1 and the Schuban guideline of SEPOS | requirements of the Si001 policy | Swiss Federal Administration |
| [ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) | technique list for validating the `attack-*` tags | ATT&CK terms of use |

### Related tools and inspiration

| Tool | Relation to checkmate |
|---|---|
| [CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro) | the assessment tool of CIS; its licensed content is not used, checkmate covers the benchmark recommendations through the sources above |
| [OpenSCAP](https://www.open-scap.org/) and [ComplianceAsCode / SCAP Security Guide](https://github.com/ComplianceAsCode/content) | model for the Linux hardening baseline and the httpd checks |
| [Wazuh SCA](https://github.com/wazuh/wazuh/tree/main/ruleset/sca) | model for checks of the hardening baseline and the application examples |
| [goss](https://github.com/goss-org/goss) | format of the Ansible Lockdown audits; model for the server validation examples |
| [InSpec](https://github.com/inspec/inspec) | model for waivers |
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | opens the layers written by `--export attack` |
| [Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) (Center for Threat-Informed Defense) | NIST-to-ATT&CK mappings, evaluated and not used for tagging (generic controls map to hundreds of techniques) |

## License

Apache License 2.0, see [LICENSE](LICENSE). The generated policies are derived from the Ansible Lockdown audits (MIT, [cis/NOTICE](cis/NOTICE), [stig/NOTICE](stig/NOTICE)) and the macOS Security Compliance Project (CC BY 4.0); ATT&CK data is used with the permission of The MITRE Corporation ([examples/attack/NOTICE](examples/attack/NOTICE)). CIS Benchmarks is a trademark of the Center for Internet Security; the policies contain no benchmark text.

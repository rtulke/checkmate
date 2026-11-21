# Security standards

checkmate ships policies for the common security standards. Each one runs
only on its own platform and can be narrowed down with tags; accepted
deviations go into a [waiver file](reference/waivers.md).

| Standard | Platforms | Policies | Select with |
|---|---|---|---|
| [CIS Benchmarks](cis/index.md) | 17 Linux distributions, Windows 11, Windows Server 2019/2022/2025, macOS 14/15/26, PostgreSQL, Apache httpd | `cis/*.yml` | `cis-level-1`, `cis-level-2`, `cis-level1-server`, … |
| [DISA STIG](stig/index.md) | RHEL 7–10, Ubuntu 22.04/24.04, Amazon Linux 2023 | `stig/*.yml` | `stig-cat-1`, `stig-cat-2`, `stig-cat-3` |
| [BSI IT-Grundschutz](examples/compliance/bsi-grundschutz.md) | Linux servers (SYS.1.1, SYS.1.3) | `examples/compliance/bsi-grundschutz.yml` | `bsi-basis`, `bsi-standard`, `bsi-hoch` |
| [Si001 IT-Grundschutz Bund (CH)](examples/compliance/si001.md) | Linux servers and clients, macOS and Windows clients | `examples/compliance/si001.yml` | `-e si001_schutzbedarf=erhoeht`, `-e si001_rolle=client` |
| NIST SP 800-53 / 800-171, CMMC | macOS (via mSCP), Linux (via STIG) | `cis/macos*.yml`, `stig/*.yml` | `nist-800-53r5-moderate`, `nist-800-171`, `cmmc-level-2`, … |
| [MITRE ATT&CK](examples/attack/index.md) | Linux | `examples/attack/*.yml` | `attack-t1053.003`, `attack-persistence`, … and `--attack-layer` |
| [Linux hardening](examples/compliance/linux-hardening.md) | Linux | `examples/compliance/linux-hardening.yml` | `hardening` |

```bash
sudo checkmate run cis/rhel9.yml --tags cis-level1-server
sudo checkmate run stig/ubuntu24.yml --tags stig-cat-1
sudo checkmate run examples/compliance/bsi-grundschutz.yml --tags bsi-standard
sudo checkmate run examples/compliance/si001.yml -e si001_schutzbedarf=erhoeht
```

## BSI IT-Grundschutz

The building blocks SYS.1.1 "Allgemeiner Server" and SYS.1.3 "Server unter
Linux und Unix" of the IT-Grundschutz-Kompendium (Edition 2023). The tags
follow the BSI levels:

| Tag | Requirements |
|---|---|
| `bsi-basis` | Basis-Anforderungen (B) |
| `bsi-standard` | Basis and Standard (B + S), the state of the art |
| `bsi-hoch` | additionally the requirements for increased protection needs (H) |

Check names and descriptions are written for checkmate and name the
requirement ID (e.g. SYS.1.3.A4); they do not reproduce BSI text.
Organisational requirements (server rooms, planning, documentation,
emergency management) cannot be checked on a host.

## Si001 IT-Grundschutz in der Bundesverwaltung

The technical requirements of Si001 version 5.1 of the Swiss Federal
Administration. The result of the Schutzbedarfsanalyse (Schuban) selects
the level:

| Variable | Effect |
|---|---|
| `si001_schutzbedarf=grundschutz` (default) | IT-Grundschutz for every object |
| `si001_schutzbedarf=erhoeht` | adds disk encryption (I2.1) and regular integrity checks (S4.1) |
| `si001_rolle=client` | adds the federal client requirements (S5): disk encryption, screen lock, no autorun |

Si001 gives concrete values for passwords (T7: at least 10 characters, three
character classes, history of 10, lockout after 5 attempts) and clients
(S5.2: screen lock after 15 minutes); the other checks are a technical
interpretation of its principles. All limits are variables.

## MITRE ATT&CK

ATT&CK is not a configuration benchmark but a knowledge base of attacker
techniques. checkmate uses it in two ways:

- **Policies** in `examples/attack/` check for traces of techniques
  (planted cron jobs, preloaded libraries, SUID files in `/tmp`, a second UID 0
  account, web shells, processes running from memory or `/tmp`, ...) and for
  their mitigations (audit, firewall, persistent logs). Every check is tagged
  with its technique and tactics, e.g. `attack-t1053.003` and
  `attack-persistence`; a test validates every tag against the ATT&CK data.
- **`--attack-layer FILE`** writes an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
  layer for any policy with `attack-t*` tags. Each technique is colored by the
  worst result of its checks (failed, warning, waived, passed) and carries the
  failing check IDs as comment. Open it in the Navigator with *Open Existing
  Layer*.

```bash
sudo checkmate run examples/attack/linux.yml --attack-layer attack.json
sudo checkmate run examples/attack/linux.yml --tags attack-persistence -v
```

An automatic mapping of all CIS and STIG checks through NIST 800-53 was
evaluated and left out: generic controls such as CM-6 map to more than 300
techniques each, which would tag every hardening check with hundreds of
techniques.

## Deviations and exceptions

Do not edit a standard's policy to silence a finding. Keep the decision in a
waiver file, with a reason and an expiry date:

```yaml
waivers:
  - id: BSI-SYS.1.1.A30-ONE-SERVICE
    reason: Reverse proxy and application share this host by design (ticket ARC-42)
    until: 2027-06-30
```

```bash
sudo checkmate run examples/compliance/bsi-grundschutz.yml --waivers waivers.yml
```

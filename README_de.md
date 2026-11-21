# checkmate

[![CI](https://github.com/rtulke/checkmate/actions/workflows/ci.yml/badge.svg)](https://github.com/rtulke/checkmate/actions/workflows/ci.yml)
[![Release](https://github.com/rtulke/checkmate/actions/workflows/release.yml/badge.svg)](https://github.com/rtulke/checkmate/actions/workflows/release.yml)
[![Docs](https://img.shields.io/badge/docs-rtulke.github.io%2Fcheckmate-3f51b5)](https://rtulke.github.io/checkmate/)

**Compliance-Checks als Kommandos.** Jeder Check ist ein Shell-Kommando und eine Bedingung an dessen Ergebnis, geschrieben in YAML. checkmate läuft auf Linux, macOS und Windows, prüft Netzwerkgeräte und entfernte Server von einem Management-Host aus und bringt fast **15.000 Checks** für CIS Benchmarks, DISA STIGs, BSI IT-Grundschutz, Si001 und MITRE ATT&CK mit.

[English version](README.md) · [Dokumentation](https://rtulke.github.io/checkmate/) · [Sicherheitsstandards](https://rtulke.github.io/checkmate/standards/) · [Beispiele](https://rtulke.github.io/checkmate/examples/)

![checkmate: Policy anzeigen, ausführen, Befund beheben, mit Schwellenwert ausführen, Checks auflisten, JSON-Zusammenfassung](docs/assets/demo.gif)

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

## Warum

Die meisten Compliance-Werkzeuge brauchen für jede Art von Prüfung ein Plugin oder Modul. checkmate braucht genau eines: ein Kommando. Was sich in einer Shell prüfen lässt, lässt sich als Check schreiben, und jeder Check lässt sich direkt in ein Terminal kopieren, um zu sehen, was er tut.

- **Lesbar**: YAML mit Jinja2-Variablen, Schleifen und wiederverwendbaren Snippets, vertraut aus Ansible.
- **Portabel**: ein statisches Binary; Plattformvarianten wählen das passende Kommando für RHEL, Debian, SUSE, Alpine, macOS oder PowerShell.
- **Fail-closed**: Ein Check, der sich nicht auswerten lässt (Timeout, fehlendes Werkzeug, unerwarteter Exit-Code), ist ein Fehler, und Fehler machen einen Lauf immer nicht konform.
- **Priorisiert**: Schweregrade, eine `--fail-on`-Schwelle mit Warnungen darunter, ein gewichteter Compliance-Score und Waivers für akzeptierte Abweichungen.
- **Unabhängige Checks**: Jeder Check holt seine Daten selbst; keine gemeinsamen Scans oder Caches zwischen Checks.
- **Bereit für Pipelines**: Exit-Codes, farbiger Text, JSON, JUnit-XML und Layer für den ATT&CK Navigator.

## Installation

| Weg | Kommando |
|---|---|
| Debian, Ubuntu | `sudo apt install ./checkmate_<version>-1_<arch>.deb` |
| Fedora, RHEL/Rocky/Alma/Oracle, openSUSE | `sudo dnf install ./checkmate-<version>-1.<arch>.rpm` (`zypper install` unter openSUSE) |
| Homebrew (macOS, Linux) | `brew install rtulke/checkmate/checkmate` |
| Binary (Linux, macOS, Windows) | Download von den [Releases](https://github.com/rtulke/checkmate/releases) |
| Go | `go install github.com/rtulke/checkmate/cmd/checkmate@latest` |

Die `.deb`- und `.rpm`-Pakete gibt es für amd64 und arm64; vor jedem Release werden sie auf Debian 12/13, Ubuntu 24.04/26.04, Fedora 43/44, EL 9/10 und openSUSE Leap 16.0/Tumbleweed installiert und ausgeführt. Pakete und Homebrew installieren die Manpages `checkmate(1)` und `checkmate-policy(5)` sowie alle Policies unter `/usr/share/checkmate/` (Homebrew: `$(brew --prefix)/share/checkmate/`). Siehe [Installation](https://rtulke.github.io/checkmate/getting-started/installation/).

## Schnellstart

```bash
sudo checkmate run /usr/share/checkmate/cis/rhel9.yml --tags cis-level1-server
checkmate run examples/getting-started.yml  # eine Policy ausführen
checkmate list -v examples/system/ssh.yml   # die Kommandos für diesen Host anzeigen
checkmate validate my-policy.yml            # eine Policy prüfen, ohne sie auszuführen
checkmate run baseline.yml -v               # mit Schweregrad und Begründung (-vv Details, -vvv Debug)
checkmate run baseline.yml --tags ssh --fail-on high --junit-out junit.xml
```

## Sicherheitsstandards

| Standard | Plattformen | Policies | Regeln | Checks | Abdeckung |
|---|---|---:|---:|---:|---|
| [CIS Benchmarks Linux](https://rtulke.github.io/checkmate/cis/) | RHEL 7–10, Debian 11–13, Ubuntu 18.04–26.04, SUSE 15/16, Amazon Linux 2/2023/2027 | 17 | 4.841 | 8.360 | alle automatisierten Empfehlungen der Ansible-Lockdown-Audits, Level 1/2, Server/Workstation |
| [CIS Benchmarks Windows](https://rtulke.github.io/checkmate/cis/) | Windows 11, Windows Server 2019/2022/2025 | 4 | 1.780 | 1.921 | alle automatisierten Empfehlungen, Member Server, Domain Controller, Standalone; nicht Server 2016 |
| [CIS Benchmarks macOS](https://rtulke.github.io/checkmate/cis/) | macOS 14, 15, 26 | 3 | 275 | 341 | alle CIS-Regeln des macOS Security Compliance Project mit automatisierter Prüfung |
| [CIS PostgreSQL](https://rtulke.github.io/checkmate/cis/postgresql/) | PostgreSQL ab 12 | 1 | 46 | 51 | automatisierbare Empfehlungen; Rechtekonzept und Backups brauchen eine Prüfung von Hand |
| [CIS Apache HTTP Server](https://rtulke.github.io/checkmate/cis/apache/) | Apache 2.4 (RHEL, Debian, SUSE) | 1 | 70 | 70 | automatisierbare Empfehlungen, Level 1/2 |
| [DISA STIG](https://rtulke.github.io/checkmate/stig/) | RHEL 7–10, Ubuntu 22.04/24.04, Amazon Linux 2023 | 7 | 1.935 | 3.034 | alle automatisierten Regeln der Ansible-Lockdown-Audits, CAT I–III |
| [BSI IT-Grundschutz](https://rtulke.github.io/checkmate/examples/compliance/bsi-grundschutz/) | Linux-Server (SYS.1.1, SYS.1.3) | 1 | | 53 | auf dem Host prüfbare Anforderungen, Basis/Standard/Hoch |
| [Si001 IT-Grundschutz Bund (CH)](https://rtulke.github.io/checkmate/examples/compliance/si001/) | Linux, macOS- und Windows-Clients | 1 | | 35 | auf dem Host prüfbare Anforderungen, Grundschutz und erhöhter Schutzbedarf (Schuban) |
| [MITRE ATT&CK](https://rtulke.github.io/checkmate/examples/attack/) | Linux, Windows, macOS | 3 | 63 Techniken | 75 | Spuren und Gegenmaßnahmen ausgewählter Techniken, Layer für den ATT&CK Navigator |
| **Gesamt** | | **38** | | **13.940** | |

Regeln sind Empfehlungen, STIG-Regeln oder Techniken; eine Regel kann mehrere Checks brauchen. Nicht automatisierbare Regeln (organisatorische Maßnahmen, Prüfungen von Hand) sind nicht enthalten. NIST SP 800-53, NIST 800-171 und CMMC sind über die Zuordnungen der STIG- und macOS-Policies abgedeckt (`--tags nist-800-53r5-moderate`). Akzeptierte Abweichungen gehören in [Waivers](https://rtulke.github.io/checkmate/reference/waivers/), nicht in die Policies.

## Eine Policy in einer Minute

```yaml
name: Web server baseline

vars:
  required_services: [nginx, chronyd]

snippets:
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg -s {{ arg }} >/dev/null 2>&1

checks:
  - id: "SVC-{{ item }}"                     # ein Check pro Schleifenelement
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
    allow_rc: [0, 1]                         # grep endet mit 1, wenn nichts passt
    expect: empty
```

`expect` versteht `true`/`false` (Exit-Code), `==`, `!=`, `>`, `>=`, `<`, `<=`, `!>`, `!<`, reguläre Ausdrücke (`~`, `!~`), Listen (`in`, `!in`), `empty`, Zeilenzahlen und stderr. Diese Bausteine lassen sich mit `all`, `any`, `not`, zeilenweisen Prüfungen (`each`, `some`, `none`) und bedingten Erwartungen kombinieren:

```yaml
expect: { each: "< 90" }                     # jede Zeile der Ausgabe
expect: { none: "~ ^permitrootlogin yes" }   # keine Zeile darf passen
expect:
  if: { stdout: "~ ^ubuntu" }                # eine andere Regel je Distribution
  then: "~ 24\\."
  else: "~ 12"
```

Siehe die [Referenz](https://rtulke.github.io/checkmate/reference/expect/) und `man checkmate-policy`.

Echte, aber akzeptierte Abweichungen kommen in eine Waiver-Datei mit Begründung und Ablaufdatum. Gewaiverte Checks laufen weiter und bleiben als `WAIVED` sichtbar, lassen den Lauf aber nicht scheitern; nach `until` zählen sie wieder:

```yaml
waivers:
  - id: SSH-PORT
    reason: Port 2222 by decision of the network team (ticket SEC-1234)
    until: 2027-06-30
```

```bash
checkmate run baseline.yml --waivers waivers.yml
```

Siehe [Waivers](https://rtulke.github.io/checkmate/reference/waivers/).

## Beispiele

58 getestete Policies mit 1.118 Checks, gegliedert wie die Dokumentation:

| Kategorie | Policies | Checks | Inhalt |
|---|---:|---:|---|
| [Erste Schritte](examples/getting-started.yml) | 1 | 11 | eine erste Policy |
| [Plattformen](examples/platforms) | 6 | 60 | allgemeines Linux, RHEL-Familie, Debian/Ubuntu, SUSE, macOS, Windows |
| [System](examples/system) | 12 | 136 | Benutzer, sudo, SSH, PAM, Dienste, Kernel, Boot, Zeit, Logging, Pakete, cron, SELinux/AppArmor |
| [Dateien](examples/files) | 6 | 63 | Berechtigungen, Inhalte, Integrität, Suchen, Mounts, Speicherplatz |
| [Netzwerk](examples/network) | 5 | 36 | Interfaces, Ports, Firewalls, DNS, TLS |
| [Hardware](examples/hardware) | 3 | 19 | CPU, Speicher, Platten, RAID, Virtualisierung, IPMI |
| [Netzwerkgeräte](examples/network-devices) | 4 | 42 | Cisco IOS, Juniper Junos, Arista EOS, SNMP |
| [Entfernte Hosts](examples/remote) | 1 | 12 | Linux-Server über SSH |
| [Anwendungen](examples/applications) | 11 | 145 | Docker, Kubernetes, nginx, Apache, PHP, PostgreSQL, MySQL, Redis, MongoDB, Web-Endpunkte |
| [Cloud](examples/cloud) | 1 | 9 | Instanzen in AWS, Azure und Google Cloud: Metadatendienst, Agenten, Zugangsdaten |
| [Server-Validierung](examples/validation) | 1 | 19 | Validierung einer Server-Rolle im Stil von goss: Benutzer, Pakete, Ports, Dateien, HTTP |
| [Compliance](examples/compliance) | 4 | 491 | BSI IT-Grundschutz, Si001, eine umfassende Linux-Hardening-Baseline nach dem Vorbild von OpenSCAP und CIS, eine Managed-RHEL-Baseline |
| [MITRE ATT&CK](examples/attack) | 3 | 75 | Spuren und Gegenmaßnahmen von ATT&CK-Techniken auf Linux, Windows und macOS |

## Plattformen und Tests

| | Läuft auf | Getestet in der CI |
|---|---|---|
| Linux | jeder Distribution mit POSIX-Shell (bash oder sh, auch BusyBox) | Beispiele auf Rocky Linux 8/9, Debian 12, Ubuntu 24.04, openSUSE Leap 15, Alpine; CIS- und STIG-Policies auf 16 Distributionen in Containern; gehärtete PostgreSQL- und Apache-Server; gepflanzte ATT&CK-Artefakte |
| Windows | Windows 10/11, Windows Server ab 2016 (PowerShell 5.1 oder 7) | CIS- und ATT&CK-Policies auf echtem Windows Server 2022 und 2025; jedes PowerShell-Kommando durch den PowerShell-Parser |
| macOS | macOS ab 13 | Unit-Tests und Homebrew-Installation auf macOS-Runnern |
| Netzwerkgeräte, entfernte Server | über SSH oder SNMP von einem Management-Host | Syntax jedes Kommandos |

## Entwicklung

```bash
make build          # bin/checkmate
make test           # Unit-Tests, Validierung der Beispiele, Escape-Tests
make lint           # gofmt und go vet
make test-linux     # alle Beispiele in Linux-Containern ausführen (docker)
make test-cis       # jede CIS- und STIG-Policy auf ihrer Plattform ausführen (docker)
make docs-serve     # Dokumentation auf http://127.0.0.1:8000 (mkdocs-material)
make dist           # Binaries für Linux, macOS und Windows
make packages       # .deb und .rpm für amd64 und arm64
make cis-import     # CIS-Policies neu erzeugen (gh)
make stig-import    # STIG-Policies neu erzeugen (gh)
vhs docs/demo.tape  # Terminal-Demo neu aufnehmen (vhs, docker)
```

Der Aufbau des Projekts:

```text
cmd/checkmate/      Kommandozeile
internal/           Engine, Policy-Loader, Erwartungen, Runner, Reports, Facts
cis/, stig/         erzeugte CIS- und STIG-Policies, PostgreSQL und Apache von Hand
examples/           Beispiel-Policies, BSI, Si001, MITRE ATT&CK (auch Quelle der Doku)
docs/               Dokumentationsseite (MkDocs Material)
packaging/          Manpages, nfpm-Paketbeschreibung, Installationstests
Formula/            Homebrew-Formel (Tap rtulke/checkmate)
tools/              cis-import (CIS, STIG, Windows), mscp-import (macOS), gendocs
test/               Container-Testumgebungen für Linux, Windows-Analyse und Angriffssimulationen
```

## Lizenz

Apache License 2.0, siehe [LICENSE](LICENSE). Die erzeugten Policies stammen aus den Ansible-Lockdown-Audits (MIT, [cis/NOTICE](cis/NOTICE), [stig/NOTICE](stig/NOTICE)) und dem macOS Security Compliance Project (CC BY 4.0); ATT&CK-Daten werden mit Erlaubnis der MITRE Corporation verwendet ([examples/attack/NOTICE](examples/attack/NOTICE)). CIS Benchmarks ist eine Marke des Center for Internet Security; die Policies enthalten keinen Benchmark-Text.

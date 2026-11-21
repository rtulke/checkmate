# checkmate

[![CI](https://github.com/rtulke/checkmate/actions/workflows/ci.yml/badge.svg)](https://github.com/rtulke/checkmate/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-rtulke.github.io%2Fcheckmate-3f51b5)](https://rtulke.github.io/checkmate/)

**Compliance-Checks als Kommandos.** Jeder Check ist ein Shell-Kommando plus eine Bedingung an dessen Ergebnis, geschrieben in YAML. checkmate läuft unter Linux, macOS und Windows und kann Netzwerkgeräte und entfernte Server von einem Management-Host aus prüfen.

[English version](README.md) · [Dokumentation](https://rtulke.github.io/checkmate/) · [Beispiele](https://rtulke.github.io/checkmate/examples/)

![checkmate: Policy anzeigen, ausführen, einen Befund beheben, mit Schwellwert ausführen, Checks auflisten, JSON-Zusammenfassung](docs/assets/demo.gif)

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

Die meisten Compliance-Werkzeuge brauchen für jede Art von Prüfung ein eigenes Plugin oder Modul. checkmate braucht nur eines: ein Kommando. Was sich in der Shell prüfen lässt, lässt sich als Check formulieren. Umgekehrt kann man jeden Check direkt ins Terminal kopieren und sehen, was er tut.

- **Lesbar:** YAML mit Jinja2-Variablen, Schleifen und wiederverwendbaren Snippets, vertraut aus Ansible.
- **Portabel:** eine statische Binary. Plattform-Varianten wählen das passende Kommando für RHEL, Debian, SUSE, Alpine, macOS oder PowerShell.
- **Fail-closed:** Ein Check, der sich nicht auswerten lässt (Timeout, fehlendes Werkzeug, unerwarteter Exit-Code), ist ein Fehler. Fehler machen einen Lauf immer nicht-konform.
- **Priorisiert:** Schweregrade, eine `--fail-on`-Schwelle mit Warnungen darunter und ein gewichteter Compliance-Score.
- **Pipeline-tauglich:** Exit-Codes, farbige Textausgabe, JSON und JUnit-XML.

## Installation

Eine Binary von den [Releases](https://github.com/rtulke/checkmate/releases) herunterladen oder:

```bash
go install github.com/rtulke/checkmate/cmd/checkmate@latest
```

## Schnellstart

```bash
checkmate run examples/getting-started.yml       # eine Policy ausführen
checkmate list -v examples/system/ssh.yml         # die Kommandos für diesen Host anzeigen
checkmate validate my-policy.yml                  # eine Policy prüfen, ohne sie auszuführen
checkmate run baseline.yml -v                     # mit Schweregrad und Gründen (-vv Details, -vvv Debug)
checkmate run baseline.yml --tags ssh --fail-on high --junit-out junit.xml
```

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
    allow_rc: [0, 1]                         # grep endet mit 1, wenn nichts gefunden wird
    expect: empty
```

`expect` versteht `true`/`false` (Exit-Code), `==`, `!=`, `>`, `>=`, `<`, `<=`, `!>`, `!<`, reguläre Ausdrücke (`~`, `!~`), Listen (`in`, `!in`), `empty`, Zeilenanzahl und stderr. Diese Bausteine lassen sich mit `all`, `any`, `not`, zeilenweisen Prüfungen (`each`, `some`, `none`) und bedingten Erwartungen kombinieren:

```yaml
expect: { each: "< 90" }                     # jede Zeile der Ausgabe
expect: { none: "~ ^permitrootlogin yes" }   # keine Zeile darf passen
expect:
  if: { stdout: "~ ^ubuntu" }                # je Distribution eine andere Regel
  then: "~ 24\\."
  else: "~ 12"
```

Details stehen in der [Referenz](https://rtulke.github.io/checkmate/reference/expect/).

## Beispiele

Fast 50 getestete Policies mit über 750 Checks, gegliedert wie die Dokumentation:

| Kategorie | Inhalt |
|---|---|
| [Plattformen](examples/platforms) | generisches Linux, RHEL-Familie, Debian/Ubuntu, SUSE, macOS, Windows |
| [System](examples/system) | Benutzer, sudo, SSH, PAM, Dienste, Kernel, Boot, Zeit, Logging, Pakete, cron, SELinux/AppArmor |
| [Dateien](examples/files) | Berechtigungen, Inhalte, Integrität, Suchen, Mounts, Speicherplatz |
| [Netzwerk](examples/network) | Interfaces, Ports, Firewalls, DNS, TLS |
| [Hardware](examples/hardware) | CPU, Speicher, Festplatten, RAID, Virtualisierung, IPMI |
| [Netzwerkgeräte](examples/network-devices) | Cisco IOS, Juniper Junos, Arista EOS, SNMP |
| [Entfernte Hosts](examples/remote) | Linux-Server über SSH |
| [Anwendungen](examples/applications) | Docker, Kubernetes, nginx/Apache, PostgreSQL, MySQL, Redis, Web-Endpunkte |
| [Cloud](examples/cloud) | Instanzen in AWS, Azure und Google Cloud: Metadatendienst, Agenten, Zugangsdaten |
| [Server-Validierung](examples/validation) | Validierung einer Server-Rolle im Stil von goss: Benutzer, Pakete, Ports, Dateien, HTTP |
| [Compliance](examples/compliance) | eine umfassende Linux-Hardening-Baseline nach dem Vorbild von OpenSCAP und CIS sowie eine Managed-RHEL-Baseline |

Jedes Beispiel wird für jede Plattform validiert und syntaktisch geprüft. In der CI läuft es außerdem echt auf Rocky Linux 8/9, Debian 12, Ubuntu 24.04, openSUSE Leap und Alpine.

## Entwicklung

```bash
make build        # bin/checkmate
make test         # Unit-Tests, Validierung der Beispiele, Escape-Tests
make lint         # gofmt und go vet
make test-linux   # alle Beispiele in Linux-Containern ausführen (docker)
make docs-serve   # Dokumentation unter http://127.0.0.1:8000 (mkdocs-material)
vhs docs/demo.tape  # Terminal-Demo neu aufnehmen (vhs, docker)
make dist         # Binaries für Linux, macOS und Windows
```

Der Aufbau des Projekts:

```text
cmd/checkmate/     Kommandozeile
internal/          Engine, Policy-Loader, Erwartungen, Runner, Reports, Facts
examples/          Beispiel-Policies (zugleich Quelle der Doku-Seiten)
docs/              Dokumentations-Webseite (MkDocs Material)
tools/gendocs/     erzeugt die Beispielseiten aus examples/
test/linux/        Container-basierte Testumgebung für die Beispiele
```

## Lizenz

Apache License 2.0, siehe [LICENSE](LICENSE).

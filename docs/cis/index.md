# CIS benchmarks

Automated checks for the CIS benchmarks of 17 Linux platforms, Windows 11 and Windows Server 2019/2022/2025, macOS, PostgreSQL and Apache httpd. The Linux policies are generated
from the goss audit content of [Ansible Lockdown](https://github.com/ansible-lockdown) (MIT license), the macOS
policies from the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (CC BY 4.0).
The recommendation number is part of the ID. The policies contain no benchmark text.

| Benchmark | Recommendations | Level 1 | Level 2 only | Checks |
|---|---|---|---|---|
| [CIS Amazon Linux 2](amazon2.md) | 276 | 221 | 55 | 502 |
| [CIS Amazon Linux 2023](amazon2023.md) | 239 | 177 | 62 | 402 |
| [CIS Amazon Linux 2027](amazon2027.md) | 309 | 215 | 94 | 490 |
| [CIS Apache HTTP Server 2.4](apache.md) | 70 | 49 | 20 | 70 |
| [CIS Debian 11](debian11.md) | 284 | 226 | 58 | 489 |
| [CIS Debian 12](debian12.md) | 290 | 233 | 57 | 501 |
| [CIS Debian 13](debian13.md) | 325 | 247 | 78 | 555 |
| [CIS Apple macOS 14 Sonoma](macos14.md) | 88 | 72 | 16 | 109 |
| [CIS Apple macOS 15 Sequoia](macos15.md) | 95 | 81 | 14 | 117 |
| [CIS Apple macOS 26 Tahoe](macos26.md) | 92 | 79 | 13 | 115 |
| [CIS PostgreSQL](postgresql.md) | 46 | 45 | 0 | 51 |
| [CIS Red Hat Enterprise Linux 7](rhel7.md) | 193 | 162 | 31 | 272 |
| [CIS Red Hat Enterprise Linux 8](rhel8.md) | 302 | 241 | 61 | 564 |
| [CIS Red Hat Enterprise Linux 9](rhel9.md) | 274 | 218 | 56 | 510 |
| [CIS Red Hat Enterprise Linux 10](rhel10.md) | 318 | 242 | 76 | 571 |
| [CIS SUSE Linux Enterprise 15](suse15.md) | 267 | 207 | 60 | 447 |
| [CIS SUSE Linux Enterprise 16](suse16.md) | 324 | 246 | 78 | 514 |
| [CIS Ubuntu 18.04 LTS](ubuntu18.md) | 229 | 200 | 29 | 379 |
| [CIS Ubuntu 20.04 LTS](ubuntu20.md) | 293 | 238 | 55 | 552 |
| [CIS Ubuntu 22.04 LTS](ubuntu22.md) | 280 | 225 | 55 | 499 |
| [CIS Ubuntu 24.04 LTS](ubuntu24.md) | 311 | 245 | 66 | 627 |
| [CIS Ubuntu 26.04 LTS](ubuntu26.md) | 332 | 257 | 75 | 553 |
| [CIS Microsoft Windows 11 Enterprise](win11.md) | 471 | 374 | 97 | 510 |
| [CIS Microsoft Windows Server 2019](win2019.md) | 424 | 352 | 72 | 458 |
| [CIS Microsoft Windows Server 2022](win2022.md) | 433 | 357 | 76 | 467 |
| [CIS Microsoft Windows Server 2025](win2025.md) | 452 | 374 | 78 | 486 |
| **Total** | **7017** | | | **10810** |

## Selecting profiles

| Tag | Selects |
|---|---|
| `cis-level1-server`, `cis-level2-server`, `cis-level1-workstation`, `cis-level2-workstation` | one of the four CIS profiles |
| `cis-level-1`, `cis-level-2` | a level (Level 2 includes Level 1) |
| `cis-server`, `cis-workstation` | recommendations of a profile type |
| `cis-section-1` … | one chapter |
| `cis-rhel9`, `cis-debian12`, `cis-macos15`, … | one benchmark |
| `nist-800-53r5-moderate`, `nist-800-171`, `disa-stig`, `cmmc-level-2`, … | macOS checks that are also part of these baselines |

macOS has no server/workstation split; use `cis-level-1` or `cis-level-2`. The PostgreSQL and Apache policies are written by hand;
PostgreSQL has the profiles `cis-postgresql-db` and `cis-postgresql-linux`, Apache uses `cis-level-1` and `cis-level-2`.

```bash
checkmate run cis/rhel9.yml --tags cis-level1-server
checkmate run cis/debian12.yml --tags cis-level-2+cis-server --fail-on high
checkmate run cis/ubuntu24.yml --id 'CIS-UBUNTU24-5.*' -vv
```

See [cis/README.md](https://github.com/rtulke/checkmate/blob/main/cis/README.md) for how the conversion works and the
few deliberate deviations from the upstream content.

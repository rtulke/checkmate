# DISA STIG

Automated checks for the Security Technical Implementation Guides of the US Defense Information Systems
Agency, generated from the goss audit content of [Ansible Lockdown](https://github.com/ansible-lockdown)
(MIT license). STIGs implement NIST SP 800-53 controls; each check names its STIG ID, vulnerability ID, CCI
and NIST control in the description. Rule titles are taken from the STIG, and every check carries the
rationale and the fix text of its rule from the DISA XCCDF benchmark (shown with `-vv` and in the reports).

| STIG | Rules | CAT I | CAT II | CAT III | Checks |
|---|---|---|---|---|---|
| [Amazon Linux 2023](amazon2023.md) | 187 | 21 | 163 | 3 | 286 |
| [Red Hat Enterprise Linux 7](rhel7.md) | 214 | 20 | 182 | 12 | 310 |
| [Red Hat Enterprise Linux 8](rhel8.md) | 344 | 28 | 291 | 25 | 505 |
| [Red Hat Enterprise Linux 9](rhel9.md) | 426 | 28 | 384 | 14 | 725 |
| [Red Hat Enterprise Linux 10](rhel10.md) | 395 | 30 | 361 | 4 | 598 |
| [Ubuntu 22.04 LTS](ubuntu22.md) | 190 | 15 | 158 | 17 | 317 |
| [Ubuntu 24.04 LTS](ubuntu24.md) | 179 | 15 | 147 | 17 | 293 |
| **Total** | **1935** | | | | **3034** |

## Selecting categories

| Tag | Selects | Severity |
|---|---|---|
| `stig-cat-1` | CAT I: direct loss of confidentiality, integrity or availability | high |
| `stig-cat-2` | CAT II: potential for loss | medium |
| `stig-cat-3` | CAT III: degrades measures | low |
| `stig-rhel9`, `stig-ubuntu24`, … | one STIG | |

```bash
sudo checkmate run stig/rhel9.yml --tags stig-cat-1
sudo checkmate run stig/ubuntu24.yml --fail-on high -v
```

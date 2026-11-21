# Waivers: accepted deviations

Some findings are real but accepted: SSH runs on another port by decision of
the network team, `/tmp` is a tmpfs managed by systemd, a CIS recommendation
does not fit a role. A **waiver** records that decision with a reason, and
optionally an expiry date and the hosts it applies to.

A waived check still runs. If it fails, warns or errors, it is reported as
<span class="st st-waived">WAIVED</span> together with the reason and the
original result, and it does not make the run non-compliant. If it passes, it
stays <span class="st st-pass">PASS</span>.

```yaml
waivers:
  - id: SSH-PORT
    reason: Port 2222 by decision of the network team (ticket SEC-1234)
    until: 2027-06-30

  - id: [CIS-RHEL9-1.1.2.1.*, CIS-RHEL9-1.1.2.2.*]
    reason: /tmp and /dev/shm are tmpfs mounts managed by systemd

  - id: STIG-RHEL-09-2*
    reason: Build hosts are rebuilt daily from a golden image
    when: facts.hostname in ["build-01", "build-02"]

  - id: HRD-PERM-UNOWNED
    reason: Scanning the NFS-mounted home directories takes hours
    skip: true
```

```text
WAIVED  SSH-PORT  SSH listens on port 22   waived: Port 2222 by decision of the network team (ticket SEC-1234) (FAIL: expected stdout == "22", got "2222")
```

## Keys

| Key | Required | Description |
|---|---|---|
| `id` | yes | Check ID or glob pattern (`*`, `?`, `[...]`), or a list of them. Same syntax as `--id`. |
| `reason` | yes | Why the deviation is accepted. Shown in every report. |
| `until` | no | Last day the waiver applies, `YYYY-MM-DD`. Afterwards the check counts again and the report shows a notice. |
| `when` | no | Jinja2 condition or list of conditions, like `when` of a check: facts and variables. The waiver applies only if all hold. |
| `skip` | no | `true` does not run the check at all (status WAIVED without a result). Use it for checks that are slow or harmful on a host, not to hide results. |

The first matching waiver wins, and the more specific source comes first: a
file before the files it includes, a policy before the policies it includes,
a later `--waivers` file before an earlier one, and `--waivers` files before
the waivers of the policy. A waiver whose `when` does not hold is ignored for
that check, so different hosts can have different waivers in one file.

## Where waivers live

**In a separate file**, passed with `--waivers` (repeatable). This is the
usual way: the policy stays unchanged (generated CIS and STIG policies must
not be edited), and each team or host keeps its own exceptions next to it.

```bash
sudo checkmate run cis/rhel9.yml --waivers /etc/checkmate/waivers.yml
sudo checkmate run cis/rhel9.yml --waivers common.yml --waivers "$(hostname).yml"
```

A waiver file contains `waivers:` and may include other waiver files, with
paths relative to the including file. This keeps common exceptions in one
place and host- or role-specific ones on top:

```yaml
# /etc/checkmate/waivers/web01.yml
include:
  - common.yml          # site-wide exceptions
  - roles/web.yml       # exceptions of all web servers
waivers:
  - id: SSH-PORT
    reason: web01 is reached through the jump host on port 2222
    until: 2027-06-30
```

```bash
sudo checkmate run cis/rhel9.yml --waivers /etc/checkmate/waivers/web01.yml
```

Include cycles are reported as errors, and every included file gets the same
ownership check as the file that includes it.

**In a policy**, under `waivers:` next to `checks:`. Waivers of included
files apply as well, so a site policy can include a benchmark and add its own
exceptions:

```yaml
name: Web servers
include:
  - ../cis/rhel9.yml
waivers:
  - id: CIS-RHEL9-2.2.*
    reason: httpd is the purpose of these hosts
```

## Safety

- **Expiry is enforced.** An expired waiver is ignored and reported as a
  notice, so the finding shows up again instead of being forgotten.
- **Nothing disappears.** Waived checks are listed with their reason and the
  status they would have had; the JSON report carries a `waiver` object with
  `reason`, `until`, `source` (file and line) and `status`, and the summary
  counts them as `waived`. In JUnit they are skipped tests with the reason.
- **Waiver files are policy files.** When checkmate runs as root, it refuses
  waiver files that other users can modify, just like policies.
- **`--ignore-waivers`** reports every result as if no waiver existed, for an
  audit of the raw state.

# Where a policy comes from

A policy is code that runs as root, and with an inventory on many hosts at once. checkmate therefore says for every policy file whether it vouches for it.

## Shipped, modified or your own

The SHA-256 hashes of all policies of a release (`cis/`, `stig/`, `examples/`) are built into the binary. Every file that is loaded, included files and variable files as well, is one of three things:

| Origin | Meaning |
|---|---|
| shipped | The content is that of a policy shipped with this checkmate. Where the file lies does not matter. |
| modified | The file has the path of a shipped policy (`.../cis/rhel9.yml`) but other content: most likely an edited copy, or the policy of another release. |
| local | A file of your own. |

The header of every run says so in one line, and names the files that differ from what was shipped:

```text
checkmate 2.5.0 · CIS Red Hat Enterprise Linux 9 · web01 (Rocky Linux 9.4)
Policy: 1 file shipped with checkmate, unchanged

checkmate 2.5.0 · Web baseline · web01 (Rocky Linux 9.4)
Policy: 1 shipped file modified, 2 files of your own
        /srv/policies/cis/rhel9.yml: differs from the shipped cis/rhel9.yml
```

`checkmate validate` lists every file with its hash and origin without running anything:

```text
$ checkmate validate baseline.yml
baseline.yml: OK (184 checks from 3 file(s), 4 snippets)
  9c1f…e2a7  /srv/policies/baseline.yml    not shipped with checkmate
  620c…b12a  /srv/policies/cis/rhel9.yml   differs from the shipped cis/rhel9.yml
  4be0…77d1  /srv/policies/vars/prod.yml   not shipped with checkmate
```

## In reports

The JSON report records the files under `policy_sources`, with `path`, `sha256` and `origin`. The HTML and PDF reports have a table "Policy files". With them, a report says not only what was found, but exactly which policy found it: two reports with the same hashes were made with the same checks.

The hash is taken over the file with Unix line ends, so a checkout on Windows that converted them is still the shipped policy.

## What this does and does not protect

Trust in the built-in hashes is trust in the binary. Verify the binary through its package or through `SHA256SUMS` of the release.

The origin is information, not a gate: your own policies are the normal case, and checkmate runs them. What it does refuse, as root, are policy files that another user could have changed; see [Running as root](../getting-started/installation.md#running-as-root).

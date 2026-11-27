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
checkmate 2.4.0 · CIS Red Hat Enterprise Linux 9 · web01 (Rocky Linux 9.4)
Policy: 1 file shipped with checkmate, unchanged

checkmate 2.4.0 · Web baseline · web01 (Rocky Linux 9.4)
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

## Signing your own policies

The built-in hashes vouch for the shipped policies. For your own, a signature does the same: whoever holds the key has released this exact content.

```bash
checkmate keygen release-team
# release-team.key  private key: keep it secret
# release-team.pub  public key: goes to the machines that run policies

checkmate sign --key release-team.key baseline.yml common/ssh.yml vars/prod.yml
# writes baseline.yml.sig, common/ssh.yml.sig, vars/prod.yml.sig
```

Every file that is loaded needs its own signature: the policy, the files it includes, variable files and waiver files. A signature file is one line and travels with the policy, in the same repository or package.

On the machines that run policies, the public keys are listed in a trust file, one per line. The default is `/etc/checkmate/trusted_keys` (on Windows `%ProgramData%\checkmate\trusted_keys`); `--trusted-keys FILE` names another one.

```text
# /etc/checkmate/trusted_keys
checkmate-key ed25519 W7lOox73drqBQknnVxf1XvMX/Ob2SmUjLeb3tgWJVOU= release-team
```

`checkmate verify` then tells what holds for a policy, without running it:

```text
$ checkmate verify baseline.yml
ok  9c1f…e2a7  /srv/policies/baseline.yml     not shipped with checkmate, signed by release-team
ok  4be0…77d1  /srv/policies/vars/prod.yml    not shipped with checkmate, signed by release-team
--  77aa…0c3e  /srv/policies/common/ssh.yml   not shipped with checkmate, not signed

1 of 3 files are neither shipped with checkmate nor signed by a trusted key
```

## Requiring signatures

```bash
checkmate run baseline.yml --require-signed
CHECKMATE_REQUIRE_SIGNED=1 checkmate run baseline.yml -i hosts.yml
```

With `--require-signed`, checkmate refuses every file that is neither shipped with it nor signed by a trusted key, before anything runs. Use it where policies are released through a review: in a scheduled job, in a pipeline, on a management host that checks an inventory.

Two things hold without the option:

- A file whose signature was made by a trusted key but does not match its content is **always** refused. It was changed after it was signed.
- A signature by a key that is not in the trust file says nothing, and the file counts as not signed.

| Situation | Without `--require-signed` | With `--require-signed` |
|---|---|---|
| shipped, unchanged | runs | runs |
| signed by a trusted key | runs | runs |
| not signed, or signed by an unknown key | runs, named in the header | refused |
| signed by a trusted key, content changed | refused | refused |

## What this does and does not protect

Trust in the built-in hashes is trust in the binary. Verify the binary through its package or through `SHA256SUMS` of the release.

Without `--require-signed`, the origin is information, not a gate: your own policies are the normal case, and checkmate runs them.

The trust file decides which policies may run, so as root it is held to the same rules as a policy file: it must not be writable by other users. See [Running as root](../getting-started/installation.md#running-as-root). The option itself is only as binding as the place it is set in: a job definition or wrapper that ordinary users cannot change.

Signatures are Ed25519 over the SHA-256 of the file with Unix line ends. The private key file is not encrypted; protect it like any other signing key, and keep it off the machines that only run policies.

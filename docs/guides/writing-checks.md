# Writing robust checks

A check is only as good as its command. These rules come from running every example in this documentation on RHEL 8/9, Debian, Ubuntu, openSUSE, Alpine (busybox) and macOS.

## The three questions

For every check, answer:

1. **What does the command print when everything is fine?** That is your `expect`.
2. **What does it print, and which exit code does it return, when the setting is missing?** It must lead to <span class="st st-fail">FAIL</span>, not to <span class="st st-error">ERROR</span> or, worse, <span class="st st-pass">PASS</span>.
3. **What happens when the tool or file does not exist?** Decide between `only_if` (skip), `allow_rc` (treat as failure) and the default (error).

Use `checkmate list -v` to see the final command and run it in a shell.

## YAML pitfalls

### Colon followed by a space

`": "` starts a mapping in YAML. It is easy to hit with `awk -F:` or `-F': '`:

```yaml
run: awk -F: '$3 == 0 {print $1}' /etc/passwd     # YAML error
```

Use a block scalar for every command that is longer than a few words. Inside a block, nothing needs escaping:

```yaml
run: |
  awk -F: '$3 == 0 {print $1}' /etc/passwd
```

The same applies to `name` and `expect`: `name: 'Value contains ": "'`, `expect: "== Status: active"`.

### Values that start with special characters

Quote values starting with `!`, `*`, `&`, `{`, `[`, `%`, `@` or a quote: `expect: "!empty"`, `when: '"suse" in facts.distro_like'`.

### Numbers that are not numbers

`027` and `1.10` are numbers in YAML and Jinja2. Quote them and use `as: string` or `as: version`:

```yaml
as: string
expect: "in ['027', '077']"
```

## Exit codes and empty output

### grep

`grep` exits **1** when nothing matches and **2** when a file is missing.

```yaml
# Must find nothing:
run: grep -E '^[^#]*NOPASSWD' /etc/sudoers
allow_rc: [0, 1]
expect: empty

# Must find something; a missing file means "not configured":
run: grep -E '^Defaults.*use_pty' /etc/sudoers
allow_rc: [0, 1, 2]
expect: { lines: ">= 1" }
```

### grep -c on a missing file

`grep -c pattern missing-file` prints **nothing**, not `0`, and a numeric comparison then fails with an error. Read through `cat`, which turns a missing file into empty input:

```yaml
run: cat /boot/grub2/user.cfg 2>/dev/null | grep -c '^GRUB2_PASSWORD='
allow_rc: [0, 1]
expect: ">= 1"
```

The same trick makes `awk` tolerate missing files and unmatched globs such as `/etc/security/pwquality.conf.d/*.conf`.

### Loops in the shell

The exit code of a `while` loop is the exit code of its last command. `[ … ] && echo` returns 1 when the condition is false, so the whole command fails on the last iteration:

```bash
# Wrong: fails if the last interface is up
while read -r dev; do [ "$state" = down ] && echo "$dev"; done

# Right
while read -r dev; do if [ "$state" = down ]; then echo "$dev"; fi; done
```

### Unmatched globs

In bash, `for f in /opt/*` loops once over the literal string `/opt/*` if the directory is empty. Guard with `[ -e "$f" ] || continue`.

### Arithmetic with failed commands

`$(( now - installed ))` silently treats an empty or non-numeric `installed` as 0. Fail explicitly if a value is missing:

```bash
installed=$(rpm -q --qf '%{INSTALLTIME}' "kernel-$(uname -r)" 2>/dev/null) ||
  { echo "no package for kernel $(uname -r)" >&2; exit 1; }
```

### head closes pipes early

`cmd | head -1` lets `head` exit after the first line. If `cmd` is still writing, it is killed by SIGPIPE and, with `pipefail`, the whole command fails with exit code 141, depending on timing. Use `sed -n 1p` (or `awk 'NR == 1'`), which reads all input:

```yaml
run: getent ahosts example.com | sed -n 1p      # not: | head -1
```

### find -perm and symbolic links

Symbolic links always have mode 777, so `find /etc/nginx -perm /022` reports every link in `sites-enabled/`. Skip them with `! -type l`, or restrict the search to `-type f` and `-type d`:

```yaml
run: find /etc/nginx ! -type l \( ! -user root -o -perm /022 \)
```

### Unit aliases in systemd

`systemctl is-enabled chronyd` prints `alias` when `chronyd` is an alias of `chrony.service` (Debian). `systemctl show` resolves aliases:

```yaml
run: echo "$(systemctl show -p ActiveState --value chronyd) $(systemctl show -p UnitFileState --value chronyd)"
expect: "== active enabled"
```

### Login scripts print banners

`su - root -c '…'` runs root's login scripts, which may print a message of the day before your output. Mark the value and extract it:

```yaml
run: su - root -c 'printf "PATH=%s\\n" "$PATH"' | sed -n 's/^PATH=//p' | tail -1
```

### Symbolic links to the files you check

Certificates and keys are often symbolic links (Let's Encrypt keeps them in `live/`). `find -H` follows links given on the command line, so the permissions of the real file are checked.

### Report a missing component once

If a component such as auditd is missing, one check should say so. Guard all checks that need it with `only_if: command -v auditctl`, otherwise a single missing package produces dozens of failures.

### Pipelines

Commands run with `pipefail`: a failure anywhere in a pipeline sets the exit code. This catches broken commands but also means that `grep` without a match in the middle of a pipeline fails it. Add the exit code to `allow_rc` when that is expected.

## Portable shell tools

GNU, BSD (macOS) and busybox (Alpine) tools differ. These rules keep a command working everywhere:

| Do | Don't | Why |
|---|---|---|
| `[[:space:]]` | `\s` in awk or sed | `\s` is a GNU extension; mawk (Debian, Ubuntu) and BSD awk do not know it |
| `[0-9]+\.[0-9]+\.[0-9]+` | `([0-9]+\.){3}` in awk | interval expressions are missing in older mawk |
| `^` only at the start of a pattern | `(^|,)` in grep | BSD grep treats `^` inside alternations differently. In `expect`, Go regular expressions handle it fine |
| `[[:space:],]use_pty` | `\buse_pty\b` | `\b` is not POSIX |
| `cat /proc/1/comm` | `ps -p 1 -o comm=` | busybox ps has no `-p` |
| `df -P` and filter with awk | `df -x tmpfs` | busybox df has no `-x` |
| `stat -c` (Linux) / `stat -f` (macOS) in platform variants | one `stat` call for both | the syntax differs completely |
| `sha256sum` (Linux) / `shasum -a 256` (macOS) | one of them for both | |

Facts and platform variants make the differences explicit:

```yaml
snippets:
  file_mode:
    linux: stat -c '%a %U %G' {{ arg }}
    macos: stat -f '%Lp %Su %Sg' {{ arg }}
```

## Prefer what the program reports

Parsing configuration files yourself is error-prone: defaults, include files, case-insensitive keys and "first value wins" rules are easy to get wrong. Ask the program instead whenever it can tell you:

| Instead of parsing | Ask |
|---|---|
| `/etc/ssh/sshd_config` | `sshd -T` |
| systemd unit files | `systemctl show`, `systemctl cat` |
| `/etc/sysctl.conf` | `sysctl -n` |
| nginx / Apache configs | `nginx -T`, `apachectl -S` |
| package files | `rpm -q --qf`, `dpkg-query -W -f` |
| crypto policy files | `update-crypto-policies --show` |

## Allowlists beat denylists

"No unknown SUID binaries" is stronger than "no SUID bit on these five files". Build allowlists with `grep -vxF` and a Jinja2 loop, or keep the list in a file next to the policy:

```yaml
run: |
  sha256sum /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vxFf trusted-sudoers.sha256
allow_rc: [0, 1]
expect: empty
```

Compare exact checksums. Normalizing content first (removing comments or blank lines) creates gaps: in sudoers, for example, `#1000` is a user ID and `#include` is a directive, not a comment.

## Keep checks read-only

A compliance check must never change the system. Avoid commands that apply configuration (`puppet agent -t`, `ansible-playbook`), install packages, delete files or restart services. Read state files and status commands instead, for example Puppet's `last_run_summary.yaml` instead of a Puppet run.

## Test your checks

- `checkmate validate policy.yml`: syntax, templates and expectations for this host.
- `checkmate list -v policy.yml`: the rendered commands.
- `checkmate run policy.yml -v --id 'MY-*'`: run a few checks with full output.
- Run the policy in containers of every distribution you support; the [test harness](https://github.com/rtulke/checkmate/tree/main/test/linux) of this project does exactly that for the examples.

# Platforms and facts

## Facts

checkmate collects facts about the host once per run. They are available in templates and `when` expressions as `facts.<name>`. Print them with `checkmate facts`:

```console
$ checkmate facts
{
  "os": "linux",
  "arch": "amd64",
  "hostname": "web-01",
  "distro": "rocky",
  "distro_like": ["rhel", "centos", "fedora"],
  "distro_name": "Rocky Linux 9.4 (Blue Onyx)",
  "version": "9.4",
  "version_major": 9,
  "kernel": "5.14.0-427.13.1.el9_4.x86_64",
  "is_root": true,
  "platform_keys": ["rocky", "rhel", "centos", "fedora", "linux", "unix", "default"]
}
```

| Fact | Linux | macOS | Windows |
|---|---|---|---|
| `os` | `linux` | `darwin` | `windows` |
| `distro` | `ID` from os-release (`rhel`, `rocky`, `debian`, `ubuntu`, `sles`, `alpine`, …) | `macos` | `windows` |
| `distro_like` | `ID_LIKE` from os-release | empty | empty |
| `distro_name` | `PRETTY_NAME` | `sw_vers -productName` | `Windows 11`, `Windows 10`, `Windows Server 2016` … `2025` |
| `version` | `VERSION_ID` | `sw_vers -productVersion` | build number from `ver` |
| `version_major` | leading number of `version` | | |
| `is_root` | effective UID 0 | effective UID 0 | running elevated (as administrator) |

## Platform variants

A command can have one variant per platform. checkmate tries the host's **platform keys** in order and uses the first variant that exists:

1. `distro` (e.g. `rocky`)
2. each entry of `distro_like` (e.g. `rhel`, `centos`, `fedora`)
3. `os` (`linux`, `darwin`, `windows`)
4. `unix` (every non-Windows system)
5. `default`

```yaml
run:
  rhel: rpm -q openssh-server          # RHEL, Rocky, Alma, CentOS, Oracle Linux
  debian: dpkg -s openssh-server       # Debian, Ubuntu, Mint
  suse: rpm -q openssh                 # SLES, openSUSE
  macos: test -x /usr/sbin/sshd
  default: echo unsupported; exit 1
```

Several keys can share a command: `rhel,suse: rpm -q {{ arg }}`.

If no key matches, the check is <span class="st st-na">N/A</span>: it is reported, but it does not count against compliance. Add a `default` variant if a missing platform should fail instead.

## Limiting checks to platforms

Use `when` for checks that only make sense on some systems:

```yaml
when: facts.os == "linux"
when: facts.distro == "rhel" or "rhel" in facts.distro_like
when: facts.version_major >= 9
when: facts.is_root
when:                                   # all must be true
  - facts.os == "linux"
  - facts.is_root
```

!!! warning "Quote expressions that start with a quote"
    `when: "suse" in facts.distro_like` is invalid YAML. Wrap the whole
    expression: `when: '"suse" in facts.distro_like'`.

Use `only_if` when the decision depends on the system state, for example whether a tool is installed: `only_if: command -v docker`.

## Shells

| Platform | Default shell | Invocation |
|---|---|---|
| Linux, macOS | `bash` (falls back to `sh`) | `bash --noprofile --norc -o pipefail -c '<command>'` |
| Windows | `pwsh` (falls back to `powershell`) | `pwsh -NoProfile -NonInteractive -Command` with `$ErrorActionPreference = 'Stop'` |

On POSIX systems, commands run with `LC_ALL=C` and `LANG=C`, so output is not translated and sorting is stable. On Windows, PowerShell output is read as UTF-8 whatever the code page of the console is; `cmd` writes in the code page of the console.

A timeout ends the command together with every process it started, on all platforms. Ctrl+C, `SIGTERM` and `SIGHUP` stop a run the same way, so no checks are left running. Set `shell:` per check or in `defaults` to use `sh`, `zsh`, `pwsh`, `powershell` or `cmd`.

Exit codes 126 and 127 mean "not executable" and "not found" for POSIX shells and are always reported as errors. PowerShell reports a missing command as an ordinary failure (exit code 1).

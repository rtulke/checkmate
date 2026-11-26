# Installation

checkmate is a single static binary. Nothing else needs to be installed on the target system; the checks use the tools that are already there (a POSIX shell on Linux and macOS, PowerShell on Windows).

## Packages for Linux

Every release has a `.deb` and an `.rpm` for amd64 and arm64. They contain the
binary, the man pages `checkmate(1)` and `checkmate-policy(5)`, and all
policies below `/usr/share/checkmate/` (CIS, STIG, examples, BSI, Si001,
MITRE ATT&CK). Each package is installed and run on every supported
distribution before a release is published:

| Package | Distributions |
|---|---|
| `.deb` | Debian 12, 13 · Ubuntu 24.04, 26.04 |
| `.rpm` | Fedora 43, 44 · RHEL, Rocky, AlmaLinux, Oracle Linux 9, 10 · openSUSE Leap 16.0, Tumbleweed |

=== "Debian / Ubuntu"

    ```bash
    # replace VERSION and ARCH (amd64, arm64) with the file of the release
    curl -fsSLO https://github.com/rtulke/checkmate/releases/download/vVERSION/checkmate_VERSION-1_ARCH.deb
    sudo apt install ./checkmate_VERSION-1_ARCH.deb
    ```

=== "Fedora / EL"

    ```bash
    # ARCH: x86_64 or aarch64
    sudo dnf install https://github.com/rtulke/checkmate/releases/download/vVERSION/checkmate-VERSION-1.ARCH.rpm
    ```

=== "openSUSE"

    ```bash
    curl -fsSLO https://github.com/rtulke/checkmate/releases/download/vVERSION/checkmate-VERSION-1.ARCH.rpm
    sudo zypper install --allow-unsigned-rpm ./checkmate-VERSION-1.ARCH.rpm
    ```

Between releases, the [rolling `latest` prerelease](https://github.com/rtulke/checkmate/releases/tag/latest)
has packages built from the main branch.

Every release also ships `SHA256SUMS`, to check the downloads with
`sha256sum -c SHA256SUMS --ignore-missing`.

## Homebrew (macOS, Linux)

```bash
brew tap rtulke/checkmate https://github.com/rtulke/checkmate
brew install checkmate
```

The formula lives in this repository, so the tap needs its URL once;
`brew upgrade checkmate` then follows new releases. This installs the
binary, the man pages and the policies below
`$(brew --prefix)/share/checkmate/`. `brew install --HEAD checkmate` builds
the main branch.

```bash
sudo checkmate run "$(brew --prefix)/share/checkmate/cis/macos15.yml" --tags cis-level-1
```

## Download a binary

The [releases page](https://github.com/rtulke/checkmate/releases) also has a
static binary for every platform:

=== "Linux"

    ```bash
    curl -fsSLo checkmate https://github.com/rtulke/checkmate/releases/latest/download/checkmate-linux-amd64
    sudo install -m 0755 checkmate /usr/local/bin/checkmate
    checkmate version
    ```

=== "macOS"

    ```bash
    curl -fsSLo checkmate https://github.com/rtulke/checkmate/releases/latest/download/checkmate-darwin-arm64
    sudo install -m 0755 checkmate /usr/local/bin/checkmate
    checkmate version
    ```

=== "Windows"

    ```powershell
    Invoke-WebRequest -OutFile checkmate.exe https://github.com/rtulke/checkmate/releases/latest/download/checkmate-windows-amd64.exe
    .\checkmate.exe version
    ```

## Install with Go

```bash
go install github.com/rtulke/checkmate/cmd/checkmate@latest
```

## Build from source

You need Go 1.26 or newer.

```bash
git clone https://github.com/rtulke/checkmate.git
cd checkmate
make build          # creates bin/checkmate
make dist           # cross-compiles for Linux, macOS and Windows into dist/
make packages       # .deb and .rpm for amd64 and arm64 into dist/
```

## Man pages

`man checkmate` describes the commands and options, `man checkmate-policy`
the format of policy and waiver files. Both are installed by the packages
and by Homebrew; in a source checkout they are in `packaging/man/`.

## Running as root

Many system checks need root, for example to read `/etc/shadow` or run `sshd -T`. Checks that need it are usually guarded with `when: facts.is_root`, so running without root simply skips them.

When checkmate runs as root it refuses policy and waiver files that another user could have changed, because a policy is code that runs as root. A file is accepted if it is not group- or world-writable and is owned by root **or by the owner of the checkmate executable**. The second case covers Homebrew, where the binary and the installed policies belong to the admin user: whoever owns the binary can change what runs as root anyway. With a package install (binary owned by root) only root-owned files are accepted.

```text
checkmate: /opt/policies/base.yml: refusing to load a group- or world-writable policy file as root
checkmate: /home/alice/p.yml: refusing to load a policy file as root that is owned neither by root nor by the owner of the checkmate executable
```

The directories above the file count as well, since whoever can write to a directory can replace a file in it. A directory is refused if it belongs to a user who would not be trusted with the file, or if everyone can write to it and it lacks the sticky bit that `/tmp` has.

Fix the ownership and permissions (`chown root:root`, `chmod 644`) or, for a one-off run of a file you trust, pass `--allow-insecure-policy`.

On **Windows** the same applies to a run with administrator rights: a policy file is refused if the access control list of the file or of its directory lets `Users`, `Authenticated Users` or `Everyone` write. That is the case for a folder created directly under `C:\`, which inherits such a right. Keep policies in a folder only administrators can write to, for example below `C:\Program Files` or in the profile of an administrator.

```text
checkmate: C:\policies\base.yml: refusing to load a policy file with administrator rights: Authenticated Users may write to C:\policies
```

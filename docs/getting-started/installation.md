# Installation

checkmate is a single static binary. Nothing else needs to be installed on the target system; the checks use the tools that are already there (a POSIX shell on Linux and macOS, PowerShell on Windows).

## Download a release

Download the binary for your platform from the [releases page](https://github.com/rtulke/checkmate/releases) and put it on your `PATH`:

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

You need Go 1.24 or newer.

```bash
git clone https://github.com/rtulke/checkmate.git
cd checkmate
make build          # creates bin/checkmate
make dist           # cross-compiles for Linux, macOS and Windows into dist/
```

## Running as root

Many system checks need root, for example to read `/etc/shadow` or run `sshd -T`. Checks that need it are usually guarded with `when: facts.is_root`, so running without root simply skips them.

When checkmate runs as root it refuses policy files that are writable by other users, because a policy is code that runs as root:

```text
checkmate: /opt/policies/base.yml: refusing to load a group- or world-writable policy file as root
```

Fix the permissions (`chown root:root`, `chmod 644`) or, for testing only, pass `--allow-insecure-policy`.

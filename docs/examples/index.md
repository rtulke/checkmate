# Examples

44 ready-to-use policies with 496 checks. Every example is validated, syntax-checked for each
platform and executed on RHEL, Debian, Ubuntu, openSUSE and Alpine in the test suite, so you can copy them as a
starting point.

<div class="grid cards" markdown>

- :material-rocket-launch: **[Getting started](getting-started.md)**

    ---

    Demonstrates the building blocks of a checkmate policy.

- :material-penguin: **[Platforms](platforms/index.md)**

    ---

    Operating-system specific baselines: generic Linux, the RHEL, Debian and SUSE families, macOS and Windows.

    [Debian and Ubuntu](platforms/debian.md) · [Linux (generic)](platforms/linux.md) · [macOS](platforms/macos.md) · [Red Hat Enterprise Linux family](platforms/rhel.md) · [SUSE Linux Enterprise and openSUSE](platforms/suse.md) · [Windows](platforms/windows.md)

- :material-cog: **[System](system/index.md)**

    ---

    Users, sudo, SSH, PAM, services, kernel, boot, time, logging, packages, cron and mandatory access control.

    [Boot security](system/boot.md) · [cron and systemd timers](system/cron.md) · [Kernel hardening](system/kernel.md) · [Logging and auditing](system/logging.md) · [Packages and updates](system/packages.md) · [PAM, password quality and account lockout](system/pam.md) · [SELinux and AppArmor](system/security-modules.md) · [systemd services](system/services.md) · [OpenSSH server](system/ssh.md) · [sudo](system/sudo.md) · [Time synchronisation](system/time.md) · [Users and groups](system/users.md)

- :material-folder-lock: **[Files](files/index.md)**

    ---

    Permissions, content, integrity, file-system searches, mounts and disk space.

    [File content](files/content.md) · [Disk space](files/disk-space.md) · [Filesystems and mounts](files/filesystems.md) · [File integrity](files/integrity.md) · [File permissions and ownership](files/permissions.md) · [Searching the file system](files/search.md)

- :material-lan: **[Network](network/index.md)**

    ---

    Interfaces and routing, listening ports, host firewalls, DNS and TLS.

    [DNS and name resolution](network/dns.md) · [Host firewall](network/firewall.md) · [Network interfaces and routing](network/interfaces.md) · [Listening ports and reachability](network/ports.md) · [TLS certificates and endpoints](network/tls.md)

- :material-chip: **[Hardware](hardware/index.md)**

    ---

    CPU and memory, disks and RAID, virtualization and IPMI sensors.

    [CPU and memory](hardware/cpu-memory.md) · [Disks and RAID](hardware/disks.md) · [Virtualization and out-of-band management](hardware/virtualization.md)

- :material-router-network: **[Network devices](network-devices/index.md)**

    ---

    Switches, routers and firewalls over SSH, eAPI and SNMP: Cisco, Juniper, Arista and any SNMP device.

    [Arista EOS (eAPI)](network-devices/arista-eos.md) · [Cisco IOS / IOS-XE switches and routers](network-devices/cisco-ios.md) · [Juniper Junos](network-devices/juniper-junos.md) · [SNMP polling (any vendor)](network-devices/snmp.md)

- :material-remote-desktop: **[Remote hosts](remote/index.md)**

    ---

    Checking servers from a management host over SSH without installing anything.

    [Linux hosts over SSH](remote/linux-over-ssh.md)

- :material-application-cog: **[Applications](applications/index.md)**

    ---

    Docker, Kubernetes, web servers, PostgreSQL and web endpoints.

    [Docker](applications/docker.md) · [Kubernetes cluster](applications/kubernetes.md) · [PostgreSQL](applications/postgresql.md) · [Web endpoints](applications/web-endpoints.md) · [nginx and Apache httpd](applications/web-servers.md)

- :material-shield-check: **[Compliance baselines](compliance/index.md)**

    ---

    Complete baselines that combine many checks with a tag-based selection model.

    [Managed RHEL baseline](compliance/managed-rhel.md)

</div>

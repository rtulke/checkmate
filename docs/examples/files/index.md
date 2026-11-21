# Files

Permissions, content, integrity, file-system searches, mounts and disk space.

| Example | Description | Checks |
|---|---|---|
| [File content](content.md) | Patterns for checking what is inside files: a line is present or absent, a key has a value (key=value, INI, JSON, YAML), a file matches a checksum, and multi-line content. | 10 |
| [Disk space](disk-space.md) | Free space and inodes per mount point, oversized log files and space held by deleted files. | 8 |
| [Filesystems and mounts](filesystems.md) | Separate partitions, hardened mount options, allowed filesystem types, fstab consistency, LVM health and swap. | 18 |
| [File integrity](integrity.md) | Detect modified files: single files against known checksums, whole directories against an allowlist, package databases and AIDE. | 9 |
| [File permissions and ownership](permissions.md) | Mode, owner and group of sensitive files. | 11 |
| [Searching the file system](search.md) | Find risky files across the whole file system: SUID/SGID binaries that do not come from a package or an allowlist, files with capabilities, world-writable files and recent changes. | 7 |

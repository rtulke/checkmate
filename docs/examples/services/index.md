# Linux services

Common Linux network services: Postfix, NFS, FTP (vsftpd, ProFTPD), BIND, DHCP (Kea, ISC dhcpd), Dovecot, Samba and OpenLDAP. Checks of a service are skipped when it is not installed.

| Example | Description | Checks |
|---|---|---|
| [BIND DNS server](bind.md) | Security of the BIND name server (named): valid configuration, no open recursion, restricted zone transfers, hidden version, DNSSEC validation, an unprivileged process and a protected rndc key. | 8 |
| [DHCP servers (Kea, ISC dhcpd)](dhcp.md) | Security of the DHCP servers Kea and ISC dhcpd: valid configuration, a protected control channel, no unauthenticated management API, and the end of life of ISC dhcpd. | 6 |
| [Dovecot](dovecot.md) | Security of the Dovecot IMAP/POP3 server: valid configuration, TLS required with TLS 1.2 or newer, no clear-text authentication without TLS, a protected private key and no clear-text POP3/IMAP listeners. | 7 |
| [FTP servers (vsftpd, ProFTPD)](ftps.md) | Security of vsftpd and ProFTPD: no anonymous access, encrypted logins and data (FTPS) with TLS 1.2 or newer, users locked into their home, no version in the banner, and transfer logging. | 16 |
| [NFS server](nfs.md) | Exports of an NFS server: no export to everyone, no root access for clients (no_root_squash), no unprivileged client ports, Kerberos instead of trusting client UIDs, NFSv4 only, and the permissions of the export files. | 7 |
| [OpenLDAP](openldap.md) | Security of an OpenLDAP server (slapd) configured through cn=config: TLS with TLS 1.2 or newer, encryption required, no anonymous binds, hashed passwords, protected userPassword attributes and an unprivileged process. | 8 |
| [Postfix](postfix.md) | Security and operation of the Postfix mail server: no open relay, no information disclosure, TLS for incoming and outgoing mail, SASL only over TLS, and the mail queue. | 13 |
| [Samba](samba.md) | Security of a Samba file server: valid configuration, SMB 2.1 or newer, NTLMv2 only, signing and encryption, no guest access and no shares writable by everyone. | 10 |

# CIS PostgreSQL

Checks for the automatable recommendations of the CIS PostgreSQL benchmark, for PostgreSQL 12 and later. checkmate runs as root and queries the server as the postgres user with psql over the local socket. Recommendations that need a human review (privilege design, row level security, backup strategy) are not included. Profiles: `cis-postgresql-db` (database settings) and `cis-postgresql-linux` (operating system); every recommendation is Level 1.

**Policy:** [`cis/postgresql.yml`](https://github.com/rtulke/checkmate/blob/main/cis/postgresql.yml) · **Benchmark version:** 1.0.0

Runs as root and queries the server as the postgres user over the local socket:

```bash
sudo checkmate run cis/postgresql.yml
sudo checkmate run cis/postgresql.yml --tags cis-postgresql-db -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-PG-0-server-reachable` | The PostgreSQL server answers on the local socket |  | <span class="sev sev-info">info</span> |
| `CIS-PG-1.2-service-enabled` | A PostgreSQL systemd unit is enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-1.3-cluster-initialized` | The data directory contains an initialized cluster | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-2.1-umask` | The postgres account uses umask 077 | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-2.1-data-directory-mode` | The data directory is accessible only by its owner | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.2-log-destination` | Server messages are written to a log destination | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.3-logging_collector` | The logging collector is enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.4-log_directory` | A log directory is set | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.5-log_filename` | Log file names contain a time pattern | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.6-log_file_mode` | Log files are readable only by the server account | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.7-log_truncate_on_rotation` | Log files are truncated on time-based rotation | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.10-syslog_facility` | A local syslog facility is used | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.11-syslog_sequence_numbers` | Syslog messages carry sequence numbers | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.12-syslog_split_messages` | Long syslog messages are split instead of truncated | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.13-syslog_ident` | A syslog program name is set | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.14-log_min_messages` | Warnings and more severe messages are logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.15-log_min_error_statement` | Statements causing errors are logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.16-debug_print_parse` | Parse trees are not logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.17-debug_print_rewritten` | Rewritten query trees are not logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.18-debug_print_plan` | Execution plans are not logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.19-debug_pretty_print` | Debug output is indented | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.20-log_connections` | Connection attempts are logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.21-log_disconnections` | Session ends are logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.22-log_error_verbosity` | Error messages are logged with detail | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.23-log_hostname` | Client host names are not resolved for logging | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.25-log_statement` | Data definition statements are logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.26-log_timezone` | Log timestamps use UTC | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.1.8-log-rotation-age` | Log files are rotated by age | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-3.1.9-log-rotation-size` | Log files are rotated by size | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-3.1.24-log-line-prefix` | Log lines carry time, process, database, user and client | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-3.2-pgaudit` | The pgAudit extension is preloaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-4.1-postgres-no-sudo` | The postgres account cannot run commands with sudo | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-4.2-admin-roles` | Only approved roles have administrative attributes | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-4.3-security-definer` | No user function runs with the privileges of its owner | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-4.6-set-user` | The set_user extension is available | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-5.1-no-trust` | No pg_hba.conf rule allows login without authentication | L1 | <span class="sev sev-critical">critical</span> |
| `CIS-PG-5.2-host-auth` | Network logins use a strong authentication method | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-5.2-hba-valid` | pg_hba.conf has no invalid lines | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-5.2-password-encryption` | Passwords are stored as SCRAM-SHA-256 | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-6.7-fips` | The kernel runs in FIPS mode | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-6.8-ssl` | TLS is enabled | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-6.8-ssl-min-protocol` | TLS 1.2 or newer is required | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-6.8-ssl-key-file` | The TLS private key is readable only by its owner | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-6.9-pgcrypto` | The pgcrypto extension is available | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-7.1-replication-not-superuser` | Replication does not connect as a superuser | L1 | <span class="sev sev-high">high</span> |
| `CIS-PG-7.2-log-replication-commands` | Replication commands are logged | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-7.4-wal-archiving` | WAL archiving is enabled and has a target | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-7.5-standby-tls` | A standby connects to its primary with TLS | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-PG-8.1-log-directory-outside` | The log directory is outside the data directory | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-8.2-pgbackrest` | pgBackRest is installed | L1 | <span class="sev sev-low">low</span> |
| `CIS-PG-8.3-dynamic-library-path` | Libraries are loaded only from the installation directory | L1 | <span class="sev sev-medium">medium</span> |

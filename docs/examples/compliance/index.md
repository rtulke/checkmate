# Compliance baselines

Complete baselines: a broad Linux hardening baseline modelled on OpenSCAP and CIS, and a managed-RHEL baseline with a tag-based selection model.

| Example | Description | Checks |
|---|---|---|
| [BSI IT-Grundschutz Linux server](bsi-grundschutz.md) | Technical checks for the host-verifiable requirements of the BSI IT-Grundschutz building blocks SYS.1.1 "Allgemeiner Server" and SYS.1.3 "Server unter Linux und Unix" (IT-Grundschutz-Kompendium, Edition 2023). | 53 |
| [Linux hardening baseline](linux-hardening.md) | A broad server hardening baseline for current Linux distributions, structured like the public hardening guides of the SCAP Security Guide (OpenSCAP) and the CIS benchmarks: file systems, services, network parameters, auditing, logging, access control, accounts, file permissions, boot and maintenance. | 324 |
| [Managed RHEL baseline](managed-rhel.md) | A complete managed-OS baseline for RHEL 8/9, ported from the module-based checkmate 1.x. | 79 |
| [Si001 IT-Grundschutz (Swiss Federal Administration)](si001.md) | Technical checks for the requirements of Si001 "IT-Grundschutz in der Bundesverwaltung" (version 5.1) that can be verified on a host. | 35 |

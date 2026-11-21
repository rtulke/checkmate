# Applications

Docker, Kubernetes, nginx, Apache, PHP and web content, PostgreSQL, MySQL, MongoDB, Redis and web endpoints.

| Example | Description | Checks |
|---|---|---|
| [Apache httpd in depth](apache.md) | A detailed Apache httpd review following the topics of the httpd rules in the SCAP Security Guide: loaded modules, information disclosure, directory options, request limits and timeouts, TLS, logging, the service account and file permissions. | 30 |
| [Docker](docker.md) | Docker daemon configuration and running containers. | 8 |
| [Kubernetes cluster](kubernetes.md) | Cluster-wide checks with kubectl and jq from an admin workstation or a CI job: node health, failing pods, privileged workloads, cluster-admin bindings and the API server version. | 7 |
| [MongoDB](mongodb.md) | MongoDB authentication, network exposure, transport encryption, server-side scripting, auditing and the service account, read from the configuration file mongod.conf (YAML). | 10 |
| [MySQL and MariaDB](mysql.md) | Server settings, accounts and file permissions for MySQL and MariaDB. | 12 |
| [nginx in depth](nginx.md) | A detailed nginx review covering the topics of the public nginx hardening benchmarks: modules, service account, file permissions, timeouts and request limits, information disclosure, logging, TLS and security headers. | 32 |
| [PHP and web content](php-web.md) | PHP runtime settings and a scan of web directories for signs of compromise: web shells, obfuscated eval code, unusual file names and modified .htaccess files. | 16 |
| [PostgreSQL](postgresql.md) | Server availability and security settings, queried with SQL through a snippet. | 9 |
| [Redis](redis.md) | Redis exposure and authentication: bind address, protected mode, passwords or ACLs, dangerous commands and file permissions. | 7 |
| [Web endpoints](web-endpoints.md) | Black-box checks of websites and APIs with curl: status codes, HTTPS redirects, security headers, response time and version disclosure. | 7 |
| [nginx and Apache httpd](web-servers.md) | Configuration syntax, version disclosure, directory listings and TLS protocols for nginx and Apache. | 7 |

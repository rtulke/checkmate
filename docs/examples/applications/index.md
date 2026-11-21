# Applications

Docker, Kubernetes, web servers, PostgreSQL, MySQL, Redis and web endpoints.

| Example | Description | Checks |
|---|---|---|
| [Docker](docker.md) | Docker daemon configuration and running containers. | 8 |
| [Kubernetes cluster](kubernetes.md) | Cluster-wide checks with kubectl and jq from an admin workstation or a CI job: node health, failing pods, privileged workloads, cluster-admin bindings and the API server version. | 7 |
| [MySQL and MariaDB](mysql.md) | Server settings, accounts and file permissions for MySQL and MariaDB. | 12 |
| [PostgreSQL](postgresql.md) | Server availability and security settings, queried with SQL through a snippet. | 9 |
| [Redis](redis.md) | Redis exposure and authentication: bind address, protected mode, passwords or ACLs, dangerous commands and file permissions. | 7 |
| [Web endpoints](web-endpoints.md) | Black-box checks of websites and APIs with curl: status codes, HTTPS redirects, security headers, response time and version disclosure. | 7 |
| [nginx and Apache httpd](web-servers.md) | Configuration syntax, version disclosure, directory listings and TLS protocols for nginx and Apache. | 7 |

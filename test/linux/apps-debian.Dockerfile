FROM debian:12
# Application servers for the application examples (not started, the checks
# read their configuration).
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nginx apache2 php-cli postfix procps iproute2 openssl curl jq ca-certificates && rm -rf /var/lib/apt/lists/*
COPY fixtures/mongod.conf /etc/mongod.conf
RUN chmod 640 /etc/mongod.conf

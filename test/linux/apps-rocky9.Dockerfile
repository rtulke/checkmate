FROM rockylinux:9
RUN dnf -y install --allowerasing nginx httpd mod_ssl php-cli postfix procps-ng iproute openssl curl jq findutils && dnf clean all
COPY fixtures/mongod.conf /etc/mongod.conf
RUN chmod 640 /etc/mongod.conf

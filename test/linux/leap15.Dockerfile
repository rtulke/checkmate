FROM opensuse/leap:15.6
RUN zypper -n install procps iproute2 openssl openssh-server openssh-clients sudo cronie chrony audit lsof curl jq \
      gawk findutils util-linux hostname netcat-openbsd && zypper clean -a && ssh-keygen -A

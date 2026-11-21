FROM rockylinux:8
RUN dnf -y install --allowerasing procps-ng iproute findutils util-linux openssl openssh-server openssh-clients \
      sudo cronie chrony audit hostname which lsof curl jq authselect libpwquality nmap-ncat && dnf clean all && ssh-keygen -A

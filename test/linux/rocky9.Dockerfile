FROM rockylinux:9
RUN dnf -y install --allowerasing procps-ng iproute findutils util-linux openssl openssh-server openssh-clients \
      sudo cronie chrony audit hostname diffutils which file lsof gawk sed grep curl jq python3 \
      authselect libpwquality nmap-ncat && dnf clean all && ssh-keygen -A

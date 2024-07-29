FROM quay.io/centos/centos:stream9

WORKDIR /root
RUN dnf install -y epel-release epel-next-release && dnf config-manager --set-enabled crb && \
    dnf update -y && \
    dnf install -y autoconf awscli curl git gnupg2 nfs-utils python36 expect jq libtool gcc-c++ libstdc++-devel rpmdevtools createrepo rpm-sign bzip2 which && \
    dnf -y --enablerepo=powertools install libstdc++-static

RUN echo "${BOLD}Downloading and installing binaries...${RESET}" && \
    curl -Of https://shellcheck.storage.googleapis.com/shellcheck-v0.7.0.linux.x86_64.tar.xz && \
    tar -C /usr/local/bin/ -xf shellcheck-v0.7.0.linux.x86_64.tar.xz --no-anchored 'shellcheck' --strip=1

ENTRYPOINT ["/bin/bash"]


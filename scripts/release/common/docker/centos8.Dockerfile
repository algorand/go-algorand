FROM quay.io/centos/centos:stream8

WORKDIR /root
RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && \
    dnf install -y autoconf awscli curl git gnupg2 nfs-utils python36 sqlite boost-devel expect jq libtool gcc-c++ libstdc++-devel rpmdevtools createrepo rpm-sign bzip2 which && \
    dnf -y --enablerepo=powertools install libstdc++-static

RUN echo "${BOLD}Downloading and installing binaries...${RESET}" && \
    curl -Of https://shellcheck.storage.googleapis.com/shellcheck-v0.7.0.linux.x86_64.tar.xz && \
    tar -C /usr/local/bin/ -xf shellcheck-v0.7.0.linux.x86_64.tar.xz --no-anchored 'shellcheck' --strip=1

ENTRYPOINT ["/bin/bash"]


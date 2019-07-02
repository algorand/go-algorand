FROM centos:7
WORKDIR /root
RUN yum install -y epel-release https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum install -y autoconf awscli git gnupg2 nfs-utils python36 sqlite3 boost-devel expect jq libtool gcc-c++ libstdc++-devel libstdc++-static rpmdevtools createrepo rpm-sign bzip2

ENTRYPOINT ["/bin/bash"]

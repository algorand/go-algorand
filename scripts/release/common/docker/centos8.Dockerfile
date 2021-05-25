FROM centos:8

WORKDIR /root
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
RUN yum install -y autoconf awscli curl git gnupg2 nfs-utils python36 sqlite3 boost-devel expect jq libtool gcc-c++ libstdc++-devel libstdc++-static rpmdevtools createrepo rpm-sign bzip2 which ShellCheck

ENTRYPOINT ["/bin/bash"]


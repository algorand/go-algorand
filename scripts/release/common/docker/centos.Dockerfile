FROM centos:7

WORKDIR /root
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum install -y autoconf awscli curl git gnupg2 nfs-utils python36 expect jq libtool gcc-c++ libstdc++-devel libstdc++-static rpmdevtools createrepo rpm-sign bzip2 which ShellCheck

ENTRYPOINT ["/bin/bash"]


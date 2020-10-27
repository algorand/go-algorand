ARG ARCH="amd64"

FROM ${ARCH}/centos:7
ARG GOLANG_VERSION
ARG ARCH="amd64"
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum update -y && \
    yum install -y autoconf wget awscli git gnupg2 nfs-utils python3-devel sqlite3 boost-devel expect jq \
    libtool gcc-c++ libstdc++-devel libstdc++-static rpmdevtools createrepo rpm-sign bzip2 which ShellCheck \
    libffi-devel openssl-devel
WORKDIR /root
RUN wget https://dl.google.com/go/go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz \
    && tar -xvf go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz && \
    mv go /usr/local
ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go
RUN mkdir -p $GOPATH/src/github.com/algorand
COPY . $GOPATH/src/github.com/algorand/go-algorand
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH \
    GOPROXY=https://gocenter.io
WORKDIR $GOPATH/src/github.com/algorand/go-algorand
RUN make ci-deps && make clean
RUN rm -rf $GOPATH/src/github.com/algorand/go-algorand && \
    mkdir -p $GOPATH/src/github.com/algorand/go-algorand
RUN echo "vm.max_map_count = 262144" >> /etc/sysctl.conf
CMD ["/bin/bash"]

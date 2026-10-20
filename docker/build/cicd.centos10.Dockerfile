ARG ARCH="amd64"

FROM quay.io/centos/centos:stream10
ARG GOLANG_VERSION
ARG ARCH="amd64"
RUN dnf install -y epel-release && dnf config-manager --set-enabled crb && \
    dnf update -y && \
    dnf install -y autoconf wget awscli git gnupg2 nfs-utils python3-devel expect jq \
    libtool gcc-c++ libstdc++-devel rpmdevtools createrepo rpm-sign bzip2 which \
    libffi-devel openssl-devel libstdc++-static
RUN echo "${BOLD}Downloading and installing binaries...${RESET}" && \
    curl -Of https://shellcheck.storage.googleapis.com/shellcheck-v0.7.0.linux.x86_64.tar.xz && \
    tar -C /usr/local/bin/ -xf shellcheck-v0.7.0.linux.x86_64.tar.xz --no-anchored 'shellcheck' --strip=1
WORKDIR /root
RUN wget https://dl.google.com/go/go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz \
    && tar -xvf go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz && \
    mv go /usr/local
ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go \
    ARCH_TYPE=${ARCH}
RUN mkdir -p $GOPATH/src/github.com/algorand
COPY . $GOPATH/src/github.com/algorand/go-algorand
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH \
    GOPROXY=https://proxy.golang.org,https://pkg.go.dev,https://goproxy.io,direct
WORKDIR $GOPATH/src/github.com/algorand/go-algorand
RUN git config --global --add safe.directory '*'
RUN make clean
RUN rm -rf $GOPATH/src/github.com/algorand/go-algorand && \
    mkdir -p $GOPATH/src/github.com/algorand/go-algorand
RUN echo "vm.max_map_count = 262144" >> /etc/sysctl.conf
CMD ["/bin/bash"]

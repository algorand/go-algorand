ARG ARCH="amd64"

FROM ${ARCH}/ubuntu:20.04
ARG GOLANG_VERSION
ARG ARCH="amd64"
ARG GOARCH="amd64"
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y build-essential git wget autoconf jq bsdmainutils shellcheck awscli libtool
WORKDIR /root
RUN wget https://dl.google.com/go/go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz \
    && tar -xvf go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz && \
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

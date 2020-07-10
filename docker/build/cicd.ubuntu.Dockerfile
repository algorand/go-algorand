ARG ARCH="amd64"

FROM ${ARCH}/ubuntu:18.04
ARG GOLANG_VERSION
ARG ARCH="amd64"
RUN apt-get update && apt-get install -y build-essential git libboost-all-dev wget sqlite3 autoconf jq bsdmainutils shellcheck
WORKDIR /root
RUN wget https://dl.google.com/go/go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz \
    && tar -xvf go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz && \
    mv go /usr/local
ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go
RUN mkdir -p $GOPATH/src/github.com/algorand
COPY . $GOPATH/src/github.com/algorand/go-algorand
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH \
    BRANCH=${BRANCH} \
    CHANNEL=${CHANNEL} \
    DEFAULTNETWORK=${DEFAULTNETWORK} \
    FULLVERSION=${FULLVERSION} \
    GOPROXY=https://gocenter.io \
    PKG_ROOT=${PKG_ROOT}
WORKDIR $GOPATH/src/github.com/algorand/go-algorand
RUN make ci-deps && make clean
RUN rm -rf $GOPATH/src/github.com/algorand/go-algorand && \
    mkdir -p $GOPATH/src/github.com/algorand/go-algorand
RUN echo "vm.max_map_count = 262144" >> /etc/sysctl.conf
CMD ["/bin/bash"]


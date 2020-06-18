FROM ubuntu:18.04
ARG GOLANG_VERSION
ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt-get install -y git libboost-all-dev wget sqlite3 autoconf sudo tzdata bsdmainutils

WORKDIR /root
RUN wget --quiet https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz && tar -xvf go${GOLANG_VERSION}.linux-amd64.tar.gz && mv go /usr/local
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV GOBIN /go/bin
ENV PATH   $GOPATH/bin:$GOROOT/bin:$PATH
RUN mkdir -p $GOPATH/src/github.com/algorand
WORKDIR $GOPATH/src/github.com/algorand
RUN git clone https://github.com/algorand/go-algorand
WORKDIR $GOPATH/src/github.com/algorand/go-algorand
RUN git checkout master && ./scripts/configure_dev.sh && make install
ENTRYPOINT ["/bin/bash"]

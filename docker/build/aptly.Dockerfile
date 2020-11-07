FROM ubuntu:18.04

ARG ARCH=amd64
ARG GOLANG_VERSION
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install aptly awscli binutils build-essential curl gnupg2 silversearcher-ag tree -y
RUN curl https://dl.google.com/go/go${GOLANG_VERSION}.linux-${ARCH%v*}.tar.gz | tar -xzf - && mv go /usr/local
ENV GOROOT=/usr/local/go \
    GOPATH=/root/go \
    PATH=$GOPATH/bin:$GOROOT/bin:$PATH

WORKDIR /root
COPY .aptly.conf .
RUN curl https://releases.algorand.com/key.pub | gpg --no-default-keyring --keyring trustedkeys.gpg --import - && \
    aptly mirror create stable https://releases.algorand.com/deb/ stable main && \
    aptly mirror create beta https://releases.algorand.com/deb/ beta main && \
    aptly mirror create indexer https://releases.algorand.com/deb/ indexer main && \
    aptly repo create -distribution=stable -architectures=amd64 -component=main -comment=mainnet stable && \
    aptly repo create -distribution=beta -architectures=amd64 -component=main -comment=betanet beta && \
    aptly repo create -distribution=indexer -architectures=amd64 -component=main -comment=indexer indexer && \
    aptly mirror update stable && \
    aptly mirror update beta && \
    aptly mirror update indexer && \
    aptly repo import stable stable algorand algorand-devtools
    aptly repo import beta beta algorand-beta algorand-devtools-beta && \
    aptly repo import indexer indexer algorand-indexer

CMD ["/bin/bash"]


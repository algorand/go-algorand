FROM ubuntu:18.04
ENV GOLANG_VERSION 1.12

RUN apt update && apt install -y git libboost-all-dev wget sqlite3 autoconf
WORKDIR /root
RUN wget --quiet https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz && tar -xvf go${GOLANG_VERSION}.linux-amd64.tar.gz && mv go /usr/local
ENV GOROOT /usr/local/go
ENV GOPATH $HOME/go
ENV PATH   $GOPATH/bin:$GOROOT/bin:$PATH
RUN mkdir -p $GOPATH/src/github.com/algorand
WORKDIR $GOPATH/src/github.com/algorand
RUN git clone https://github.com/algorand/go-algorand
WORKDIR $GOPATH/src/github.com/algorand/go-algorand
RUN apt-get -y install sudo
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y install tzdata
RUN apt-get -y install bsdmainutils
RUN git checkout master && scripts/configure_dev.sh && make
ENTRYPOINT ["/bin/bash"]

ARG ARCH="amd64"

FROM ${ARCH}/ubuntu:18.04
ENV GOLANG_VERSION 1.12 \
    GOROOT=/usr/local/go \
    GOPATH=$HOME/go \
    PATH=$GOPATH/bin:$GOROOT/bin:$PATH
RUN apt-get update && apt-get install curl wget python build-essential apt-transport-https ca-certificates software-properties-common -y && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt-get update && apt-get install docker-ce -y
WORKDIR /root
RUN wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz \
    && tar -xvf go1.12.linux-amd64.tar.gz && \
    mv go /usr/local
ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go
CMD ["/bin/bash"]


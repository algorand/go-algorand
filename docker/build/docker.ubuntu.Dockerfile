ARG ARCH="amd64"

FROM ${ARCH}/ubuntu:20.04
ARG GOLANG_VERSION
ARG ARCH="amd64"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install curl python python3.7 python3-pip build-essential apt-transport-https ca-certificates software-properties-common -y && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    DEBIAN_FRONTEND=noninteractive add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install docker-ce -y

RUN pip3 install mulecli

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y autoconf bsdmainutils git && \
    curl https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -xzf - && \
    mv go /usr/local

ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go \
    ARCH_TYPE=${ARCH}
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

WORKDIR /root
CMD ["/bin/bash"]


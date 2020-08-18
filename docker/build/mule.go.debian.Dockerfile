FROM docker:19 as docker
FROM python:3.7
ARG GOLANG_VERSION

COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY *.yaml /root/

RUN apt-get update && apt-get install -y autoconf bsdmainutils build-essential curl git libboost-all-dev && \
    curl https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -xzf - && \
    mv go /usr/local && \
    pip install mulecli

ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

WORKDIR /root

CMD ["/bin/bash"]


FROM docker:19 as docker
FROM python:3.7

COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY *.yaml ./

RUN pip install mulecli

RUN apt-get update && apt-get install -y build-essential curl libboost-all-dev autoconf bsdmainutils
RUN curl https://dl.google.com/go/go1.12.linux-amd64.tar.gz | tar -xzf -
RUN mv go /usr/local
ENV GOROOT=/usr/local/go \
    GOPATH=$HOME/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

WORKDIR /root

CMD ["/bin/bash"]


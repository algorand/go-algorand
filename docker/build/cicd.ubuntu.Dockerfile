ARG ARCH="amd64"

FROM ${ARCH}/ubuntu:24.04
ARG GOLANG_VERSION
ARG ARCH="amd64"
ARG GOARCH="amd64"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get install -y build-essential git wget autoconf jq bsdmainutils shellcheck libtool
RUN apt-get install -y curl unzip
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
WORKDIR /root
RUN wget https://dl.google.com/go/go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz \
    && tar -xvf go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz && \
    mv go /usr/local
RUN mkdir -p /app/go
ENV GOROOT=/usr/local/go \
    GOPATH=/app/go \
    ARCH_TYPE=${ARCH}
WORKDIR /app
COPY . /app
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH \
    GOPROXY=https://proxy.golang.org,https://pkg.go.dev,https://goproxy.io,direct
RUN git config --global --add safe.directory '*'
RUN make clean
RUN echo "vm.max_map_count = 262144" >> /etc/sysctl.conf
CMD ["/bin/bash"]
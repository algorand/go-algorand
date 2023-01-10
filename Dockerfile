FROM ubuntu:18.04 as builder

ARG GO_VERSION="1.17.13"

ARG CHANNEL
ARG URL
ARG BRANCH
ARG SHA
ARG TARGETARCH

ADD https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz /go.tar.gz

# Basic dependencies.
ENV HOME="/node" DEBIAN_FRONTEND="noninteractive" GOPATH="/node"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    apt-utils \
    bsdmainutils \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/* && \
    \
    tar -C /usr/local -xzf /go.tar.gz && \
    rm -rf /go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

COPY ./docker/files/ /node/files
COPY ./installer/genesis /node/files/run/genesis
COPY ./cmd/updater/update.sh /node/files/build/update.sh
COPY ./installer/config.json.example /node/files/run/config.json.example

# Install algod binaries.
RUN /node/files/build/install.sh \
    -p "${GOPATH}/bin" \
    -d "/node/data" \
    -c "${CHANNEL}" \
    -u "${URL}" \
    -b "${BRANCH}" \
    -s "${SHA}"

FROM debian:bullseye-slim as final

ENV PATH="/node/bin:${PATH}" ALGOD_PORT="8080" ALGORAND_DATA="/algod/data"

# curl is needed to lookup the fast catchup url
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p "$ALGORAND_DATA" && \
    groupadd --system algorand && \
    useradd --no-log-init --create-home --system --gid algorand algorand && \
    chown -R algorand:algorand /algod

USER algorand

COPY --chown=algorand:algorand --from=builder "/node/bin/" "/node/bin/"
COPY --chown=algorand:algorand --from=builder "/node/files/run/" "/node/run/"

# Expose Algod REST API, Algod Gossip, and Prometheus Metrics ports
EXPOSE $ALGOD_PORT 4160 9100

CMD ["/node/run/run.sh"]

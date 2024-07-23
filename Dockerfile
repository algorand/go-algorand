FROM ubuntu:20.04 as builder

ARG GO_VERSION="1.21.10"

ARG CHANNEL
ARG URL
ARG BRANCH
ARG SHA
ARG TARGETARCH

ADD https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz /go.tar.gz

# Basic dependencies.
ENV HOME="/node" DEBIAN_FRONTEND="noninteractive" GOPATH="/dist"

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

COPY ./docker/files/ /dist/files
COPY ./installer/genesis /dist/files/run/genesis
COPY ./cmd/updater/update.sh /dist/files/build/update.sh
COPY ./installer/config.json.example /dist/files/run/config.json.example

# Install algod binaries.
RUN /dist/files/build/install.sh \
    -p "${GOPATH}/bin" \
    -d "/algod/data" \
    -c "${CHANNEL}" \
    -u "${URL}" \
    -b "${BRANCH}" \
    -s "${SHA}"

FROM debian:bookworm-20240311-slim as final

ENV PATH="/node/bin:${PATH}" ALGOD_PORT="8080" KMD_PORT="7833" ALGORAND_DATA="/algod/data"

# curl is needed to lookup the fast catchup url
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    update-ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p "$ALGORAND_DATA" && \
    groupadd --gid=999 --system algorand && \
    useradd --uid=999 --no-log-init --create-home --system --gid algorand algorand && \
    chown -R algorand:algorand /algod

COPY --chown=algorand:algorand --from=builder "/dist/bin/" "/node/bin/"
COPY --chown=algorand:algorand --from=builder "/dist/files/run/" "/node/run/"

# Expose Algod REST API, KMD REST API, Algod Gossip, and Prometheus Metrics ports
EXPOSE $ALGOD_PORT $KMD_PORT 4160 9100

WORKDIR /algod

CMD ["/node/run/run.sh"]

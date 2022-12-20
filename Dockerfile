ARG GO_VERSION="1.17.13"

FROM golang:$GO_VERSION-bullseye as builder

ARG CHANNEL
ARG URL
ARG BRANCH
ARG SHA

# Basic dependencies.
ENV HOME="/node" DEBIAN_FRONTEND="noninteractive" GOPATH="/node"
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    bsdmainutils \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

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

RUN mkdir -p "$ALGORAND_DATA" && \
    groupadd --system algorand && \
    useradd --no-log-init --create-home --system --gid algorand algorand && \
    chown -R algorand:algorand /algod

USER algorand

COPY --chown=algorand:algorand --from=builder "/node/bin/" "/node/bin/"
COPY --chown=algorand:algorand --from=builder "/node/files/run/" "/node/run/"

# Expose Algod REST API, Algod Gossip, and Prometheus Metrics ports
EXPOSE $ALGOD_PORT 4160 9100

CMD ["/node/run/run.sh"]

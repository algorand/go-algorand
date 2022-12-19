ARG GO_VERSION="1.17.13"

FROM golang:$GO_VERSION-bullseye as builder

ARG CHANNEL
ARG URL
ARG BRANCH
ARG SHA

# Basic dependencies.
ENV HOME="/node"
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    bsdmainutils \
    curl \
    git \
    git-core \
    python3

COPY ./docker/files/ /node/files
COPY ./installer/genesis /node/files/run/genesis
COPY ./cmd/updater/update.sh /node/files/build/update.sh
COPY ./installer/config.json.example /node/files/build/config.json

# Install algod binaries.
RUN /node/files/build/install.sh \
    -p "/node/bin" \
    -d "/node/data" \
    -c "${CHANNEL}" \
    -u "${URL}" \
    -b "${BRANCH}" \
    -s "${SHA}"

# Copy binaries into a clean image
# TODO: We don't need most of the binaries.
#       Should we delete everything except goal/algod/algocfg/tealdbg?
FROM debian:bullseye-slim as final
COPY --from=builder "/node/bin/" "/node/bin"
COPY --from=builder "/node/data/" "/node/dataTemplate"
COPY --from=builder "/node/files/run" "/node/run"

ENV PATH="/node/bin:${PATH}" ALGOD_PORT="8080" ALGORAND_DATA="/algod/data"

WORKDIR /node/data

# curl is needed to lookup the fast catchup url
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    \
    mkdir -p "$ALGORAND_DATA" && \
    \
    groupadd --system algorand && \
    useradd --no-log-init --create-home --system --gid algorand algorand && \
    chown -R algorand.algorand /node && \
    chown -R algorand.algorand /algod

USER algorand

# Expose Algod REST API, Algod Gossip, and Prometheus Metrics ports
EXPOSE $ALGOD_PORT 4160 9100

CMD ["/node/run/run.sh"]

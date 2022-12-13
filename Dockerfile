ARG GO_VERSION=1.17.5
FROM golang:$GO_VERSION-bullseye as builder

ARG CHANNEL=nightly
ARG URL=
ARG BRANCH=
ARG SHA=

# Basic dependencies.
ENV HOME /node
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y \
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

RUN find /node/files

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

ENV BIN_DIR="/node/bin"
ENV PATH="$BIN_DIR:${PATH}"
ENV ALGOD_PORT=8080
ENV ALGORAND_DATA="/algod/data"
RUN mkdir -p "$ALGORAND_DATA"
WORKDIR /node/data

# curl is needed to lookup the fast catchup url
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# TODO: This works fine, but causes problems when mounting a volume
# Use algorand user instead of root
#RUN groupadd -r algorand && \
#  useradd --no-log-init -r -g algorand algorand && \
#  chown -R algorand.algorand /node && \
#  chown -R algorand.algorand /algod
#USER algorand

# Algod REST API
EXPOSE $ALGOD_PORT

# Algod Gossip Port
EXPOSE 4160

# Prometheus Metrics
EXPOSE 9100

CMD ["/node/run/run.sh"]
#CMD ["/bin/bash"]

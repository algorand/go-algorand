FROM ubuntu
ARG ALGOD_INSTALL_TAR_FILE

ENV PATH /root/node/bin:$PATH
ENV ALGORAND_DATA /root/node/data
ENV ALGORAND_NETWORK testnet

WORKDIR /root/install
RUN apt update && apt install -y ca-certificates curl --no-install-recommends

WORKDIR /root/node
ADD $ALGOD_INSTALL_TAR_FILE .
COPY algod_docker_init.sh .

CMD  [ "/root/node/algod_docker_init.sh" ]

ENTRYPOINT ["/bin/bash"]


ARG ARCH="amd64"

FROM ${ARCH}/ubuntu:18.04
RUN apt-get update && apt-get install curl python build-essential apt-transport-https ca-certificates software-properties-common -y && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt-get update && apt-get install docker-ce -y
WORKDIR /root
CMD ["/bin/bash"]


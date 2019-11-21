FROM ubuntu

WORKDIR /root/install
RUN apt update && apt install -y ca-certificates curl --no-install-recommends && \
    curl --silent -L https://github.com/algorand/go-algorand-doc/blob/master/downloads/installers/linux_amd64/install_master_linux-amd64.tar.gz?raw=true -o installer.tar.gz && \
    tar -xf installer.tar.gz && \
    ./update.sh -c stable -n -p ~/node -d ~/node/data -i && \
    cd .. && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf install
WORKDIR /root/node

ENTRYPOINT ["/bin/bash"]

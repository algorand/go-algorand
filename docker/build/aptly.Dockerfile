FROM ubuntu:22.04

ARG ARCH=amd64

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install aptly awscli binutils build-essential curl gnupg2 -y

WORKDIR /root
COPY .aptly.conf .
RUN curl https://releases.algorand.com/key.pub | gpg --no-default-keyring --keyring /root/.gnupg/trustedkeys.gpg --import -
RUN gpg --no-default-keyring --keyring /root/.gnupg/trustedkeys.gpg --export --output /root/.gnupg/newkeyring.gpg && mv -f /root/.gnupg/newkeyring.gpg /root/.gnupg/trustedkeys.gpg
RUN aptly mirror create stable https://releases.algorand.com/deb/ stable main && \
    aptly mirror create beta https://releases.algorand.com/deb/ beta main && \
    aptly repo create -distribution=stable -architectures=amd64,arm64 -component=main -comment=mainnet stable && \
    aptly repo create -distribution=beta -architectures=amd64,arm64 -component=main -comment=betanet beta

CMD ["/bin/bash"]

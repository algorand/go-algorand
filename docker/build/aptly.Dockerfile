FROM ubuntu:24.04

ARG ARCH=amd64

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install aptly binutils build-essential curl gnupg2 -y
RUN apt-get install -y curl unzip
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update

WORKDIR /root
COPY .aptly.conf .
RUN curl https://releases.algorand.com/key.pub | gpg --no-default-keyring --keyring /root/.gnupg/trustedkeys.gpg --import -
RUN gpg --no-default-keyring --keyring /root/.gnupg/trustedkeys.gpg --export --output /root/.gnupg/newkeyring.gpg && mv -f /root/.gnupg/newkeyring.gpg /root/.gnupg/trustedkeys.gpg
RUN aptly mirror create stable https://releases.algorand.com/deb/ stable main && \
    aptly mirror create beta https://releases.algorand.com/deb/ beta main && \
    aptly repo create -distribution=stable -architectures=amd64,arm64 -component=main -comment=mainnet stable && \
    aptly repo create -distribution=beta -architectures=amd64,arm64 -component=main -comment=betanet beta

CMD ["/bin/bash"]

FROM ubuntu:18.04

ARG AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY

ENV DEBIAN_FRONTEND noninteractive \
    AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
    AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY

RUN apt-get update && apt-get install aptly awscli binutils curl gnupg2 silversearcher-ag tree -y

WORKDIR /root

COPY . .

RUN aws s3 sync s3://algorand-internal/packages packages && \
    aptly repo create -distribution=stable -architectures=amd64 -component=main -comment=mainnet algorand && \
    aptly repo create -distribution=beta -architectures=amd64 -component=main -comment=betanet algorand-beta && \
    aptly repo create -distribution=indexer -architectures=amd64 -component=main -comment=indexer algorand-indexer && \
    aptly repo create -distribution=indexer-beta -architectures=amd64 -component=main -comment=indexer-beta algorand-indexer-beta && \
    aptly repo add algorand packages/deb/stable/*.deb && \
    aptly repo add algorand-beta packages/deb/beta/*.deb && \
    aptly repo add algorand-indexer packages/deb/indexer/stable/*.deb && \
    aptly repo add algorand-indexer-beta packages/deb/indexer/beta/*.deb

CMD ["/bin/bash"]


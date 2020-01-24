#!/usr/bin/env bash

# Need to log in to Docker desktop before docker push will succeed.
# e.g. `docker login`
# Login name is "algorand".

# To build both images, one could run:
#
# $ ./build_releases.sh
# $ ./build_releases.sh testnet
#
# or
#
# for name in {mainnet,testnet}
# do
#     ./build_releases.sh $name
# done

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

# Default to "mainnet".
NAME=${1:-mainnet}
NETWORK=

if [[ ! "$NAME" =~ ^mainnet$|^testnet$ ]]
then
    echo "$RED_FG[$0]$END_FG_COLOR Network values must be either \`mainnet\` or \`testnet\`."
    exit 1
fi

if [ "$NAME" == "testnet" ]
then
    NETWORK="-g $1"
fi

build_image () {
    IFS='' read -r -d '' DOCKERFILE <<EOF
    FROM ubuntu

    WORKDIR /root/install
    RUN apt-get update && apt-get install -y ca-certificates curl --no-install-recommends && \
        curl --silent -L https://github.com/algorand/go-algorand-doc/blob/master/downloads/installers/linux_amd64/install_master_linux-amd64.tar.gz?raw=true | tar xzf - && \
        ./update.sh -c stable -n -p ~/node -d ~/node/data -i $NETWORK && \
        cd .. && \
        rm -rf install /var/lib/apt/lists/*
    WORKDIR /root/node

    ENTRYPOINT ["/bin/bash"]
EOF

    if ! echo "$DOCKERFILE" | docker build -t algorand/"$NAME":latest -
    then
        echo -e "\n$RED_FG[$0]$END_FG_COLOR The algorand/$NAME:latest image could not be built."
        exit 1
    fi
}

build_image

if ! docker push algorand/"$NAME":latest
then
    echo -e "\n$RED_FG[$0]$END_FG_COLOR \`docker push\` failed."
    exit 1
fi

echo "$GREEN_FG[$0]$END_FG_COLOR Build completed with no failures."


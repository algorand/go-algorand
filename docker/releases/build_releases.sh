#!/usr/bin/env bash

# Need to log in to Docker desktop before docker push will succeed.
# e.g. `docker login`
# Login name is "algorand".
#
# To build and push to docker hub the latest release:
#
# For mainnet:
#   ./build_releases.sh
#   ./build_releases.sh --tagname 2.0.6
#
# For testnet:
#   ./build_releases.sh --network testnet
#
# For betanet:
#   ./build_releases.sh --network betanet
#

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

# These are reasonable defaults.
CHANNEL=stable
DEPLOY=true
IMAGE_NAME=stable
NETWORK=mainnet
TAGNAME=latest

while [ "$1" != "" ]; do
    case "$1" in
        --name)
            shift
            IMAGE_NAME="${1-stable}"
            ;;
        --network)
            shift
            NETWORK="$1"
            ;;
        --no-deploy)
            DEPLOY=false
            ;;
        --tagname)
            shift
            TAGNAME="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [[ ! "$NETWORK" =~ ^mainnet$|^testnet$|^betanet$ ]]
then
    echo "$RED_FG[$0]$END_FG_COLOR Network values must be either \`mainnet\`, \`testnet\` or \`betanet\`."
    exit 1
elif [ "$NETWORK" != "mainnet" ]
then
    if [ "$NETWORK" == "betanet" ]
    then
        CHANNEL=beta
    fi

    IMAGE_NAME="$NETWORK"
    NETWORK="-g $NETWORK"
fi

build_image () {
    IFS='' read -r -d '' DOCKERFILE <<EOF
    FROM ubuntu

    RUN apt-get update && apt-get install -y ca-certificates curl --no-install-recommends && \
        curl --silent -L https://github.com/algorand/go-algorand-doc/blob/master/downloads/installers/linux_amd64/install_master_linux-amd64.tar.gz?raw=true | tar xzf - && \
        ./update.sh -c $CHANNEL -n -p ~/node -d ~/node/data -i $NETWORK
    WORKDIR /root/node
EOF

    if ! echo "$DOCKERFILE" | docker build -t "algorand/$IMAGE_NAME:$TAGNAME" -
    then
        echo -e "\n$RED_FG[$0]$END_FG_COLOR The algorand/$IMAGE_NAME:$TAGNAME image could not be built."
        exit 1
    fi
}

build_image

if $DEPLOY
then
    if ! docker push "algorand/$IMAGE_NAME:$TAGNAME"
    then
        echo -e "\n$RED_FG[$0]$END_FG_COLOR \`docker push\` failed."
        exit 1
    fi

    echo -e "\n$GREEN_FG[$0]$END_FG_COLOR Successfully published to docker hub."
fi

echo "$GREEN_FG[$0]$END_FG_COLOR Build completed with no failures."


#!/usr/bin/env bash

# Need to log in to Docker desktop before docker push will succeed.
# e.g. `docker login`
# Login name is "algorand".

GREEN_FG=$(tput setaf 2)
RED_FG=$(tput setaf 1)
END_FG_COLOR=$(tput sgr0)

NAME=stable
NETWORK=""

while [ "$1" != "" ]; do
    case "$1" in
        -n|--name)
            shift
            NAME="$1"
            NETWORK="-g $1"
            ;;
        *)
            echo "$RED_FG[$0]$END_FG_COLOR Unknown option $1."
            exit 1
            ;;
    esac
    shift
done

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


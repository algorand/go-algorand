#!/usr/bin/env bash

OS_LIST=(
    centos:7
    centos:8
    fedora:28
    ubuntu:16.04
    ubuntu:18.04
)

AWS_KEY_ID=
AWS_SECRET_KEY=

# These are default values which can be changed by the CLI args.
BUCKET=algorand-builds
CHANNEL=stable

FAILED=()
RET_VALUE=0

while [ "$1" != "" ]; do
    case "$1" in
        -c)
            shift
            CHANNEL="$1"
            ;;
        -b)
            shift
            BUCKET="$1"
            ;;
        -k)
            shift
            AWS_KEY_ID="$1"
            ;;
        -s)
            shift
            AWS_SECRET_KEY="$1"
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
    shift
done

# We'll use this simple tokenized Dockerfile.
# https://serverfault.com/a/72511
IFS='' read -r -d '' TOKENIZED <<EOF
FROM {{OS}}
WORKDIR /root/install
{{PACMAN}}

ENV AWS_ACCESS_KEY_ID=$AWS_KEY_ID
ENV AWS_SECRET_ACCESS_KEY=$AWS_SECRET_KEY

RUN curl --silent -L https://github.com/algorand/go-algorand-doc/blob/master/downloads/installers/linux_amd64/install_master_linux-amd64.tar.gz?raw=true | tar xzf - && \
    ./update.sh -b $BUCKET -c $CHANNEL -n -p ~/node -d ~/node/data -i && \
    cd .. && \
    rm -rf install /var/lib/apt/lists/*

WORKDIR /root/node
ENTRYPOINT ["./algod", "-v"]
EOF

for item in ${OS_LIST[*]}
do
    # Install root certs.
    # We use pattern substitution here (like sed).
    # ${parameter/pattern/substitution}
    if [[ $item =~ ubuntu ]]
    then
        WITH_PACMAN=$(echo -e "${TOKENIZED//\{\{PACMAN\}\}/RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y curl ca-certificates --no-install-recommends}")
    else
        # CentOS/Fedora must have the updated root certs already installed.
        WITH_PACMAN=$(echo -e "${TOKENIZED//\{\{PACMAN\}\}/RUN yum install -y curl}")
    fi

    # Finally, designate the OS and send the fully-formed Dockerfile to Docker.
    echo -e "\n$(tput setaf 4)[$0]$(tput sgr0) Testing $item..."
    if ! echo -e "${WITH_PACMAN/\{\{OS\}\}/$item}" | docker build -t "$item" -
    then
        RET_VALUE=1
        FAILED+=("$item")
    fi
done

if [ "${#FAILED[@]}" -gt 0 ]
then
    echo -e "\n$(tput setaf 1)[$0]$(tput sgr0) The following images have problems:"
    for failed in ${FAILED[*]}
    do
        echo " - $failed"
    done
    echo
fi

exit $RET_VALUE


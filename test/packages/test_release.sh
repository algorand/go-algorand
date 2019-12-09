#!/usr/bin/env bash

if [[ ! "$AWS_ACCESS_KEY_ID" || ! "$AWS_SECRET_ACCESS_KEY" ]]
then
    echo -e "$(tput setaf 1)[$0]$(tput sgr0) Missing AWS credentials."
    echo "Export $(tput setaf 2)\$AWS_ACCESS_KEY_ID$(tput sgr0) and $(tput setaf 2)\$AWS_SECRET_ACCESS_KEY$(tput sgr0) before running this script."
    echo "See https://aws.amazon.com/blogs/security/wheres-my-secret-access-key/ to obtain creds."
    exit 1
fi

OS_LIST=(
    centos:7
    centos:8
    fedora:28
    ubuntu:16.04
    ubuntu:18.04
)

# These are default values which can be changed by the CLI args.
BUCKET=algorand-builds
CHANNEL=stable

FAILED=()
RET_VALUE=0

while [ "$1" != "" ]; do
    case "$1" in
        -b)
            shift
            BUCKET="$1"
            ;;
        -c)
            shift
            CHANNEL="$1"
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

ENV AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
ENV AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY

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
    echo -e "$(tput setaf 4)[$0]$(tput sgr0) Testing $item..."
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


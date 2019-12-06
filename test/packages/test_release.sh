#!/usr/bin/env bash

OS_LIST=(
    centos:7
    centos:8
    fedora:28
    ubuntu:16.04
    ubuntu:18.04
)

FAILED=()
RET_VALUE=0

# We'll use this simple tokenized Dockerfile.
# https://serverfault.com/a/72511
IFS='' read -r -d '' TOKENIZED <<"EOF"
FROM {{OS}}
WORKDIR /root/install
{{PACMAN}}

RUN curl --silent -L https://algorand-releases.s3.us-east-1.amazonaws.com/channel/stable/install_stable_linux-amd64_2.0.1.tar.gz | tar xzf - && \
    ./update.sh -c stable -n -p ~/node -d ~/node/data -i && \
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


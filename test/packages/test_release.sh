#!/usr/bin/env bash

BLUE_FG=$(tput setaf 4)
GREEN_FG=$(tput setaf 2)
RED_FG=$(tput setaf 1)
TEAL_FG=$(tput setaf 6)
END_COLOR=$(tput sgr0)

if [[ ! "$AWS_ACCESS_KEY_ID" || ! "$AWS_SECRET_ACCESS_KEY" ]]
then
    echo -e "$RED_FG[$0]$END_COLOR Missing AWS credentials." \
        "\nExport $GREEN_FG\$AWS_ACCESS_KEY_ID$END_COLOR and $GREEN_FG\$AWS_SECRET_ACCESS_KEY$END_COLOR before running this script." \
        "\nSee https://aws.amazon.com/blogs/security/wheres-my-secret-access-key/ to obtain creds."
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

build_images () {
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
    CMD ["/bin/bash"]
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
        echo -e "$BLUE_FG[$0]$END_COLOR Testing $item..."
        if ! echo -e "${WITH_PACMAN/\{\{OS\}\}/$item}" | docker build -t "${item}-test" -
        then
            FAILED+=("$item")
        fi
    done
}

run_images () {
    for item in ${OS_LIST[*]}
    do
        echo "$TEAL_FG[$0]$END_COLOR Running ${item}-test..."
        if ! docker run -t "${item}-test" ./algod -v
        then
            FAILED+=("$item")
        fi
    done
}

check_failures() {
    if [ "${#FAILED[@]}" -gt 0 ]
    then
        echo -e "\n$RED_FG[$0]$END_COLOR The following images could not be $1:"

        for failed in ${FAILED[*]}
        do
            echo " - $failed"
        done

        echo
        exit 1
    fi
}

build_images
check_failures built

run_images
check_failures run

echo "$GREEN_FG[$0]$END_COLOR Tests completed with no failures."
exit 0


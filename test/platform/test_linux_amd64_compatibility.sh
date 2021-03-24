#!/usr/bin/env bash

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
TEAL_FG=$(tput setaf 6 2>/dev/null)
BLUE_FG=$(tput setaf 4 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

OS_LIST=(
    centos:7
    centos:8
    fedora:28
    ubuntu:16.04
    ubuntu:18.04
)

FAILED=()

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
PLATFORM=$($SCRIPTPATH/../../scripts/osarchtype.sh)

if [ "${PLATFORM}" != "linux/amd64" ]
then
    echo "$RED_FG[$0]$END_FG_COLOR The test_linux_amd64_compatibility.sh script is intended to support local execution only on linux/x86-64 machines."
    exit 0
fi

build_images () {
    # We'll use this simple tokenized Dockerfile.
    # https://serverfault.com/a/72511
    IFS='' read -r -d '' TOKENIZED <<EOF
FROM public.ecr.aws/i3h3n7g0/{{OS}}

WORKDIR /root
CMD ["/bin/bash"]
EOF

    for item in ${OS_LIST[*]}
    do
        echo "$BLUE_FG[$0]$END_FG_COLOR Testing $item..."

        echo -e "${TOKENIZED/\{\{OS\}\}/$item}" > Dockerfile
        if ! docker build -t "${item}-test" .
        then
            FAILED+=("$item")
        fi
    done
}

run_images () {
    for item in ${OS_LIST[*]}
    do
        echo "$TEAL_FG[$0]$END_FG_COLOR Running ${item}-test..."
        DOCKER_CONTAINER_ID=$(docker run -dt "${item}-test")
        docker cp $GOPATH/bin/algod ${DOCKER_CONTAINER_ID}:/root/algod
        docker cp $GOPATH/bin/goal ${DOCKER_CONTAINER_ID}:/root/goal
        if ! docker exec ${DOCKER_CONTAINER_ID} /root/algod -v
        then
            FAILED+=("$item")
        elif ! docker exec ${DOCKER_CONTAINER_ID} /root/goal --version
        then
            FAILED+=("$item")
        fi
        docker stop ${DOCKER_CONTAINER_ID}
    done
}

cleanup() {
    rm -f Dockerfile
}

check_failures() {
    if [ "${#FAILED[@]}" -gt 0 ]
    then
        echo -e "\n$RED_FG[$0]$END_FG_COLOR The following images could not be $1:"

        for failed in ${FAILED[*]}
        do
            echo " - $failed"
        done

        echo

        exit 1
    fi
}

build_images
cleanup

check_failures built
echo "$GREEN_FG[$0]$END_FG_COLOR Builds completed with no failures."

run_images
check_failures run
echo "$GREEN_FG[$0]$END_FG_COLOR Runs completed with no failures."

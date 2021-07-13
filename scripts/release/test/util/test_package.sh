#!/usr/bin/env bash
# shellcheck disable=1090

# TODO: use `trap` instead of cleanup function?

set -ex

. "${HOME}"/build_env

OS_LIST=(
    centos:7
    centos:8
    fedora:28
    ubuntu:16.04
    ubuntu:18.04
)

FAILED=()

if [ -z "$BRANCH" ] || [ -z "$CHANNEL" ] || [ -z "$COMMIT_HASH" ] || [ -z "$FULLVERSION" ]
then
    echo "[ERROR] $0 was not provided with BRANCH, CHANNEL, COMMIT_HASH or FULLVERSION!"
    exit 1
fi

build_images () {
    # We'll use this simple tokenized Dockerfile.
    # https://serverfault.com/a/72511
    TOKENIZED=$(echo -e "\
FROM {{OS}}\n\n\
WORKDIR /root\n\
COPY . .\n\
CMD [\"/bin/bash\"]")

    for item in ${OS_LIST[*]}
    do
        # Note: we eventually want to move to storing the Dockerfiles.
        #
        # Use pattern substitution here (like sed).
        # ${parameter/pattern/substitution}
        echo -e "${TOKENIZED/\{\{OS\}\}/$item}" > Dockerfile
        if ! docker build -t "${item}-smoke-test" .
        then
            FAILED+=("$item")
        fi
    done
}

run_images () {
    for item in ${OS_LIST[*]}
    do
        echo "[$0] Running ${item}-test..."
        if ! docker run --rm --name algorand -t "${item}-smoke-test" bash smoke_test.sh -b "$BRANCH" -c "$CHANNEL" -h "$COMMIT_HASH" -r "$FULLVERSION"
        then
            FAILED+=("$item")
        fi
    done
}

cleanup() {
    rm -f Dockerfile
}

check_failures() {
    if [ "${#FAILED[@]}" -gt 0 ]
    then
        echo -e "\n[$0] The following images could not be $1:"

        for failed in ${FAILED[*]}
        do
            echo " - $failed"
        done

        echo

        cleanup
        exit 1
    fi
}

build_images
check_failures built
echo "[$0] All builds completed with no failures."

run_images
check_failures verified
echo "[$0] All runs completed with no failures."

cleanup


#!/usr/bin/env bash

# TODO: use `trap` instead of cleanup function?

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
TEAL_FG=$(tput setaf 6 2>/dev/null)
YELLOW_FG=$(tput setaf 3 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

# TODO: The following error happens on centos:8
#
# Error:
#  Problem: conflicting requests
#    - nothing provides yum-cron needed by algorand-2.0.4-1.x86_64
# (try to add '--skip-broken' to skip uninstallable packages or '--nobest' to use not only best candidate packages)
# smoke_test.sh: line 47: algod: command not found

OS_LIST=(
    centos:7
#    centos:8
    fedora:28
    ubuntu:16.04
    ubuntu:18.04
)

BRANCH=
CHANNEL=stable
HASH=
RELEASE=
FAILED=()

while [ "$1" != "" ]; do
    case "$1" in
        -b)
            shift
            BRANCH="$1"
            ;;
        -c)
            shift
            CHANNEL="$1"
            ;;
        -h)
            shift
            HASH="$1"
            ;;
        -r)
            shift
            RELEASE="$1"
            ;;
        *)
            echo "$RED_FG[$0]$END_FG_COLOR Unknown option $1"
            exit 1
            ;;
    esac
    shift
done

if [ -z "$BRANCH" ] || [ -z "$HASH" ] || [ -z "$RELEASE" ]
then
    echo "$YELLOW_FG[Usage]$END_FG_COLOR $0 -b BRANCH -c CHANNEL -h HASH -r RELEASE"
    exit 1
fi

build_images () {
    # We'll use this simple tokenized Dockerfile.
    # https://serverfault.com/a/72511
    IFS='' read -r -d '' TOKENIZED <<EOF
FROM {{OS}}

WORKDIR /root
COPY pkg/* /root/
COPY smoke_test.sh .
CMD ["/bin/bash"]
EOF

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
        echo "$TEAL_FG[$0]$END_FG_COLOR Running ${item}-test..."
        if ! docker run --rm --name algorand -t "${item}-smoke-test" bash smoke_test.sh -b "$BRANCH" -c "$CHANNEL" -h "$HASH" -r "$RELEASE"
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
        echo -e "\n$RED_FG[$0]$END_FG_COLOR The following images could not be $1:"

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
echo "$GREEN_FG[$0]$END_FG_COLOR All builds completed with no failures."

run_images
check_failures verified
echo "$GREEN_FG[$0]$END_FG_COLOR All runs completed with no failures."

cleanup


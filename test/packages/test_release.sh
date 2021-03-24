#!/usr/bin/env bash

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
TEAL_FG=$(tput setaf 6 2>/dev/null)
BLUE_FG=$(tput setaf 4 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

if [[ ! "$AWS_ACCESS_KEY_ID" || ! "$AWS_SECRET_ACCESS_KEY" ]]
then
    echo -e "$RED_FG[$0]$END_FG_COLOR Missing AWS credentials." \
        "\nExport $GREEN_FG\$AWS_ACCESS_KEY_ID$END_FG_COLOR and $GREEN_FG\$AWS_SECRET_ACCESS_KEY$END_FG_COLOR before running this script." \
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
            echo "$RED_FG[$0]$END_FG_COLOR Unknown option $1"
            exit 1
            ;;
    esac
    shift
done

build_images () {
    # We'll use this simple tokenized Dockerfile.
    # https://serverfault.com/a/72511
    IFS='' read -r -d '' TOKENIZED <<EOF
FROM public.ecr.aws/i3h3n7g0/{{OS}}

ENV AWS_ACCESS_KEY_ID=""
ENV AWS_SECRET_ACCESS_KEY=""

{{PACMAN}}
WORKDIR /root
COPY install.sh .
CMD ["/bin/bash"]
EOF

    for item in ${OS_LIST[*]}
    do
        # Install root certs.
        # We use pattern substitution here (like sed).
        # ${parameter/pattern/substitution}
        if [[ $item =~ ubuntu ]]
        then
            WITH_PACMAN=$(echo -e "${TOKENIZED//\{\{PACMAN\}\}/RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y curl}")
        else
            WITH_PACMAN=$(echo -e "${TOKENIZED//\{\{PACMAN\}\}/RUN yum install -y curl}")
        fi

        echo -e "$BLUE_FG[$0]$END_FG_COLOR Testing $item..."

        # Note that we now create a Dockerfile so the Docker context is properly set.
        # Without this context, Docker tried to COPY from /var/lib/docker/tmp and seemed
        # to do so because the Dockerfile was being automatically generated, i.e.,
        #
        #       echo -e "..." | docker build -t foo -
        #
        # To avoid this, we now redirect the generated Dockerfile to disk, overwriting it
        # with each subsequent iteration (and cleaning it up upon exit).
        #
        # Since we eventually want to move to storing the Dockerfiles, this seems like an
        # acceptable tradeoff.
        echo -e "${WITH_PACMAN/\{\{OS\}\}/$item}" > Dockerfile
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
        if ! docker run --rm --name algorand -e "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID" -e "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY" -t "${item}-test" bash install.sh -b "$BUCKET" -c "$CHANNEL"
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
echo "$GREEN_FG[$0]$END_FG_COLOR Builds completed with no failures."

run_images
check_failures run
echo "$GREEN_FG[$0]$END_FG_COLOR Runs completed with no failures."

cleanup


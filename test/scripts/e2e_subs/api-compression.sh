#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"


my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"

function headers() {
    curl -q -s -D - -o /dev/null -H "Authorization: Bearer $PUB_TOKEN" -H "Accept-Encoding: gzip, deflate, br" "$NET$1"
}

set -e
set -x
set -o pipefail
export SHELLOPTS

OUT=$(headers "/v2/blocks/1")
[[ ${OUT} == *Content-Encoding:\ gzip* ]] || false

date "+${scriptname} OK %Y%m%d_%H%M%S"

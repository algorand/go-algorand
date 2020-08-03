#!/bin/bash
set -e
set -o pipefail

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

if [[ "$#" -ne 1 ]]; then
    echo "Syntax: function-test <path-to-go-algorand-git>"
    exit 1
fi

# list releases
BASE_VERSION="1.0.29"
RELEASE_V1="rel/stable-${BASE_VERSION}"

BASE_VERSION="2.0.6"
RELEASE_V2="v${BASE_VERSION}-stable"

CURRENT_VERSION="2.0.323"
CURRENT="rel/nightly-${CURRENT_VERSION}"
# after build 399 there is no nightly tags
# use the code below to get the latest nightly build version and create a branch
<< COMMENT
COMMIT=$(git log upstream/rel/nightly -1 --format=oneline -- buildnumber.dat | cut -d' ' -f 1-1)
BUILD=$(echo $COMMIT | xargs git show $1 --format=oneline | tail -1 | cut -c 2-)
CURRENT_VERSION="2.0.$BUILD"
git checkout $COMMIT -b rel/nightly-$CURRENT_VERSION
COMMENT
CURRENT_VERSION="2.0.574"
CURRENT="rel/nightly-${CURRENT_VERSION}"

# Parameters
# git revision of the previous release
STABLE=$RELEASE_V2
# git revision of the current (new) release
TESTING=$CURRENT

# Protocol versions
V17="https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0"
V19="https://github.com/algorandfoundation/specs/tree/03ae4eac54f1325377d0a2df62b5ef7cc08c5e18"
V23="https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f"
VFU="future"

BASE_PROTO=$V23
NEXT_PROTO=$VFU

# if testing against stable-1.0.29 release, ensure go-algorand is in $GOPATH/src/github.com/algorand
if [ "${STABLE}" = "${RELEASE_V1}" ]; then
    if [[ $1 != *src/github.com/algorand* ]]; then
        echo "For ${RELEASE_V1} go-algorand must be under go-path" 1>&2
        exit 1
    fi
fi

SRC_DIR=$1

GOPATH=$(go env GOPATH)
GO_BIN="${GOPATH}/bin"

NETWORK_DIR="${SCRIPTPATH}/tests/net"
ASSET_NAME="my_long_asset_name"
ASSET_TOKEN="tatok"


function revision_to_name() {
    local revision=$1
    echo "${revision##*/}"
}

function version_gt() {
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1";
}

function git_cleanup() {
    local current_branch_name=$1
    local target_branch_name=$2

    git reset --hard
    git checkout "$current_branch_name"
    git branch -D "$target_branch_name"
}

# Source patching helpers
# Expects to be called in git repo dir.
# Expects patches at ${SCRIPTPATH}/patch.

# Enable logging in TxPool
function patch_log_txpool_remember() {
    trace_if_needed "patch_log_txpool_remember"
    local revision=$1
    local diff_file="txpool-remember.diff"
    cp -r "${SCRIPTPATH}/patch/${revision}/$diff_file" ./
    git apply "$diff_file"
}

# Change consensus version to future
function patch_change_current_consensus_version() {
    trace_if_needed "patch_change_current_consensus_version"
    local revision=$1
    local diff_file="consensus-version-next-proto.diff"
    cp -r "${SCRIPTPATH}/patch/${revision}/$diff_file" ./
    git apply "$diff_file"
}

# Change consensus version to future
function patch_disable_tx_broadcast() {
    local revision=$1
    trace_if_needed patch_disable_tx_broadcast
    local diff_file="node-no-tx-broadcast.diff"
    cp -r "${SCRIPTPATH}/patch/${revision}/$diff_file" ./
    git apply "$diff_file"
}

function patch_upgrade_path_to_next_proto() {
    local revision=$1
    trace_if_needed patch_upgrade_path_to_next_proto
    local diff_file="upgrade-path-to-next-proto.diff"
    cp -r "${SCRIPTPATH}/patch/${revision}/$diff_file" ./
    git apply "$diff_file"
}

function patch_fast_upgrade_to_next_proto() {
    local revision=$1
    trace_if_needed patch_fast_upgrade_to_next_proto
    local diff_file="fast-upgrade-to-next-proto.diff"
    cp -r "${SCRIPTPATH}/patch/${revision}/$diff_file" ./
    git apply "$diff_file"
}

function patch_agg_remember_and_disable_gossip() {
    local revision=$1
    patch_log_txpool_remember $revision
    patch_disable_tx_broadcast $revision
}

function patch_agg_remember_and_upgrade_path() {
    local revision=$1
    patch_log_txpool_remember $revision
    patch_upgrade_path_to_next_proto $revision
}

function patch_agg_remember_and_disable_gossip_and_upgrade_path() {
    local revision=$1
    patch_log_txpool_remember $revision
    patch_disable_tx_broadcast $revision
    patch_upgrade_path_to_next_proto $revision
}

function patch_agg_remember_and_fast_upgrade_to_next_proto() {
    local revision=$1
    patch_log_txpool_remember $revision
    patch_fast_upgrade_to_next_proto $revision
}

function patch_agg_remember_and_disable_gossip_and_patch_fast_upgrade_to_next_proto() {
    local revision=$1
    patch_log_txpool_remember $revision
    patch_disable_tx_broadcast $revision
    patch_fast_upgrade_to_next_proto $revision
}

function patch_noop() {
    return 0
}

function build_algorand_by_rev() {
    local src_dir=$1
    local revision=$2
    local target_dir=$3
    local patcher=$4

    pushd "$src_dir"

    local target_branch_name=$(revision_to_name $revision)
    local current_branch_name="$(git rev-parse --abbrev-ref HEAD)"

    trap "git_cleanup $current_branch_name $target_branch_name" ERR

    git reset --hard
    git checkout "$revision" -b "$target_branch_name"

    # if testing against stable-1.0.29 release, patch homebrew in dependencies installation
    if [ "$revision" = "${RELEASE_V1}" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            sed -i '.bak' -e 's|caskroom/cask|homebrew/cask|g' ./scripts/configure_dev.sh
            sh ./scripts/configure_dev.sh
            mv ./scripts/configure_dev.sh.bak ./scripts/configure_dev.sh
        fi
    fi

    # Patch sources. The caller provides a correct patcher
    rm -f *.diff
    $patcher "$revision"

    mkdir -p "$target_dir"

    # build
    git diff > "$target_dir/build.log"
    make install >> "$target_dir/build.log" 2>&1

    trap - ERR

    # restore to branch
    git_cleanup $current_branch_name $target_branch_name

    popd

    bin_files=("algod" "carpenter" "goal" "kmd" "msgpacktool" "algokey")
    for bin in "${bin_files[@]}"; do
        cp "${GO_BIN}/${bin}" $target_dir
        if [ $? -ne 0 ]; then exit 1; fi
    done
}

function build_binaries() {
    local src_dir=$1
    local revision=$2
    local bin_dir=$3
    local patcher=$4

    echo "Building $revision with patch(es) $patcher to $bin_dir"

    if [ -z "$patcher" ]; then
        patcher=patch_noop
    fi

    rm -rf $bin_dir && mkdir -p "${bin_dir}"
    build_algorand_by_rev "$src_dir" "$revision" "$bin_dir" "$patcher"
}

function update_node_config() {
    update_json_value "$1" "$2" "$3"
}

function update_json_value() {
    local file=$1
    local key=$2
    local value=$3

    jq --argjson value $value '. + {'$key': $value}' "$file" >"$file.tmp" && mv "$file.tmp" "$file"
}

function delete_from_json() {
    local file=$1
    local key=$2

    jq 'del(.'$key')' "$file" >"$file.tmp" && mv "$file.tmp" "$file"
}

function generate_network() {
    local bin_dir=$1
    local proto=$2

    rm -rf "$NETWORK_DIR"

    "$bin_dir/goal" network create -r "$NETWORK_DIR" -n funtestnet -t "${SCRIPTPATH}/network-config/three-nodes.json"

    update_json_value "$NETWORK_DIR/genesis.json" "proto" '"'$proto'"'
    for node in "$NETWORK_DIR"/*/; do
        update_json_value "$node/genesis.json" "proto"  '"'$proto'"'
    done
}

<< DESCRIPTION
Update all nodes config (config.json) in the network dir
Parameters:
    network_dir - path to network
    key - config option name
    value - config option value
DESCRIPTION
function update_network_node_config() {
    local network_dir=$1
    local key=$2
    local value=$3

    for node in "$network_dir"/*/; do
        update_json_value "$node/config.json" "$key" "$value"
    done
}

<< DESCRIPTION
Update all nodes config (config.json) in the network dir for gossip tests
Parameters:
    network_dir - path to network
DESCRIPTION
function update_network_node_config_for_gossip() {
    update_network_node_config "$network_dir" TxSyncIntervalSeconds 3600
    update_network_node_config "$network_dir" BaseLoggerDebugLevel 5
    update_network_node_config "$network_dir" IncomingConnectionsLimit 10240
    update_network_node_config "$network_dir" Version 6
}

<< DESCRIPTION
Update all nodes config (config.json) in the network dir for txsync tests
Parameters:
    network_dir - path to network
DESCRIPTION
function update_network_node_config_for_txsync() {
    update_network_node_config "$network_dir" TxSyncIntervalSeconds 1
    update_network_node_config "$network_dir" BaseLoggerDebugLevel 5
    update_network_node_config "$network_dir" IncomingConnectionsLimit 10240
    update_network_node_config "$network_dir" Version 6
}

function fresh_temp_net() {
    local target_dir=$1

    rm -rf $target_dir
    cp -r "$NETWORK_DIR" $target_dir
}

function remove_temp_net() {
    local target_dir=$1
    rm -rf "$target_dir"
}

function network_cleanup() {
    local bin_dir=$1
    local network_dir=$2

    network_stop "$bin_dir" "$network_dir"
    remove_temp_net  "$network_dir"
}

# Starts nodes specified by nodes map.
# Returns sender's bin dir (by echoing)
function network_start() {
    local nodes=( $1 )
    local network_dir=$2
    local sender_name=$3

    local bin_dir
    for item in "${nodes[@]}"; do
        local node_name="${item%%:*}"
        local node_bin_dir="${item##*:}"

        # set bin dir to some value to have some default
        if [ -z "$bin_dir" ]; then
            bin_dir="$node_bin_dir"
        fi

        # then set to sender's path
        if [ "$node_name" == "$sender_name" ]; then
            bin_dir="$node_bin_dir"
        fi

        "$node_bin_dir/goal" network start -r "$network_dir" --node "$network_dir/$node_name" 2>&1 1>/dev/null
        local retval="$?"
        if [ "$retval" -ne "0" ]; then
            "$node_bin_dir/goal" network stop -r "$network_dir"
            return 1
        fi
    done

    if [ -z "$bin_dir" ]; then
        echo "bin dir not found for $sender_name" >&2
        return 1
    fi

    echo "$bin_dir"
    return 0
}

function network_stop() {
    local bin_dir=$1
    local network_dir=$2

    "$bin_dir/goal" network stop -r "$network_dir"
}

function all_nodes_alive() {
    local nodes=( $1 )
    local network_dir=$2

    local failed
    for item in "${nodes[@]}"; do
        local node_name="${item%%:*}"
        local node_bin_dir="${item##*:}"

        local output=$("$node_bin_dir/goal" node status -d "$network_dir/$node_name" | grep 'Last committed block')
        if [ -n "$output" ]; then
            trace_if_needed "Node $node_name looks good"
        else
            trace_if_needed "Node $node_name looks dead"
            failed="1"
            tail -20 "$network_dir/$node_name/node.log"
            break
        fi
    done

    local retval=0
    if [ -n "$failed" ]; then
        retval=1
    fi

    return $retval
}

function extract_from_emit_info() {
    local emit_info=( $1 )
    local prop=$2
    local expected

    for item in "${emit_info[@]}"; do
        local key="${item%%:*}"
        local value="${item##*:}"
        local node_name="${value%%@*}"
        local count="${value##*@}"
        if [ "$key" == "$prop" ]; then
            expected="$node_name"
        fi
    done

    if [ -z "$expected" ]; then
        echo "prop $prop not found in ${emit_info[@]}" >&2
        return 1
    fi

    echo "$expected"
}

function sender_name_from_emit_info() {
    local emit_info=( $1 )
    extract_from_emit_info "$(echo ${emit_info[@]})" "snd"
    return $?
}

function proposer_name_from_emit_info() {
    local emit_info=( $1 )
    extract_from_emit_info "$(echo ${emit_info[@]})" "prp"
    return $?
}

# Execute a command and wait for specific value
# Need to provide regex to capture the value and max timeout
function wait_for_value() {
    local cmd=$1
    local value=$2
    local regex=$3
    local timeout=$4

    local sleep_duration=5
    local time_spent=0
    local actual_value=""
    while [ "$time_spent" -le "$timeout" ] && [ "$actual_value" != "$value" ]; do
        local output=$($cmd)
        [[ $output =~ $regex ]]
        actual_value=${BASH_REMATCH[1]}
        sleep $sleep_duration
        ((time_spent=time_spent+$sleep_duration))
    done

    echo $actual_value
}

function trace_if_needed() {
    local comment=$1
    local output=$2
    local ret_code=$3

    if [ -z "$ret_code" ]; then
        ret_code=0
    fi

    if [ -n "$ALGODEBUG" ] || [ "$ret_code" -ne "0" ]; then
        echo "$comment"
        if [ -n "$output" ]; then
            echo "Result: $output"
        fi
        if [ "$ret_code" -ne "0" ]; then
            echo "Status: $ret_code"
        fi
    fi
}

function log_error() {
    local message=$1
    echo "$message" 1>&2
}

<< DESCRIPTION
Transaction submission well before upgrade with Gossip disabled (TxSync is on).
See submit_and_check for details.
DESCRIPTION
function test_pre_upgrade_txsync() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3
    local proto=$4

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"

    update_network_node_config_for_txsync "$network_dir"

    local sender_name=$(sender_name_from_emit_info "$(echo ${emit_info[@]})")
    local bin_dir=$(network_start "$(echo ${nodes[@]})" "$network_dir" "$sender_name")
    trace_if_needed "Network started $network_dir"

    trap "network_cleanup $bin_dir $network_dir" ERR

    submit_and_check "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir" "$proto"
    local retval="$?"
    local tx_sync_count="${__submit_and_check}"

    trap - ERR
    network_cleanup "$bin_dir" "$network_dir"

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -eq "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected non-zero"
        retval=1
    fi

    return $retval
}

<< DESCRIPTION
Transaction submission well before upgrade with TxSync disabled (Gossip is on).
See submit_and_check for details.
DESCRIPTION
function test_pre_upgrade_gossip() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3
    local proto=$4

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"

    update_network_node_config_for_gossip "$network_dir"

    local sender_name=$(sender_name_from_emit_info "$(echo ${emit_info[@]})")
    local bin_dir=$(network_start "$(echo ${nodes[@]})" "$network_dir" "$sender_name")
    trace_if_needed "Network started $network_dir"

    trap "network_cleanup $bin_dir $network_dir" ERR

    submit_and_check "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir" "$proto"
    local retval="$?"
    local tx_sync_count="${__submit_and_check}"

    trap - ERR
    network_cleanup "$bin_dir" "$network_dir"

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -ne "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected zero"
        retval=1
    fi

    return $retval
}

<< DESCRIPTION
Transaction submission after upgrade proposal with TxSync disabled (Gossip is on).
See txn_submit_after_proposal for details.
DESCRIPTION
function test_after_proposal_gossip() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"
    update_network_node_config_for_gossip "$network_dir"

    txn_submit_after_proposal "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir"
    local retval="$?"
    local tx_sync_count="${__txn_submit_after_proposal}"

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -ne "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected zero"
        retval=1
    fi

    return $retval
}

<< DESCRIPTION
Transaction submission after upgrade proposal with Gossip disabled (TxSync is on).
See txn_submit_after_proposal for details.
DESCRIPTION
function test_after_proposal_txsync() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"
    update_network_node_config_for_txsync "$network_dir"

    txn_submit_after_proposal "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir"
    local retval="$?"
    local tx_sync_count="${__txn_submit_after_proposal}"

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -eq "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected non-zero"
        retval=1
    fi

    return $retval
}

__txn_submit_after_proposal="0"

<< DESCRIPTION
Transaction submission after upgrade proposal
Preconditions:
1. Network provisioned, config updated, but not started
Parameters:
    nodes - an array (encoded map) of node names and binary paths
    emit_info - an array (encoded map) with sender, receiver and update initiator nodes names and tx count expectations
    network_dir - a path to the directory with running network
    tx_dir - a path to the directory with pre-generated transactions to submit
Return:
    0 on success
    __txn_submit_after_proposal is set to amount of txsync requests found in the log

Idea:
1. Wait for the upgrade proposal is assigned to a block
2. Submit transactions as usual
DESCRIPTION
function txn_submit_after_proposal() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local network_dir=$3
    local tx_dir=$4

    local sender_name=$(sender_name_from_emit_info "$(echo ${emit_info[@]})")
    local proposer_name=$(proposer_name_from_emit_info "$(echo ${emit_info[@]})")
    local bin_dir=$(network_start "$(echo ${nodes[@]})" "$network_dir" "$sender_name")
    trace_if_needed "Network started $network_dir"

    trap "network_cleanup $bin_dir $network_dir" ERR

    local cmd="$bin_dir/goal node status -d $network_dir/$proposer_name"
    local regex='Next consensus protocol: ([a-zA-Z0-9:/.]+)'
    local expected="$NEXT_PROTO"
    local timeout="30"
    local actual=$(wait_for_value "$cmd" "$expected" "$regex" "$timeout")
    if [ -z "$actual" ]; then
        log_error "Node $proposer_name has not accepted the upgrade in $timeout seconds"
        false  # abort and force trap
    fi

    tx_dir="$tx_dir/$sender_name"
    submit_and_check "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir"
    local retval="$?"
    __txn_submit_after_proposal="${__submit_and_check}"

    trap - ERR
    network_cleanup "$bin_dir" "$network_dir"

    return $retval
}

<< DESCRIPTION
Transaction submission after upgrade with TxSync disabled (Gossip is on).
See txn_submit_after_upgrade for details.
DESCRIPTION
function test_upgrade_applied_gossip() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"

    update_network_node_config_for_gossip "$network_dir"
    txn_submit_after_upgrade "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir"
    local retval="$?"
    local tx_sync_count=${__txn_submit_after_upgrade}

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -ne "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected zero"
        retval=1
    fi

    return $retval
}

<< DESCRIPTION
Transaction submission after upgrade with Gossip disabled (TxSync is on).
See txn_submit_after_upgrade for details.
DESCRIPTION
function test_upgrade_applied_txsync() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"

    update_network_node_config_for_txsync "$network_dir"
    txn_submit_after_upgrade "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir"
    local retval="$?"
    local tx_sync_count=${__txn_submit_after_upgrade}

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -eq "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected non-zero"
        retval=1
    fi

    return $retval
}

__txn_submit_after_upgrade="0"

<< DESCRIPTION
Transaction submission after upgrade
Preconditions:
1. Network provisioned, config updated, but not started
Parameters:
    nodes - an array (encoded map) of node names and binary paths
    emit_info - an array (encoded map) with sender, receiver and update initiator nodes names and tx count expectations
    network_dir - a path to the directory with running network
    tx_dir - a path to the directory with pre-generated transactions to submit
Return:
    0 on success
    __txn_submit_after_upgrade is set to amount of txsync requests found in the log

Idea:
1. Wait for the upgrade
2. Submit transactions as usual
DESCRIPTION
function txn_submit_after_upgrade() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local network_dir=$3
    local tx_dir=$4

    local sender_name=$(sender_name_from_emit_info "$(echo ${emit_info[@]})")
    local bin_dir=$(network_start "$(echo ${nodes[@]})" "$network_dir" "$sender_name")
    trace_if_needed "Network started $network_dir"

    trap "network_cleanup $bin_dir $network_dir" ERR

    local cmd="$bin_dir/goal node status -d $network_dir/$sender_name"
    local regex='Last consensus protocol: ([a-zA-Z0-9:/.]+)'
    local expected="$NEXT_PROTO"
    local timeout="60"
    local actual=$(wait_for_value "$cmd" "$expected" "$regex" "$timeout")
    if [ -z "$actual" ]; then
        log_error "Node $sender_name has not upgraded in $timeout seconds"
        false  # abort and force trap
    fi

    local proto="$actual"
    tx_dir="$tx_dir/$sender_name"
    submit_and_check "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir" "$proto"
    local retval="$?"
    __txn_submit_after_upgrade="${__submit_and_check}"

    # ensure all nodes alive (no crashes)
    all_nodes_alive "$(echo ${nodes[@]})" "$network_dir"

    trap - ERR
    network_cleanup "$bin_dir" "$network_dir"

    return $retval
}

<< DESCRIPTION
Transaction submission around the upgrade round with TxSync disabled (Gossip is on).
See txn_submit_at_round for details.
DESCRIPTION
function test_at_upgrade_gossip() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3
    local upgrade_round=$4
    local submit_round=$5

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"
    update_network_node_config_for_gossip "$network_dir"

    txn_submit_at_round "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir" "$upgrade_round" "$submit_round"
    local retval="$?"
    local tx_sync_count=${__txn_submit_at_round}

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -ne "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected zero"
        retval=1
    fi

    return $retval
}

<< DESCRIPTION
Transaction submission around the upgrade round with Gossip disabled (TxSync is on).
See txn_submit_at_round for details.
DESCRIPTION
function test_at_upgrade_txsync {
    local nodes=( $1 )
    local emit_info=( $2 )
    local tx_dir=$3
    local upgrade_round=$4
    local submit_round=$5

    local test_name="${FUNCNAME[0]}"
    local base_dir="${SCRIPTPATH}/tests/${test_name}"
    local network_dir="${base_dir}/net"
    mkdir -p $base_dir

    fresh_temp_net "$network_dir"
    update_network_node_config_for_txsync "$network_dir"

    txn_submit_at_round "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir" "$upgrade_round" "$submit_round"
    local retval="$?"
    local tx_sync_count=${__txn_submit_at_round}

    if [ "$retval" -ne "0" ] || [ "$tx_sync_count" -eq "0" ]; then
        log_error "$test_name failed: txsync count is $tx_sync_count but expected non-zero"
        retval=1
    fi

    return $retval
}

__txn_submit_at_round="0"

<< DESCRIPTION
Transaction submission around the upgrade round with TxSync disabled (Gossip is on).
Preconditions:
1. Network provisioned, config updated, but not started
Parameters:
    nodes - an array (encoded map) of node names and binary paths
    emit_info - an array (encoded map) with sender, receiver and update initiator nodes names and tx count expectations
    network_dir - a path to the directory with running network
    tx_dir - a path to the directory with pre-generated transactions to submit
    upgrade_round - a round number when upgrade is expected to happen
    submit_round - a round number for transaction submission
Return:
    0 on success
    __txn_submit_at_round is set to amount of txsync requests found in the log

Idea:
1. Wait for the upgrade approval
2. Ensure that last round is less then upgrade_round and submit_round so there is a time window to submit transactions
3. Wait for end of submit_round
4. Submit transactions as usual

The function is designed to validate two scenarios:
 - submitting at upgrade round - set upgrade_round=5 and submit_round=5
 - submitting at upgrade+1 round - set upgrade_round=5 and submit_round=6s
DESCRIPTION
function txn_submit_at_round() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local network_dir=$3
    local tx_dir=$4
    local upgrade_round=$5
    local submit_round=$6

    local sender_name=$(sender_name_from_emit_info "$(echo ${emit_info[@]})")
    local bin_dir=$(network_start "$(echo ${nodes[@]})" "$network_dir" "$sender_name")
    trace_if_needed "Network started $network_dir"

    trap "network_cleanup $bin_dir $network_dir" ERR

    local token=$(cat "$network_dir/$sender_name/algod.token")
    local node_address=$(cat "$network_dir/$sender_name/algod.net")
    local info_url="http://$node_address/v1/status"
    local next_proto="some_random_value_123"
    local next_proto_round="0"
    local last_round="0"
    local timeout="60"
    local sleep_duration="0.01"
    local time_spent="0"
    local time_spent_act="0"

    trace_if_needed "Waiting for upgrade... expected at $upgrade_round, will be submitting at the beginning of $submit_round"
    while [ "$time_spent" -le "$timeout" ] && [ "$next_proto" != "$NEXT_PROTO" ]; do
        local output=$(curl -s -H "X-ALGO-API-Token: $token" $info_url)
        next_proto=$(echo $output | jq -r '.nextConsensusVersion')
        next_proto_round=$(echo $output | jq -r '.nextConsensusVersionRound')
        last_round=$(echo $output | jq -r '.lastRound')

        sleep $sleep_duration
        time_spent_act=$(echo $time_spent_act + $sleep_duration | bc |  awk '{printf "%.1f\n", $0}')
        time_spent=${time_spent_act%.*}
    done

    if [ "$next_proto_round" -ne "$upgrade_round" ]; then
        log_error "Upgrade round is expected to be $upgrade_round but actual is $next_proto_round"
        return 1
    fi

    local current_round="0"
    ((current_round=last_round+1))
    if [ "$current_round" -gt "$submit_round" ]; then
        log_error "Last round $last_round (current $current_round) is too high, needs to be below submit round $submit_round"
        return 1
    fi

    local pre_submit_round="0"
    ((pre_submit_round=submit_round-1))
    local time_since_last_round="0"
    local round_duration="4000000000"  # nanoseconds
    trace_if_needed "Catching current round == $pre_submit_round and time since < $round_duration ns"
    while [ "$time_spent" -le "$timeout" ] && \
        ( \
            [ "$current_round" -lt "$pre_submit_round" ] || \
            [ "$current_round" -eq "$pre_submit_round" ] && [ "$time_since_last_round" -le "$round_duration" ] \
        )
    do
        local output=$(curl -s -H "X-ALGO-API-Token: $token" $info_url)
        time_since_last_round=$(echo $output | jq -r '.timeSinceLastRound')
        last_round=$(echo $output | jq -r '.lastRound')
        ((current_round=last_round+1))

        sleep $sleep_duration
        time_spent_act=$(echo $time_spent_act + $sleep_duration | bc |  awk '{printf "%.1f\n", $0}')
        time_spent=${time_spent_act%.*}
    done

    if [ "$time_spent" -gt "$timeout" ]; then
        log_error "Failed to current ($current_round) <= pre ($pre_submit_round) and $time_since_last_round < $round_duration"
        return 1
    fi

    local output=$(curl -s -H "X-ALGO-API-Token: $token" $info_url)
    last_round=$(echo $output | jq -r '.lastRound')
    time_since_last_round=$(echo $output | jq -r '.timeSinceLastRound')

    trace_if_needed "Sending at last round $last_round and time since $time_since_last_round"

    submit_and_check "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$tx_dir" "$NEXT_PROTO"
    local retval="$?"
    __txn_submit_at_round=${__submit_and_check}

    trap - ERR
    network_cleanup "$bin_dir" "$network_dir"

    return $retval
}


__submit_and_check=0

<< DESCRIPTION
Submit all the transactions from the directory.
It checks sender and receiver node logs (see emit_info) and count transactions
Preconditions:
    1. Binaries are instrumented
    2. Network is running
Parameters:
    nodes - an array (encoded map) of node names and binary paths
    emit_info - an array (encoded map) with sender, receiver and update initiator nodes names and tx count expectations
    network_dir - a path to the directory with running network
    tx_dir - a path to the directory with pre-generated transactions to submit
    proto - a protocol version is being test. If it is '$NEXT_PROTO' then submit new transaction
Returns:
    0 on success
    __submit_and_check is set to amount of txsync requests found in the log

The function is designed to count TX remember calls (instrumented logging) and TxSync calls.
DESCRIPTION
function submit_and_check() {

    local nodes=( $1 )
    local emit_info=( $2 )
    local network_dir=$3
    local tx_dir=$4
    local proto=$5

    local sender_name
    local receiver_name
    local sender_count
    local receiver_count

    for item in "${emit_info[@]}"; do
        local key="${item%%:*}"
        local value="${item##*:}"
        local node_name="${value%%@*}"
        local count="${value##*@}"

        if [ "$key" == "snd" ]; then
            sender_name="$node_name"
            sender_count="$count"

        fi
        if [ "$key" == "rcv" ]; then
            receiver_name="$node_name"
            receiver_count="$count"
        fi
    done

    if [ -z "$sender_name" ] || [ -z "$receiver_name" ]; then
        echo "Error: snd or rcv not set in ${emit_info[@]}"
        return 1
    fi

    if [ -z "$sender_count" ] || [ -z "$receiver_count" ]; then
        echo "Error: expected count not set in ${emit_info[@]}"
        return 1
    fi

    "$bin_dir/goal" node wait -w 30 -d "$network_dir/$sender_name"

    local txids=()
    for f in "$tx_dir"/*.stx; do
        # Send and parse tx ID from 'Raw transaction ID 5ORN5BDZX2WPT6VGISKXZC4UMW6WWS7ZTCPDAW33VTKDAPOHZEVQ issued'
        local output=$("$bin_dir/goal" clerk rawsend -f $f -N -d "$network_dir/$sender_name")
        local regex='Raw transaction ID ([A-Z0-9=]{52,52})'
        [[ $output =~ $regex ]]
        local txid=${BASH_REMATCH[1]}
        # local txid=$(echo $output | head -1 | awk '{ print $4 }')
        if [ -z "$txid" ]; then
            log_error "$output"
        else
            txids+=($txid)
        fi
    done

    # check_new_transactions "$(echo ${nodes[@]})" "$(echo ${emit_info[@]})" "$network_dir" "$proto"
    # local new_txids=( ${__check_new_transactions[@]} )
    # local txids=( "${txids[@]}" "${new_txids[@]}" )

    # wait to let all tx get propagated
    "$bin_dir/goal" node wait -w 30 -d "$network_dir/$sender_name"

    local node1=0
    local node2=0
    local txsync_request=$(grep "http sync got" "$network_dir/$receiver_name/node.log" | grep -c '^')
    for txid in "${txids[@]}"; do
        trace_if_needed "Looking for tx ID $txid"

        local node1_lines=$(grep "Transaction remembered $txid" "$network_dir/$sender_name/node.log" | grep -c '^')
        local node2_lines=$(grep "Transaction remembered $txid" "$network_dir/$receiver_name/node.log" | grep -c '^')

        ((node1=node1+node1_lines))
        ((node2=node2+node2_lines))
    done

    trace_if_needed "Sender ($sender_name): found $node1, expected $sender_count"
    trace_if_needed "Receiver ($receiver_name): found $node2, expected $receiver_count"

    local retval=0
    if [ "$sender_count" -ne "$node1" ] || [ "$receiver_count" -ne "$node2" ]; then
        echo "${FUNCNAME[0]} error: $sender_count != $node1 OR $receiver_count != $node2"
        retval=1
    fi

    # return two values - one in the global var and the second as a regular ret code
    __submit_and_check=$txsync_request
    return $retval
}

# return random value from [1000, 1500)
function get_random_fee() {
    echo "$((RANDOM % 500 + 1000))"
}

<< DESCRIPTION
Pre-generate transactions using specified binaries into a dir provided.
Parameters:
    bin_dir - a path to algod/goal binaries
    sender_name - sender's node name
    receiver_name - receiver's node name
    tx_dir - a path to the directory where store transactions to
    proto - a protocol version is being used. "$NEXT_PROTO" triggers waiting for an upgrade
    valid_round - firstvalid and lastvalid set to this value
DESCRIPTION
function generate_transactions() {
    local bin_dir=$1
    local sender_name=$2
    local receiver_name=$3
    local tx_dir=$4
    local proto=$5
    local valid_round=$6

    local network_dir="${tx_dir}/net"
    mkdir -p "$tx_dir"

    local alogd_version="$("$bin_dir/algod" -v | sed -n 2p | cut -f 1 -d ' ' | cut -f 1-3 -d .)"

    fresh_temp_net "$network_dir"

    trap "network_cleanup $bin_dir $network_dir" ERR

    # echo "To stop type"
    # echo "$bin_dir/goal" network stop -r "$network_dir"
    # echo "$bin_dir/goal" network delete -r "$network_dir"

    "$bin_dir/goal" network start -r "$network_dir"
    "$bin_dir/goal" node wait -w 60 -d "$network_dir/Primary"

    if [ "$proto" == "$NEXT_PROTO" ]; then
        local cmd="$bin_dir/goal node status -d $network_dir/$sender_name"
        local regex='Last consensus protocol: ([a-zA-Z0-9:/.]+)'
        local expected="$NEXT_PROTO"
        local timeout="60"
        local actual=$(wait_for_value "$cmd" "$expected" "$regex" "$timeout")
        if [ -z "$actual" ]; then
            log_error "Node $sender_name has not upgraded in $timeout seconds"
            false  # abort and force trap
        fi
    fi

    local firstvalid="1"
    local lastvalid="1000"
    local validrounds="$lastvalid"
    if [ -n "$valid_round" ]; then
        firstvalid="$valid_round"
        lastvalid="$valid_round"
        validrounds="1"  # well, it should be 0 but goal interprets 0 as max validity=1000
    fi

    local src_addr=$("$bin_dir/goal" account list -d "$network_dir/$sender_name" | head -1 | awk '{ print $2 }')
    local dst_addr=$("$bin_dir/goal" account list -d "$network_dir/$receiver_name" | head -1 | awk '{ print $2 }')

    trace_if_needed "Creating payset tx"
    local fee=$(get_random_fee)
    "$bin_dir/goal" clerk send --fee $fee -a 1000 -f $src_addr -t $dst_addr --firstvalid "$firstvalid" --lastvalid "$lastvalid" -o "$tx_dir/payset.tx" -d "$network_dir/$sender_name"
    "$bin_dir/goal" clerk sign -i "$tx_dir/payset.tx" -o "$tx_dir/payset.stx" -d "$network_dir/$sender_name"

    trace_if_needed "Creating keyreg tx"
    fee=$(get_random_fee)
    "$bin_dir/goal" account changeonlinestatus --fee $fee --address $src_addr -o -t "$tx_dir/keyreg.tx" --firstRound "$firstvalid" --validRounds "$validrounds" -d "$network_dir/$sender_name"
    "$bin_dir/goal" clerk sign -i "$tx_dir/keyreg.tx" -o "$tx_dir/keyreg.stx" -d "$network_dir/$sender_name"

    trace_if_needed "Creating logic sig payset tx"
    fee=$(get_random_fee)
    echo "int 1" > "$tx_dir/int1.teal"
    "$bin_dir/goal" clerk compile "$tx_dir/int1.teal" -s -a $src_addr -o "$tx_dir/int1.lsig" -d "$network_dir/$sender_name"
    "$bin_dir/goal" clerk send --fee $fee -a 1000 -f $src_addr -t $dst_addr --firstvalid "$firstvalid" --lastvalid "$lastvalid" -o "$tx_dir/payset-teal.tx" -d "$network_dir/$sender_name"
    "$bin_dir/goal" clerk sign -P "$proto" -L "$tx_dir/int1.lsig" -i "$tx_dir/payset-teal.tx" -o "$tx_dir/payset-teal.stx" -d "$network_dir/$sender_name"

    trace_if_needed "Creating payset group tx"
    fee=$(get_random_fee)
    "$bin_dir/goal" clerk send --fee $fee -a 1000 -f $src_addr -t $dst_addr --firstvalid "$firstvalid" --lastvalid "$lastvalid" -o "$tx_dir/payset-again.tx" -d "$network_dir/$sender_name"
    cat "$tx_dir/payset.tx" "$tx_dir/payset-again.tx" > "$tx_dir/payset-concat.tx"
    "$bin_dir/goal" clerk group -i "$tx_dir/payset-concat.tx" -o "$tx_dir/payset-group.tx"
    "$bin_dir/goal" clerk sign -P "$proto" -i "$tx_dir/payset-group.tx" -o "$tx_dir/payset-group.stx" -d "$network_dir/$sender_name"

    trace_if_needed "Creating asset create tx"
    fee=$(get_random_fee)
    "$bin_dir/goal" asset create --fee $fee --creator $src_addr --name $ASSET_NAME --total 100 --unitname $ASSET_TOKEN --firstvalid "$firstvalid" --validrounds "$validrounds" -o "$tx_dir/asset-create.tx" -d "$network_dir/$sender_name"
    "$bin_dir/goal" clerk sign -P "$proto" -i "$tx_dir/asset-create.tx" -o "$tx_dir/asset-create.stx" -d "$network_dir/$sender_name"

    if version_gt "$alogd_version" "$BASE_VERSION" ; then
        if [ "$proto" == "$NEXT_PROTO" ]; then
            trace_if_needed "Creating app create tx"
            printf "#pragma version 2\nint 1" > "$tx_dir/int1.teal"
            "$bin_dir/goal" app create --creator $src_addr --approval-prog "$tx_dir/int1.teal" --clear-prog "$tx_dir/int1.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --firstvalid "$firstvalid" --lastvalid "$lastvalid" -o "$tx_dir/app-create.tx" -d "$network_dir/$sender_name"
            "$bin_dir/goal" clerk sign -P "$proto" -i "$tx_dir/app-create.tx" -o "$tx_dir/app-create.stx" -d "$network_dir/$sender_name"

            local rekey_src_addr=$("$bin_dir/goal" account list -d "$network_dir/$sender_name" | tail -1 | awk '{ print $2 }')
            local rekey_to_addr=$src_addr

            trace_if_needed "Creating rekey txn"
            "$bin_dir/goal" clerk send --fee $fee -a 1000 -f $rekey_src_addr -t $dst_addr --firstvalid "$firstvalid" --lastvalid "$lastvalid" --rekey-to $rekey_to_addr -o "$tx_dir/rekey-payset-1.tx" -d "$network_dir/$sender_name"
            "$bin_dir/goal" clerk sign -P "$proto" -i "$tx_dir/rekey-payset-1.tx" -o "$tx_dir/rekey-payset-1.stx" -d "$network_dir/$sender_name"

            trace_if_needed "Creating rekeyed txn that also rekeys it back"
            "$bin_dir/goal" clerk send --fee $fee -a 1000 -f $rekey_src_addr -t $dst_addr --firstvalid "$firstvalid" --lastvalid "$lastvalid" --rekey-to $rekey_src_addr -o "$tx_dir/rekey-payset-2.tx" -d "$network_dir/$sender_name"
            "$bin_dir/goal" clerk sign -S $rekey_to_addr -P "$proto" -i "$tx_dir/rekey-payset-2.tx" -o "$tx_dir/rekey-payset-2.stx" -d "$network_dir/$sender_name"
        fi
    fi

    trap - ERR
    network_cleanup "$bin_dir" "$network_dir"
}

__check_new_transactions=()

<< DESCRIPTION
Submits transactions of new type - that are only valid after upgrade
Parameters:
    nodes - an array (encoded map) of node names and binary paths
    emit_info - an array (encoded map) with sender, receiver and update initiator nodes names and tx count expectations
    network_dir - a path to the directory with running network
    proto - a protocol version is being test. If it is '$NEXT_PROTO' then submit new transaction
Returns:
    0 on success
    __check_new_transactions contains an array of submitted tx ids

DESCRIPTION
function check_new_transactions() {
    local nodes=( $1 )
    local emit_info=( $2 )
    local network_dir=$3
    local proto=$4

    if [ "$proto" != "$NEXT_PROTO" ]; then
        return
    fi

    local sender_name
    local receiver_name

    for item in "${emit_info[@]}"; do
        local key="${item%%:*}"
        local value="${item##*:}"
        local node_name="${value%%@*}"
        local count="${value##*@}"

        if [ "$key" == "snd" ]; then
            sender_name="$node_name"

        fi
        if [ "$key" == "rcv" ]; then
            receiver_name="$node_name"
        fi
    done

    local bin_dir
    local primary_bin_dir
    for item in "${nodes[@]}"; do
        local node_name="${item%%:*}"
        local node_bin_dir="${item##*:}"
        if [ "$node_name" == "$sender_name" ]; then
            bin_dir="$node_bin_dir"
        fi
        if [ "$node_name" == "Primary" ]; then
            primary_bin_dir="$node_bin_dir"
        fi
    done

    local alogd_version="$("$bin_dir/algod" -v | sed -n 2p | cut -f 1 -d ' ' | cut -f 1-3 -d .)"

    local txids=()
    if version_gt "$alogd_version" "$BASE_VERSION"; then
        local src_addr=$("$bin_dir/goal" account list -d "$network_dir/$sender_name" | head -1 | awk '{ print $2 }')
        local dst_addr=$("$bin_dir/goal" account list -d "$network_dir/$receiver_name" | head -1 | awk '{ print $2 }')

        "$bin_dir/goal" node wait -w 30 -d "$network_dir/$sender_name"
        "$bin_dir/goal" node wait -w 30 -d "$network_dir/$receiver_name"

        local rekey_src_addr=$("$bin_dir/goal" account list -d "$network_dir/$sender_name" | tail -1 | awk '{ print $2 }')
        local rekey_to_addr=$src_addr

        local regex='txid ([A-Z0-9=]{52,52})'
        # Issued transaction from account AKMIEYU64TDLTDER6LTGPRMAXUMDQQFKVMH5QTYECBWIXT7V4KZ6GFTI2I, txid ITJPKM7JW57HTJUWIZH3VDUYJ6VVAHPASMKGKIFXZT2P6M3IEKAA (fee 1000)

        printf "#pragma version 2\nint 1" > "$tx_dir/int1.teal"
        trace_if_needed "Sending app create tx"
        local output=$("$bin_dir/goal" app create --creator $src_addr --approval-prog "$tx_dir/int1.teal" --clear-prog "$tx_dir/int1.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --firstvalid 1 --lastvalid 1000 -d "$network_dir/$sender_name")
        trace_if_needed "Sent app create tx" "$output" $?

        [[ $output =~ $regex ]]
        local txid=${BASH_REMATCH[1]}
        trace_if_needed $txid
        txids+=($txid)

        trace_if_needed "Sending rekey txn"
        local output=$("$bin_dir/goal" clerk send --fee 1000 -a 1000 -f $rekey_src_addr -t $dst_addr --firstvalid 1 --lastvalid 1000 --rekey-to $rekey_to_addr -d "$network_dir/$sender_name")
        trace_if_needed "Sent rekey tx" "$output" $?

        [[ $output =~ $regex ]]
        local txid=${BASH_REMATCH[1]}
        trace_if_needed $txid
        txids+=($txid)

        trace_if_needed "Sending rekeyed txn"
        mkdir -p "$tx_dir/tmp"
        "$bin_dir/goal" clerk send --fee 1000 -a 1000 -f $rekey_src_addr -t $dst_addr --firstvalid 1 --lastvalid 1000 --rekey-to $rekey_src_addr -o "$tx_dir/tmp/rekeyed-send-payset.tx" -d "$network_dir/$sender_name"
        "$bin_dir/goal" clerk sign -S $rekey_to_addr -P "$proto" -i "$tx_dir/tmp/rekeyed-send-payset.tx" -o "$tx_dir/tmp/rekeyed-send-payset.stx" -d "$network_dir/$sender_name"
        local output=$("$bin_dir/goal" clerk rawsend -f "$tx_dir/tmp/rekeyed-send-payset.stx") -d "$network_dir/$sender_name"

        [[ $output =~ $regex ]]
        local txid=${BASH_REMATCH[1]}
        trace_if_needed $txid
        txids+=($txid)
    fi

    __check_new_transactions=( ${txids[@]} )
}

TESTING_BIN_DIR="${SCRIPTPATH}/tests/$(revision_to_name $TESTING)/bin"
STABLE_BIN_DIR="${SCRIPTPATH}/tests/$(revision_to_name $STABLE)/bin"
VANILLA_TESTING_BIN_DIR="${SCRIPTPATH}/tests/$(revision_to_name $TESTING)-vanilla/bin"
VANILLA_STABLE_BIN_DIR="${SCRIPTPATH}/tests/$(revision_to_name $STABLE)-vanilla/bin"

UPGRADE_ROUND="5"   # matches to the code patch
((UPGRADE_ROUND_NEXT=UPGRADE_ROUND+1))

TX_BASE_DIR="${SCRIPTPATH}/tests/tx"
mkdir -p $TX_BASE_DIR

if [ ! -d "$VANILLA_TESTING_BIN_DIR" ]; then
    build_binaries "$SRC_DIR" "$TESTING" "$VANILLA_TESTING_BIN_DIR"
fi
if [ ! -d "$VANILLA_STABLE_BIN_DIR" ]; then
    build_binaries "$SRC_DIR" "$STABLE" "$VANILLA_STABLE_BIN_DIR"
fi

# flag indicating the need of txn generation
# usually it is done only once at the beginning
init_generate_network_and_txn=""

# payset, keyreg, lsig, group, asset
TXN_BASE_COUNT=5
# base + app call, rekey, rekeyed
TXN_ALL_COUNT=8

# test flags - see details at each test below
test_new_pre_upgrade=""
test_old_pre_upgrade=""
test_new_upgrade_proposed=""
test_new_upgrade_applied=""
test_at_upgrade_round=""
test_next_proto_standalone=""  # !!! <-- this test breaks all pre-generated transactions !!!

if [ -n "$init_generate_network_and_txn" ]; then
# generate sample network once to have the same genesis for all subsequent tests (except the separate future test)
generate_network "$VANILLA_TESTING_BIN_DIR" "$BASE_PROTO"

# pre-generate old transactions
SENDER="Node1"
RECEIVER="Primary"
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR"

# generate tx with valid round=UPGRADE_ROUND for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$UPGRADE_ROUND"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE with validity round=$UPGRADE_ROUND"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$BASE_PROTO" "$UPGRADE_ROUND"

# generate tx with valid round=UPGRADE_ROUND+1 for at upgrade+1 test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$UPGRADE_ROUND_NEXT"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE transaction with validity round=$UPGRADE_ROUND_NEXT"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$BASE_PROTO" "$UPGRADE_ROUND_NEXT"

SENDER="Primary"
RECEIVER="Node2"
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR"

# generate tx with valid round=UPGRADE_ROUND for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$UPGRADE_ROUND"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE with validity round=$UPGRADE_ROUND"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$BASE_PROTO" "$UPGRADE_ROUND"

# generate tx with valid round=UPGRADE_ROUND+1 for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$UPGRADE_ROUND_NEXT"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE with validity round=$UPGRADE_ROUND_NEXT"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$BASE_PROTO" "$UPGRADE_ROUND_NEXT"

SENDER="Node2"
RECEIVER="Primary"
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $STABLE"
generate_transactions "$VANILLA_STABLE_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR"

# upgrade network and pre-generate new transactions
build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_fast_upgrade_to_next_proto

SENDER="Node1"
RECEIVER="Primary"
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING transaction"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO"

# generate tx with valid round=UPGRADE_ROUND for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$UPGRADE_ROUND"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING with validity round=$UPGRADE_ROUND"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO" "$UPGRADE_ROUND"

# generate tx with valid round=UPGRADE_ROUND+1 for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$UPGRADE_ROUND_NEXT"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING with validity round=$UPGRADE_ROUND_NEXT"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO" "$UPGRADE_ROUND_NEXT"

SENDER="Primary"
RECEIVER="Node2"
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO"

# generate tx with valid round=5 for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$UPGRADE_ROUND"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING with validity round=$UPGRADE_ROUND"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO" "$UPGRADE_ROUND"

# generate tx with valid round=UPGRADE_ROUND+1 for at upgrade test
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$UPGRADE_ROUND_NEXT"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING with validity round=$UPGRADE_ROUND_NEXT"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO" "$UPGRADE_ROUND_NEXT"

SENDER="Node2"
RECEIVER="Primary"
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
trace_if_needed "Creating tx $SENDER -> $RECEIVER by version $TESTING transaction"
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO"
fi

####################################################################################################
#
# Tests
# Note set -e handles exit after each failed tests
#
####################################################################################################
if [ -n "$test_new_pre_upgrade" ]; then
echo "============================================================================================="
echo "1. Check NEW ALGOD accepts old and new basic transactions (pre upgrade)"
echo

NODES=(
    "Primary:$TESTING_BIN_DIR"
    "Node1:$TESTING_BIN_DIR"
    "Node2:$TESTING_BIN_DIR"
)
COUNT=$TXN_BASE_COUNT

echo "---------------------------------------------------------------------------------------------"
echo "1.1. TxSync disabled"

SENDER="Node1"
RECEIVER="Primary"
echo "Will be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_log_txpool_remember

# test new binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
test_pre_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test new binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
test_pre_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

echo "---------------------------------------------------------------------------------------------"
echo "1.2. Gossip tx broadcast disabled"

SENDER="Primary"
RECEIVER="Node2"
echo "Will be sending from $SENDER to $RECEIVER (because TxSync pulls only from Relays)"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_disable_gossip

# test new binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
test_pre_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test new binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
test_pre_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"
fi

if [ -n "$test_old_pre_upgrade" ]; then
echo "============================================================================================="
echo "2. Check OLD ALGOD accepts old and new basic transactions (pre upgrade)"
echo

NODES=(
    "Primary:$STABLE_BIN_DIR"
    "Node1:$STABLE_BIN_DIR"
    "Node2:$STABLE_BIN_DIR"
)
COUNT=$TXN_BASE_COUNT

echo "---------------------------------------------------------------------------------------------"
echo "2.1. TxSync disabled"

SENDER="Node1"
RECEIVER="Primary"
echo "Will be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

build_binaries "$SRC_DIR" "$STABLE" "$STABLE_BIN_DIR" patch_log_txpool_remember

# test old binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
test_pre_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test old binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
test_pre_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

echo "---------------------------------------------------------------------------------------------"
echo "2.2. Gossip tx broadcast disabled"

SENDER="Primary"
RECEIVER="Node2"
echo "Will be sending from $SENDER to $RECEIVER (because TxSync pulls only from Relays)"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

build_binaries "$SRC_DIR" "$STABLE" "$STABLE_BIN_DIR" patch_agg_remember_and_disable_gossip

# test old binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER"
test_pre_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test old binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER"
test_pre_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"
fi

if [ -n "$test_new_upgrade_proposed" ]; then
echo "============================================================================================="
echo "3. Check NEW algod and OLD algod accept old and new basic transactions (upgrade proposed)"
echo

NODES=(
    "Primary:$TESTING_BIN_DIR"
    "Node1:$TESTING_BIN_DIR"
    "Node2:$STABLE_BIN_DIR"
)
COUNT=$TXN_BASE_COUNT
PROPOSER="Node1"

echo "---------------------------------------------------------------------------------------------"
echo "3.1. TxSync disabled"

SENDER="Node1"
RECEIVER="Primary"
echo "Will be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
    "prp:$PROPOSER@0"
)

build_binaries "$SRC_DIR" "$STABLE" "$STABLE_BIN_DIR" patch_log_txpool_remember
build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_upgrade_path

# test new binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
test_after_proposal_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test new binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)"
test_after_proposal_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

SENDER="Node2"
RECEIVER="Primary"
echo "Now be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
    "prp:$PROPOSER@0"
)
# test old binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
test_after_proposal_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test old binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)"
test_after_proposal_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

echo "---------------------------------------------------------------------------------------------"
echo "3.2. Gossip tx broadcast disabled"

SENDER="Primary"
RECEIVER="Node2"
echo "Will be sending from $SENDER to $RECEIVER (because TxSync pulls only from Relays)"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
    "prp:$PROPOSER@0"
)

build_binaries "$SRC_DIR" "$STABLE" "$STABLE_BIN_DIR" patch_agg_remember_and_disable_gossip
build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_disable_gossip_and_upgrade_path

# test new binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
test_after_proposal_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test new binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)"
test_after_proposal_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# because TxSync pulls only from Relays, set Primary to be on the binaries
NODES=(
    "Primary:$STABLE_BIN_DIR"
    "Node1:$TESTING_BIN_DIR"
    "Node2:$STABLE_BIN_DIR"
)
echo "Changing network to ${NODES[@]}"

# test old binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
test_after_proposal_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test old binaries with old transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)"
test_after_proposal_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"
fi

if [ -n "$test_new_upgrade_applied" ]; then
echo "============================================================================================="
echo "4. Check NEW ALGOD accepts old basic and all new transactions (post upgrade)"
echo

NODES=(
    "Primary:$TESTING_BIN_DIR"
    "Node1:$TESTING_BIN_DIR"
    "Node2:$TESTING_BIN_DIR"
)
COUNT=$TXN_ALL_COUNT
OLD_COUNT=$TXN_BASE_COUNT

echo "---------------------------------------------------------------------------------------------"
echo "4.1. TxSync disabled"

SENDER="Node1"
RECEIVER="Primary"
echo "Will be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_fast_upgrade_to_next_proto

# test new binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
test_upgrade_applied_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test new binaries with old transactions
EMIT_INFO=(
    "snd:$SENDER@$OLD_COUNT"
    "rcv:$RECEIVER@$OLD_COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)"
test_upgrade_applied_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

echo "---------------------------------------------------------------------------------------------"
echo "4.2. Gossip tx broadcast disabled"

SENDER="Primary"
RECEIVER="Node2"
echo "Will be sending from $SENDER to $RECEIVER (because TxSync pulls only from Relays)"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_disable_gossip_and_patch_fast_upgrade_to_next_proto

# test new binaries with new transactions
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
test_upgrade_applied_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"

# test new binaries with old transactions
EMIT_INFO=(
    "snd:$SENDER@$OLD_COUNT"
    "rcv:$RECEIVER@$OLD_COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)"
test_upgrade_applied_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR"
fi

if [ -n "$test_at_upgrade_round" ]; then
echo "============================================================================================="
echo "5. Check NEW algod accepts all old and new transactions (upgrade and upgrade+1)"
echo

NODES=(
    "Primary:$TESTING_BIN_DIR"
    "Node1:$TESTING_BIN_DIR"
    "Node2:$TESTING_BIN_DIR"
)
COUNT=$TXN_BASE_COUNT
((SUBMIT_ROUND=$UPGRADE_ROUND-1))

echo "---------------------------------------------------------------------------------------------"
echo "5.1. TxSync disabled"

SENDER="Node1"
RECEIVER="Primary"
echo "Will be sending from $SENDER to $RECEIVER"
echo

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_fast_upgrade_to_next_proto

trace_if_needed "check upgrade round"
# submit a the beginning of UPGRADE_ROUND, so that transactions go to UPGRADE_ROUND+1 block
((SUBMIT_ROUND=$UPGRADE_ROUND-1))
((TX_VALID_ROUND=$UPGRADE_ROUND))

trace_if_needed "test new binaries with old transactions"
COUNT=$TXN_BASE_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

trace_if_needed "test new binaries with old transactions"
COUNT=$TXN_BASE_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

trace_if_needed "check upgrade+1 round"
# submit a the beginning of UPGRADE_ROUND, so that transactions go to UPGRADE_ROUND+1 block
SUBMIT_ROUND="$UPGRADE_ROUND"
((TX_VALID_ROUND=$UPGRADE_ROUND+1))

trace_if_needed "test new binaries with all transactions"
COUNT=$TXN_ALL_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

trace_if_needed "test new binaries with old transactions"
COUNT=$TXN_BASE_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

echo "---------------------------------------------------------------------------------------------"
echo "5.2. Gossip tx broadcast disabled"

SENDER="Primary"
RECEIVER="Node2"
echo "Will be sending from $SENDER to $RECEIVER (because TxSync pulls only from Relays)"
echo

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_disable_gossip_and_patch_fast_upgrade_to_next_proto

trace_if_needed "check upgrade round"
# submit a the beginning of UPGRADE_ROUND-1, so that transactions go to UPGRADE_ROUND block
((SUBMIT_ROUND=$UPGRADE_ROUND-1))
((TX_VALID_ROUND=$UPGRADE_ROUND))
# test new binaries with old transactions
COUNT=$TXN_BASE_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

trace_if_needed "test new binaries with old transactions"
COUNT=$TXN_BASE_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

trace_if_needed "check upgrade+1 round"
# submit a the beginning of UPGRADE_ROUND, so that transactions go to UPGRADE_ROUND+1 block
SUBMIT_ROUND="$UPGRADE_ROUND"
((TX_VALID_ROUND=$UPGRADE_ROUND+1))

trace_if_needed "test new binaries with all transactions"
COUNT=$TXN_ALL_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"

trace_if_needed "test new binaries with old transactions"
COUNT=$TXN_BASE_COUNT
EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)
TX_DIR="$TX_BASE_DIR/$(revision_to_name $STABLE)/$SENDER/Round$TX_VALID_ROUND"
test_at_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$UPGRADE_ROUND" "$SUBMIT_ROUND"
fi

if [ -n "$test_next_proto_standalone" ]; then
echo "============================================================================================="
echo "6. Check NEW algod accepts all transactions (create a fresh v=NEXT_PROTO network)"
echo "This test re-generates the network so that no pre-generated transactions are valid"

NODES=(
    "Primary:$TESTING_BIN_DIR"
    "Node1:$TESTING_BIN_DIR"
    "Node2:$TESTING_BIN_DIR"
)
COUNT=$TXN_ALL_COUNT

generate_network "$VANILLA_TESTING_BIN_DIR" "$NEXT_PROTO"

echo "---------------------------------------------------------------------------------------------"
echo "6.1. TxSync disabled"

SENDER="Node1"
RECEIVER="Primary"
echo "Will be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_change_current_consensus_version
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO"

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_log_txpool_remember
test_pre_upgrade_gossip "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$NEXT_PROTO"

echo "---------------------------------------------------------------------------------------------"
echo "6.2. Gossip tx broadcast disabled"

SENDER="Primary"
RECEIVER="Node2"
echo "Will be sending from $SENDER to $RECEIVER"
echo

EMIT_INFO=(
    "snd:$SENDER@$COUNT"
    "rcv:$RECEIVER@$COUNT"
)

TX_DIR="$TX_BASE_DIR/$(revision_to_name $TESTING)"
build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_change_current_consensus_version
generate_transactions "$TESTING_BIN_DIR" "$SENDER" "$RECEIVER" "$TX_DIR" "$NEXT_PROTO"

build_binaries "$SRC_DIR" "$TESTING" "$TESTING_BIN_DIR" patch_agg_remember_and_disable_gossip
test_pre_upgrade_txsync "$(echo ${NODES[@]})" "$(echo ${EMIT_INFO[@]})" "$TX_DIR" "$NEXT_PROTO"
fi

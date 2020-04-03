#!/usr/bin/env bash
echo "######################################################################"
echo "  Start Auction Script"
echo "######################################################################"
set -e
set -x
export GOPATH=$(go env GOPATH)

if [[ ! "$#" -eq 5 ]]; then
    echo "Syntax: auctionStart.sh <test_dir> <auction_bank_port> <console_port> <auction_params_file> <auctionmaster_starting_balance>"
    exit 1
fi

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

# Ensure our required environment variables are set - in case running this script standalone
CLEANUP_TEMPDIR=0
WAIT_SECONDS=3

# Set root dir for auction test
export AUCTION_TESTDIR=${1}

# Setup ports
export AUCTION_BANK_PORT="${2}"
export CONSOLE_PORT="${3}"

# Set params file
export PARAMS_FILE=${4}

# Specify starting balance for auction master
export AUCTIONMASTER_STARTING_BALANCE=${5}

echo AUCTION_TESTDIR = ${AUCTION_TESTDIR}
echo PARAMS_FILE = ${PARAMS_FILE}
echo AUCTIONMASTER_STARTING_BALANCE=${AUCTIONMASTER_STARTING_BALANCE}

cat ${PARAMS_FILE}


if [[ "${AUCTION_TESTDIR}" = "" ]]; then
    # Create our own temp folder - we'll clean it up if everything passes
    TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
    CLEANUP_TEMPDIR=1
    export AUCTION_TESTDIR=${TEMPDIR}
fi


echo "Test output can be found in ${AUCTION_TESTDIR}"

mkdir -p ${AUCTION_TESTDIR}
cd ${AUCTION_TESTDIR}
echo "PWD" $(pwd)

if [[ "${SRCROOT}" = "" ]]; then
    export SRCROOT=${REPO_ROOT}
fi

if [[ "${NODEBINDIR}" = "" ]]; then
    export NODEBINDIR="${GOPATH}/bin"
fi

if [ -d "${NODEBINDIR}/../tools" ]; then
    export TOOLSBINDIR="${NODEBINDIR}/../tools"
else
    export TOOLSBINDIR="${NODEBINDIR}"
fi

if [ -d "${NODEBINDIR}/../test-utils" ]; then
    export TESTBINDIR="${NODEBINDIR}/../test-utils"
else
    export TESTBINDIR="${NODEBINDIR}"
fi


#define algod working dir
if [[ "${ALGOTESTDIR}" = "" ]]; then
    export ALGOTESTDIR="${AUCTION_TESTDIR}/Primary"
fi

sleep ${WAIT_SECONDS}

mkdir -p ${ALGOTESTDIR}

#define auction master working dir
if [[ "${AUCTIONBANKTESTDIR}" = "" ]]; then
    export AUCTIONBANKTESTDIR="${AUCTION_TESTDIR}/AuctionBank"
fi

mkdir -p ${AUCTIONBANKTESTDIR}

sleep ${WAIT_SECONDS}

export ALGOD_PORT=$(cat ${ALGOTESTDIR}/algod.net)

# start auction bank instance with port number

pushd ${AUCTIONBANKTESTDIR}
rm -f bank.sqlite3
rm -f bank.keyfile
rm -f ${AUCTIONBANKTESTDIR}/bank.key
${TESTBINDIR}/auctionbank -create
${TESTBINDIR}/auctionbank -addr ${AUCTION_BANK_PORT} &> ${AUCTIONBANKTESTDIR}/bank.key &

sleep ${WAIT_SECONDS}
echo "Auction Bank PID: $(cat ${AUCTIONBANKTESTDIR}/auctionbank.pid)"
echo "Auction Bank port: $(cat ${AUCTIONBANKTESTDIR}/auctionbank.net)"
export AUCTION_BANK_PORT="$(cat ${AUCTIONBANKTESTDIR}/auctionbank.net)"
popd

sleep ${WAIT_SECONDS}
export BANK_KEY=$(awk 'NR==1{print $3}' ${AUCTIONBANKTESTDIR}/bank.key)


#define auction master working dir
if [[ "${AUCTIONMASTERTESTDIR}" = "" ]]; then
    export AUCTIONMASTERTESTDIR="${AUCTION_TESTDIR}/AuctionMaster"
fi
mkdir -p ${AUCTIONMASTERTESTDIR}

#define auction master working dir
if [[ "${AUCTIONCONSOLETESTDIR}" = "" ]]; then
    export AUCTIONCONSOLETESTDIR="${AUCTION_TESTDIR}/AuctionConsole"
fi
mkdir -p ${AUCTIONCONSOLETESTDIR}

sleep ${WAIT_SECONDS}

# setup auction master key
${NODEBINDIR}/algokey generate -f ${AUCTIONMASTERTESTDIR}/master.key -p ${AUCTIONMASTERTESTDIR}/master.pub
export AUCTIONMASTERPUBKEY=$(cat ${AUCTIONMASTERTESTDIR}/master.pub)
echo AUCTIONMASTERPUBKEY ${AUCTIONMASTERPUBKEY}

${NODEBINDIR}/goal account list -d ${ALGOTESTDIR}  &>${ALGOTESTDIR}/accountlist.out
echo "current account list: " $(cat ${ALGOTESTDIR}/accountlist.out)

#choose the account with highest balance for funding the auction master account
export PRIMARY_ACCOUNT=$(cat ${ALGOTESTDIR}/accountlist.out | ( while read account
do
    account_key=$(awk '{print $3}' <<< ${account})
    account_balance=$(awk '{print $4}' <<< ${account})
    if [ "${account_balance}" = "[n/a]" ]; then
        echo "ERROR: unable to retrieve available funds for account ${account_key}"
        exit 1
    fi
    if [[ ${max_balance} -lt ${account_balance} ]]; then
       max_balance=${account_balance}
       primary_account=${account_key}
    fi
done
echo ${primary_account}
))

if [[ "${PRIMARY_ACCOUNT}" = "" ]]; then
    echo "ERROR: no primary Algod account found"
    exit 1
fi

echo "Transfer money to Auction Master account: ${AUCTIONMASTERPUBKEY} from algod account: " ${PRIMARY_ACCOUNT}

echo Transfering ${AUCTIONMASTER_STARTING_BALANCE} Algos from account ${PRIMARY_ACCOUNT} to ${AUCTIONMASTERPUBKEY}

${NODEBINDIR}/goal clerk send --amount ${AUCTIONMASTER_STARTING_BALANCE} --from ${PRIMARY_ACCOUNT} --to ${AUCTIONMASTERPUBKEY} -d ${ALGOTESTDIR}

## Set up multisig account representing the auction dispenser
MSIGACCT=$(${NODEBINDIR}/goal account multisig new -T 1 ${AUCTIONMASTERPUBKEY} -d ${ALGOTESTDIR} | awk '{print $6;}')
${NODEBINDIR}/goal clerk send --amount ${AUCTIONMASTER_STARTING_BALANCE} --from ${PRIMARY_ACCOUNT} --to ${MSIGACCT} -d ${ALGOTESTDIR}

${NODEBINDIR}/goal account list -d ${ALGOTESTDIR}  &>${ALGOTESTDIR}/accountlist.out
cat ${ALGOTESTDIR}/accountlist.out
echo "end transfer some money to account  am/master.pub"

# setup auction minion

#define auction master working dir
if [[ "${AUCTIONMINIONTESTDIR}" = "" ]]; then
    export AUCTIONMINIONTESTDIR="${AUCTION_TESTDIR}/AuctionMinion"
fi
mkdir -p ${AUCTIONMINIONTESTDIR}
export AUCTIONMINIONSTATEFILE=${AUCTIONMINIONTESTDIR}/auctionminion.state

sleep ${WAIT_SECONDS}

${TOOLSBINDIR}/auctionminion -init -statefile ${AUCTIONMINIONSTATEFILE} &>${AUCTIONMINIONTESTDIR}/auctionminion_init.log

# Update the auction minion state file, fill in AuctionKey from  am/master.pub, AlgodToken from xx/algod.token, and use correct algod URL

export AUCTION_START_ROUND=$(awk '$1 == "\"FirstRound\"\:" {print $2}' ${PARAMS_FILE})

export ALGOD_TOKEN="$(cat ${ALGOTESTDIR}/algod.token)"

sed -i.bak "s/\"AuctionKey\"\: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\"/\"AuctionKey\"\: \"${AUCTIONMASTERPUBKEY}\"/g" ${AUCTIONMINIONSTATEFILE} && rm ${AUCTIONMINIONSTATEFILE}.bak

sed -i.bak "s/\"AlgodToken\"\: \"\"/\"AlgodToken\"\: \"${ALGOD_TOKEN}\"/g" ${AUCTIONMINIONSTATEFILE} && rm ${AUCTIONMINIONSTATEFILE}.bak

sed -i.bak "s/127.0.0.1\:8080/${ALGOD_PORT}/g" ${AUCTIONMINIONSTATEFILE} && rm ${AUCTIONMINIONSTATEFILE}.bak

echo ${AUCTIONMINIONSTATEFILE}
cat ${AUCTIONMINIONSTATEFILE}

sleep ${WAIT_SECONDS}

# Register auction with the bank
curl -g -X POST --data-urlencode "auction=${AUCTIONMASTERPUBKEY}" http://${AUCTION_BANK_PORT}/create-auctions

# Setup Auction Parameters

cp ${PARAMS_FILE} ${AUCTIONMASTERTESTDIR}/initparams.json
sed -i.bak "s/%BANK_KEY%/${BANK_KEY}/g" ${AUCTIONMASTERTESTDIR}/initparams.json && rm ${AUCTIONMASTERTESTDIR}/initparams.json.bak
sed -i.bak "s/%DISPENSE_KEY%/${AUCTIONMASTERPUBKEY}/g" ${AUCTIONMASTERTESTDIR}/initparams.json && rm ${AUCTIONMASTERTESTDIR}/initparams.json.bak

echo "Contents of initparams.json"
cat ${AUCTIONMASTERTESTDIR}/initparams.json

sleep ${WAIT_SECONDS}

export LAST_ROUND="$(${NODEBINDIR}/goal -d ${ALGOTESTDIR} node lastround)"
export CURRENT_VERSION="$(${NODEBINDIR}/goal node status -d ${ALGOTESTDIR} | grep 'Next consensus protocol' | grep -v 'supported' | cut -c 25-)"
export GENESIS_HASH="$(${NODEBINDIR}/goal node status -d ${ALGOTESTDIR} | grep 'Genesis hash' | cut -c 15-)"
echo LAST_ROUND ${LAST_ROUND}
echo CURRENT_VERSION ${CURRENT_VERSION}
echo GENESIS_HASH ${GENESIS_HASH}
export TXN_FEE=1000

# Run the auction master to initialize the auction
${TOOLSBINDIR}/auctionmaster -dir ${AUCTIONMASTERTESTDIR} -initparams -txround ${LAST_ROUND} -notesfee ${TXN_FEE} -payfee ${TXN_FEE} -currentversion ${CURRENT_VERSION} -genhash ${GENESIS_HASH}

sleep ${WAIT_SECONDS}

echo "Confirming auctionmaster is funded before posting starttx."
AUCTIONMASTER_CURRENT_BALANCE="$(${NODEBINDIR}/goal account balance --address ${AUCTIONMASTERPUBKEY} -d ${ALGOTESTDIR}| grep -o '[0-9]\+')"
retries=0
max_retries=20
while [[ ${AUCTIONMASTER_CURRENT_BALANCE} != "${AUCTIONMASTER_STARTING_BALANCE}" ]]
do
    echo "No money yet, checking again."
    sleep 1
    AUCTIONMASTER_CURRENT_BALANCE="$(${NODEBINDIR}/goal account balance --address ${AUCTIONMASTERPUBKEY} -d ${ALGOTESTDIR}| grep -o '[0-9]\+')"
    retries++
    if ${retries}==${max_retries}; then
        echo "Retried too many times. Failing out."
        exit 1
    fi
done

cat ${AUCTIONMASTERTESTDIR}/auction1.starttx

# Broadcast initial auction start
${NODEBINDIR}/goal -d ${ALGOTESTDIR} clerk rawsend -f ${AUCTIONMASTERTESTDIR}/auction1.starttx

# Start the auction console
pushd ${AUCTIONCONSOLETESTDIR}
nohup ${TOOLSBINDIR}/auctionconsole -apitoken $(cat ${ALGOTESTDIR}/algod.token) -auctionkey ${AUCTIONMASTERPUBKEY} -addr ${CONSOLE_PORT} -algod http://${ALGOD_PORT} &>${AUCTIONCONSOLETESTDIR}/auctionconsole.log &
popd


sleep ${WAIT_SECONDS}
echo "Auction Console PID: $(cat ${AUCTIONCONSOLETESTDIR}/auctionconsole.pid)"
echo "Auction Console port: $(cat ${AUCTIONCONSOLETESTDIR}/auctionconsole.net)"
export AUCTION_CONSOLE_PORT="$(cat ${AUCTIONCONSOLETESTDIR}/auctionconsole.net)"


echo "Last Auction Id after auction start: "
curl -g -X GET http://${AUCTION_CONSOLE_PORT}/auctions/last-auction-id


echo "----------------------------------------------------------------------"
echo "  DONE: Auction Start"
echo "----------------------------------------------------------------------"

#!/usr/bin/env bash
echo "######################################################################"
echo "  End Auction Script"
echo "######################################################################"
set -e
set -x
export GOPATH=$(go env GOPATH)
WAIT_SECONDS=3

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

if [[ ! "$#" -eq 4 ]]; then
    echo "Syntax: auctionEnd.sh <test_dir> <auction_bank_port> <console_port> <final_auction_id>"
    exit 1
fi

export AUCTION_TESTDIR=${1}

# setup ports
export AUCTION_BANK_PORT="${2}"
export CONSOLE_PORT="${3}"
export FINAL_AUCTION_ID=${4}

# Ensure our required environment variables are set - in case running this script standalone

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

#define algod working dir
if [[ "${ALGOTESTDIR}" = "" ]]; then
    export ALGOTESTDIR="${AUCTION_TESTDIR}/Primary"
fi


#define auction master working dir
if [[ "${AUCTIONBANKTESTDIR}" = "" ]]; then
    export AUCTIONBANKTESTDIR="${AUCTION_TESTDIR}/AuctionBank"
fi

#define auction master working dir
if [[ "${AUCTIONMASTERTESTDIR}" = "" ]]; then
    export AUCTIONMASTERTESTDIR="${AUCTION_TESTDIR}/AuctionMaster"
fi

#define auction master working dir
if [[ "${AUCTIONMINIONTESTDIR}" = "" ]]; then
    export AUCTIONMINIONTESTDIR="${AUCTION_TESTDIR}/AuctionMinion"
fi

#setup Alogd Port

export ALGOD_PORT=$(cat ${ALGOTESTDIR}/algod.net)

export AUCTIONMINIONSTATEFILE=${AUCTIONMINIONTESTDIR}/auctionminion.state

cat ${AUCTIONMINIONTESTDIR}/auctionminion.state


sleep ${WAIT_SECONDS}

# call auction minion to complete auction
{
  ${TOOLSBINDIR}/auctionminion -verbose -statefile ${AUCTIONMINIONSTATEFILE}  &> ${AUCTIONMINIONTESTDIR}/auctionminion_complete.log
} || {
  echo "error calling auction minion"
  cat ${AUCTIONMINIONTESTDIR}/auctionminion_complete.log
  exit 1
}
sleep ${WAIT_SECONDS}

# call auction master to settle the transaction
mv auction*.inputs ${AUCTIONMASTERTESTDIR}/

export FINAL_ROUND=$(${NODEBINDIR}/goal -d ${ALGOTESTDIR} node lastround)
export CURRENT_VERSION="$(${NODEBINDIR}/goal node status -d ${ALGOTESTDIR} | grep 'Next consensus protocol' | grep -v 'supported' | cut -c 25-)"
export GENESIS_HASH="$(${NODEBINDIR}/goal node status -d ${ALGOTESTDIR} | grep 'Genesis hash' | cut -c 15-)"
export TXN_FEE=1000

{
  ${TOOLSBINDIR}/auctionmaster -dir ${AUCTIONMASTERTESTDIR} -txround ${FINAL_ROUND} -notesfee ${TXN_FEE} -payfee ${TXN_FEE} -currentversion ${CURRENT_VERSION} -genhash ${GENESIS_HASH} &> ${AUCTIONMASTERTESTDIR}/auction_master.log
} || {
  echo "error calling auction master"
  cat ${AUCTIONMASTERTESTDIR}/auction_master.log
  exit 1
}

sleep ${WAIT_SECONDS}

#Broadcast auction settlement
export LAST_AUCTION_ID="$(cat ${AUCTIONMASTERTESTDIR}/lastsettled)"
export NEXT_AUCTION_ID="$(expr ${LAST_AUCTION_ID} + 1)"

${NODEBINDIR}/algokey multisig -k ${AUCTIONMASTERTESTDIR}/master.key -t ${AUCTIONMASTERTESTDIR}/auction${LAST_AUCTION_ID}.paymenttx -o ${AUCTIONMASTERTESTDIR}/auction${LAST_AUCTION_ID}.paymenttx.signed

${NODEBINDIR}/goal -d ${ALGOTESTDIR} clerk rawsend -f ${AUCTIONMASTERTESTDIR}/auction${LAST_AUCTION_ID}.settletx
${NODEBINDIR}/goal -d ${ALGOTESTDIR} clerk rawsend -f ${AUCTIONMASTERTESTDIR}/auction${LAST_AUCTION_ID}.paymenttx.signed

sleep ${WAIT_SECONDS}

# inform the auction bank that the auction is over
curl -g -v -X POST --data-urlencode "auction=$(cat ${AUCTIONMASTERTESTDIR}/master.pub)" --data-urlencode "outcomes=$(base64 ${AUCTIONMASTERTESTDIR}/auction${LAST_AUCTION_ID}.outcomes)" --data-urlencode "sigsettle=$(base64 ${AUCTIONMASTERTESTDIR}/auction${LAST_AUCTION_ID}.settle)" http://${AUCTION_BANK_PORT}/settle-auction
echo "Last Auction Id after auction end: "
curl -g -X GET http://${CONSOLE_PORT}/auctions/last-auction-id


echo "----------------------------------------------------------------------"
echo "  DONE: Auction End"
echo "----------------------------------------------------------------------"

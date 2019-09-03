#!/bin/sh -e

if [ "$1" = "" ]; then
  echo "Usage: $0 genesis.json"
  exit 1
fi

D=$(mktemp -d)
trap "rm -r $D" 0

GENJSON="$1"
GOPATH1=$(go env GOPATH | cut -d: -f1)
$GOPATH1/bin/algod -d $D -g "$GENJSON" -x >/dev/null
LEDGERS=$D/*/ledger.*sqlite

for LEDGER in $LEDGERS; do
  for T in $(echo .tables | sqlite3 $LEDGER); do
    case "$T" in
      blocks)
        SORT=rnd
        ;;
      accountbase)
        SORT=address
        ;;
      accounttotals)
        SORT=id
        ;;
      acctrounds)
        SORT=id
        ;;
      participationperiods)
        SORT=period
        ;;
      *)
        echo "Unknown table $T" >&2
        exit 1
        ;;
    esac

    echo ".schema $T" | sqlite3 $LEDGER
    ( echo .headers on;
      echo .mode insert $T;
      echo "SELECT * FROM $T ORDER BY $SORT;" ) | sqlite3 $LEDGER
  done
done

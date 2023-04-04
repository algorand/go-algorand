package generickv

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

// LookupOnline pulls the Online Account data for a given account+round
func (r *accountsReader) LookupOnline(addr basics.Address, rnd basics.Round) (data trackerdb.PersistedOnlineAccountData, err error) {
	// read the current db round
	data.Round, err = r.AccountsRound()
	if err != nil {
		return
	}

	value, closer, err := r.kvr.Get(onlineAccountKey(addr, rnd))
	if err == trackerdb.ErrNotFound {
		// Note: the SQL implementation returns a data value and no error even when the account does not exist.
		return data, nil
	} else if err != nil {
		return
	}
	defer closer.Close()

	data.Addr = addr
	err = protocol.Decode(value, &data.AccountData)
	if err != nil {
		return
	}

	normBalance := data.AccountData.NormalizedOnlineBalance(r.proto)
	data.Ref = onlineAccountRef{addr, normBalance, rnd}

	return
}

// LookupOnlineTotalsHistory pulls the total Online Algos on a given round
func (r *accountsReader) LookupOnlineTotalsHistory(round basics.Round) (basics.MicroAlgos, error) {
	value, closer, err := r.kvr.Get(onlineBalanceTotalKey(round))
	if err != nil {
		return basics.MicroAlgos{}, err
	}
	defer closer.Close()
	var ma basics.MicroAlgos
	err = protocol.Decode(value, &ma)
	if err != nil {
		return basics.MicroAlgos{}, err
	}
	return ma, nil
}

func (r *accountsReader) LookupOnlineHistory(addr basics.Address) (result []trackerdb.PersistedOnlineAccountData, rnd basics.Round, err error) {
	low := onlineAccountOnlyPartialKey(addr)
	high := onlineAccountOnlyPartialKey(addr)
	high[len(high)-1] += 1
	iter := r.kvr.NewIter(low, high, false)
	defer iter.Close()

	var value []byte
	var updround uint64

	// read the current db round
	var round basics.Round
	round, err = r.AccountsRound()
	if err != nil {
		return
	}

	for iter.Next() {
		pitem := trackerdb.PersistedOnlineAccountData{Round: round}

		// schema: <prefix>-<addr>-<rnd>
		key := iter.Key()
		// extract updround, its the last section after the "-"
		rndOffset := len(kvPrefixOnlineAccount) + 1 + 32 + 1
		updround = binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])
		if err != nil {
			return
		}
		pitem.Addr = addr
		pitem.UpdRound = basics.Round(updround)
		// TODO: load "Round" here too

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return
		}
		// decode raw value
		err = protocol.Decode(value, &pitem.AccountData)
		if err != nil {
			return
		}
		// append entry to accum
		result = append(result, pitem)
	}

	return
}

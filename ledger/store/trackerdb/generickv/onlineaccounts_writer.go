// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package generickv

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

type onlineAccountsWriter struct {
	kvw KvWrite
}

type onlineAccountRef struct {
	addr        basics.Address
	normBalance uint64
	round       basics.Round
}

func (ref onlineAccountRef) OnlineAccountRefMarker() {}

// MakeOnlineAccountsWriter constructs an kv agnostic OnlineAccountsWriter
func MakeOnlineAccountsWriter(kvw KvWrite) trackerdb.OnlineAccountsWriter {
	return &onlineAccountsWriter{kvw}
}

func (w *onlineAccountsWriter) InsertOnlineAccount(addr basics.Address, normBalance uint64, data trackerdb.BaseOnlineAccountData, updRound uint64, voteLastValid uint64) (ref trackerdb.OnlineAccountRef, err error) {
	raw := protocol.Encode(&data)
	rnd := basics.Round(updRound)

	// write to the online account key
	err = w.kvw.Set(onlineAccountKey(addr, rnd), raw)
	if err != nil {
		return nil, err
	}

	// write to the secondary account balance key
	// err = w.kvw.Set(onlineAccountBalanceKey(updRound, normBalance, addr), []byte{})
	// TODO: Nacho: shortcut to get the demo working, we nede to see if we want to trade storage for efficiency on this one
	err = w.kvw.Set(onlineAccountBalanceKey(updRound, normBalance, addr), raw)
	if err != nil {
		return nil, err
	}

	return onlineAccountRef{addr, normBalance, rnd}, nil
}

func (w *onlineAccountsWriter) Close() {
}

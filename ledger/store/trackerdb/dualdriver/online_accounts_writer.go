// Copyright (C) 2019-2024 Algorand, Inc.
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

package dualdriver

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

type onlineAccountsWriter struct {
	primary   trackerdb.OnlineAccountsWriter
	secondary trackerdb.OnlineAccountsWriter
}

// Close implements trackerdb.OnlineAccountsWriter
func (oaw *onlineAccountsWriter) Close() {
	oaw.primary.Close()
	oaw.secondary.Close()
}

// InsertOnlineAccount implements trackerdb.OnlineAccountsWriter
func (oaw *onlineAccountsWriter) InsertOnlineAccount(addr basics.Address, normBalance uint64, data trackerdb.BaseOnlineAccountData, updRound uint64, voteLastValid uint64) (ref trackerdb.OnlineAccountRef, err error) {
	// Note: we do not check the refs since they are internal to the engines and wont match
	refP, errP := oaw.primary.InsertOnlineAccount(addr, normBalance, data, updRound, voteLastValid)
	refS, errS := oaw.secondary.InsertOnlineAccount(addr, normBalance, data, updRound, voteLastValid)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// return ref
	return onlineAccountRef{refP, refS}, nil
}

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

package generickv

import (
	"context"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

type reader struct {
	proto config.ConsensusParams
	KvRead
}

// MakeReader returns a trackerdb.Reader for a KV
func MakeReader(kvr KvRead, proto config.ConsensusParams) trackerdb.Reader {
	return &reader{proto, kvr}
}

// MakeAccountsOptimizedReader implements trackerdb.Reader
func (r *reader) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return MakeAccountsReader(r, r.proto), nil
}

// MakeAccountsReader implements trackerdb.Reader
func (r *reader) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return MakeAccountsReader(r, r.proto), nil
}

// MakeOnlineAccountsOptimizedReader implements trackerdb.Reader
func (r *reader) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	return MakeAccountsReader(r, r.proto), nil
}

// MakeSpVerificationCtxReader implements trackerdb.Reader
func (r *reader) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	return MakeStateproofReader(r)
}

// MakeCatchpointPendingHashesIterator implements trackerdb.Reader
func (r *reader) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	// TODO: catchpoint
	panic("unimplemented")
}

// MakeCatchpointReader implements trackerdb.Reader
func (r *reader) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	// TODO: catchpoint
	panic("unimplemented")
}

// MakeEncodedAccoutsBatchIter implements trackerdb.Reader
func (r *reader) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	// TODO: catchpoint
	panic("unimplemented")
}

// MakeKVsIter implements trackerdb.Reader
func (r *reader) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	// TODO: catchpoint
	panic("unimplemented")
}

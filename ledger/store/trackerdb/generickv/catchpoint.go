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
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

type catchpoint struct{}

// MakeCatchpoint returns a trackerdb.Catchpoint for a KV
func MakeCatchpoint() trackerdb.Catchpoint {
	return &catchpoint{}
}

// MakeCatchpointReaderWriter implements trackerdb.Catchpoint
func (*catchpoint) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	panic("unimplemented")
}

// MakeCatchpointWriter implements trackerdb.Catchpoint
func (*catchpoint) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	panic("unimplemented")
}

// MakeMerkleCommitter implements trackerdb.Catchpoint
func (*catchpoint) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	panic("unimplemented")
}

// MakeOrderedAccountsIter implements trackerdb.Catchpoint
func (*catchpoint) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	panic("unimplemented")
}

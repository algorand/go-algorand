// Copyright (C) 2019-2021 Algorand, Inc.
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

package agreement

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

// A LedgerBranchReader is a LedgerReader specialized to a specific leafBranch.
type LedgerBranchReader struct {
	lr     LedgerReader
	branch bookkeeping.BlockHash
}

func LedgerWithoutBranch(lr LedgerReader) LedgerBranchReader {
	return LedgerBranchReader{
		lr: lr,
	}
}

func (lbr LedgerBranchReader) Seed(round basics.Round) (committee.Seed, error) {
	return lbr.lr.Seed(round, lbr.branch)
}

func (lbr LedgerBranchReader) ConsensusParams(round basics.Round) (config.ConsensusParams, error) {
	return lbr.lr.ConsensusParams(round, lbr.branch)
}

func (lbr LedgerBranchReader) ConsensusVersion(round basics.Round) (protocol.ConsensusVersion, error) {
	return lbr.lr.ConsensusVersion(round, lbr.branch)
}

func (lbr LedgerBranchReader) LookupDigest(round basics.Round) (crypto.Digest, error) {
	return lbr.lr.LookupDigest(round, lbr.branch)
}

func (lbr LedgerBranchReader) Lookup(round basics.Round, addr basics.Address) (basics.AccountData, error) {
	return lbr.lr.Lookup(round, lbr.branch, addr)
}

func (lbr LedgerBranchReader) Circulation(round basics.Round) (basics.MicroAlgos, error) {
	return lbr.lr.Circulation(round, lbr.branch)
}

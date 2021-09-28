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

package testing

import "github.com/algorand/go-algorand/data/transactions"

const maxNumProposalBytes = 30000       // sizeof(block header)
const maxNumTxGroupHashesBytes = 320000 // 10K * 32

// ProposalData contains the data of a proposal, just used for testing
type ProposalData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ProposalBytes []byte              `codec:"b,allocbound=maxNumProposalBytes"`
	TxGroupIds    []transactions.Txid `codec:"h,allocbound=maxNumTxGroupHashesBytes"` // TODO: make this []byte
}

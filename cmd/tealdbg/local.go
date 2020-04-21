// Copyright (C) 2019-2020 Algorand, Inc.
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

package main

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// RunLocal starts a local debugging session
func RunLocal(debugger *Debugger) error {
	proto := config.Consensus[protocol.ConsensusV23]
	ep := logic.EvalParams{
		Proto:    &proto,
		Debugger: debugger,
		Txn:      &transactions.SignedTxn{},
	}

	source := `int 0
int 1
+
`
	program, err := logic.AssembleStringV1(source)
	if err != nil {
		return err
	}
	_, err = logic.Eval(program, ep)
	if err != nil {
		return err
	}

	return nil
}

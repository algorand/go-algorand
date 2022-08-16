// Copyright (C) 2019-2022 Algorand, Inc.
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

package simulation

import (
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// ==============================
// > Simulator Debugger
// ==============================

type debuggerHook struct {
	result *SimulationResult
}

func makeDebuggerHook(txgroup []transactions.SignedTxn) debuggerHook {
	result := MakeSimulationResult([][]transactions.SignedTxn{txgroup})
	return debuggerHook{&result}
}

func (dh *debuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	// Set result ApplyData for this transaction
	dh.result.TxnGroups[0].Txns[groupIndex].Txn.ApplyData = ep.TxnGroup[groupIndex].ApplyData
	return nil
}

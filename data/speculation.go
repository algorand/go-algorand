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

package data

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

// A SpeculationLedger adapts a BlockEvaluator to the Ledger interface
// (and provides access to the BlockEvalutors ability to execute
// trasnactions) This means we code that expects a Ledger to report on
// balances and such as we go.

type SpeculationLedger struct {
	Evaluator *ledger.BlockEvaluator
	baseRound basics.Round
	Version   protocol.ConsensusVersion
}

func NewSpeculationLedger(l *Ledger, rnd basics.Round) (*SpeculationLedger, error) {
	hdr, err := l.BlockHdr(rnd)
	if err != nil {
		return nil, err
	}
	evaluator, err := l.StartEvaluator(hdr, 0)
	if err != nil {
		return nil, err
	}
	sl := &SpeculationLedger{Evaluator: evaluator, baseRound: rnd, Version: hdr.CurrentProtocol}
	return sl, nil
}

func (sl *SpeculationLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return sl.Evaluator.State().GetCreator(cidx, ctype)
}
func (sl *SpeculationLedger) Latest() basics.Round {
	return sl.baseRound // or +1 per group? The speculative txns are certainly not in the ledger's round.
}
func (sl *SpeculationLedger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	if rnd > sl.Latest() {
		return basics.AccountData{}, fmt.Errorf("trying to lookup in future round %d", rnd)
	}
	return sl.Evaluator.State().Get(addr, true)
}
func (sl *SpeculationLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	if rnd > sl.Latest() {
		return basics.AccountData{}, basics.Round(0), fmt.Errorf("trying to lookup in future round %d", rnd)
	}
	acct, err := sl.Evaluator.State().Get(addr, false)
	// Need to understand what the "validThrough" round returned here should mean
	return acct, basics.Round(0), err
}
func (sl *SpeculationLedger) Apply(txgroup []transactions.SignedTxn) error {
	return sl.Evaluator.TransactionGroup(txgroup)
}

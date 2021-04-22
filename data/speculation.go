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
	baseLedger  *Ledger
	baseRound   basics.Round
	txgroups    [][]transactions.SignedTxn
	Checkpoints []uint64

	Evaluator *ledger.BlockEvaluator
	Version   protocol.ConsensusVersion
}

func NewSpeculationLedger(l *Ledger, rnd basics.Round) (*SpeculationLedger, error) {
	sl := &SpeculationLedger{baseLedger: l, baseRound: rnd}
	err := sl.start()
	return sl, err
}

// Note that start() does not manipulate txgroups or checkpoints, so
// it can be used at construction time and during rollback.
func (sl *SpeculationLedger) start() error {
	hdr, err := sl.baseLedger.BlockHdr(sl.baseRound)
	if err != nil {
		return err
	}
	evaluator, err := sl.baseLedger.StartEvaluator(hdr, 0)
	if err != nil {
		return err
	}
	sl.Evaluator = evaluator
	sl.Version = hdr.CurrentProtocol
	return nil
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
	err := sl.Evaluator.TransactionGroup(txgroup)
	if err != nil {
		return err
	}
	sl.txgroups = append(sl.txgroups, txgroup)
	return nil
}

func (sl *SpeculationLedger) Checkpoint() error {
	sl.Checkpoints = append(sl.Checkpoints, uint64(len(sl.txgroups)))
	return nil
}
func (sl *SpeculationLedger) Rollback() error {
	// Start the evaluator over again from the beginning
	err := sl.start()
	if err != nil {
		return err
	}

	// Replay the txns up until the last checkpoint
	last := len(sl.Checkpoints) - 1
	replays := sl.txgroups[:sl.Checkpoints[last]]
	sl.txgroups = nil
	for _, txgroup := range replays {
		err := sl.Apply(txgroup)
		if err != nil {
			return err
		}
	}

	// Discard that checkpoint
	sl.Checkpoints = sl.Checkpoints[:last]
	return nil
}

func (sl *SpeculationLedger) Commit() error {
	last := len(sl.Checkpoints) - 1
	sl.Checkpoints = sl.Checkpoints[:last]
	return nil
}

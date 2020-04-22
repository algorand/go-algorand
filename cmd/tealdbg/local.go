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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func protoFromString(protoString string) (name string, proto config.ConsensusParams, err error) {
	if len(protoString) == 0 || protoString == "current" {
		name = string(protocol.ConsensusCurrentVersion)
		proto = config.Consensus[protocol.ConsensusCurrentVersion]
	} else {
		var ok bool
		proto, ok = config.Consensus[protocol.ConsensusVersion(protoString)]
		if !ok {
			err = fmt.Errorf("Unknown protocol %s", protoString)
			return
		}
		name = protoString
	}

	return
}

func txnGroupFromParams(dp *DebugParams) (txnGroup []transactions.SignedTxn, groupIndex int, err error) {
	if dp.TxnFile == "" {
		txnGroup = append(txnGroup, transactions.SignedTxn{})
		return
	}

	var data []byte
	data, err = ioutil.ReadFile(dp.TxnFile)
	if err != nil {
		return
	}

	// 1. Attempt json - a single transaction
	var txn transactions.SignedTxn
	err = json.Unmarshal(data, &txn)
	if err == nil {
		// groupIndex must be zero
		if dp.GroupIndex != 0 {
			err = fmt.Errorf("invalid group index %d for a single transaction", dp.GroupIndex)
			return
		}
		txnGroup = append(txnGroup, txn)
		groupIndex = 0
		return
	}

	// 2. Attempt json - array of transactions
	err = json.Unmarshal(data, &txnGroup)
	if err == nil {
		if dp.GroupIndex >= len(txnGroup) {
			err = fmt.Errorf("invalid group index %d for a txn transaction group of %d", dp.GroupIndex, len(txnGroup))
			return
		}
		groupIndex = dp.GroupIndex
		return
	}

	// 3. Attempt msgp - array of transactions
	dec := protocol.NewDecoderBytes(data)
	for {
		err = dec.Decode(&txn)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
		txnGroup = append(txnGroup, txn)
	}
	if err == nil {
		if dp.GroupIndex >= len(txnGroup) {
			err = fmt.Errorf("invalid group index %d for a txn transaction group of %d", dp.GroupIndex, len(txnGroup))
			return
		}
		groupIndex = dp.GroupIndex
		return
	}

	return
}

type debugLedger struct {
	round int
}

func (l *debugLedger) Balance(addr basics.Address) (basics.MicroAlgos, error) {
	return basics.MicroAlgos{Raw: 0}, nil
}
func (l *debugLedger) Round() basics.Round {
	return basics.Round(l.round)
}
func (l *debugLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	return nil, nil
}
func (l *debugLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	return nil, nil

}
func (l *debugLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	return basics.AssetHolding{}, nil

}
func (l *debugLedger) AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetParams, error) {
	return basics.AssetParams{}, nil
}

// RunLocal starts a local debugging session
func RunLocal(debugger *Debugger, dp *DebugParams) (err error) {
	protoName, proto, err := protoFromString(dp.Proto)
	if err != nil {
		return
	}
	log.Printf("Using proto: %s", protoName)

	txnGroup, groupIndex, err := txnGroupFromParams(dp)
	if err != nil {
		return
	}

	ledger := debugLedger{
		round: dp.Round,
	}
	ep := logic.EvalParams{
		Proto:      &proto,
		Debugger:   debugger,
		Txn:        &txnGroup[groupIndex],
		TxnGroup:   txnGroup,
		GroupIndex: groupIndex,
		Ledger:     &ledger,
	}

	for _, data := range dp.ProgramBlobs {
		var program []byte = data
		if IsTextFile(data) {
			program, err = logic.AssembleStringWithVersion(string(data), proto.LogicSigVersion)
			if err != nil {
				return err
			}
		}

		switch dp.RunMode {
		case "signature":
			_, err = logic.Eval(program, ep)
		case "application":
			_, _, err = logic.EvalStateful(program, ep)
		default:
			err = fmt.Errorf("unknown run mode")
			return
		}
		if err != nil {
			return err
		}
	}

	return nil
}

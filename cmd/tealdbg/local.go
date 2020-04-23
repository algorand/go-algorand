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
	"fmt"
	"io"
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

// txnGroupFromParams validates DebugParams.TxnBlob and DebugParams.GroupIndex.
// DebugParams.TxnBlob parsed as JSON object, JSON array or MessagePack array of transactions.SignedTxn.
// The function returns ready to use txnGroup and groupIndex, or error
func txnGroupFromParams(dp *DebugParams) (txnGroup []transactions.SignedTxn, groupIndex int, err error) {
	if len(dp.TxnBlob) == 0 {
		txnGroup = append(txnGroup, transactions.SignedTxn{})
		return
	}

	var data []byte = dp.TxnBlob

	// 1. Attempt json - a single transaction
	var txn transactions.SignedTxn
	err = protocol.DecodeJSON(data, &txn)
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
	err = protocol.DecodeJSON(data, &txnGroup)
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

// balanceRecordsFromParams attempts to parse DebugParams.BalanceBlob as
// JSON object, JSON array or MessagePack array of basics.BalanceRecord
func balanceRecordsFromParams(dp *DebugParams) (records []basics.BalanceRecord, err error) {
	if len(dp.BalanceBlob) == 0 {
		return
	}

	var data []byte = dp.BalanceBlob

	// 1. Attempt json - a single record
	var record basics.BalanceRecord
	err = protocol.DecodeJSON(data, &record)
	if err == nil {
		records = append(records, record)
		return
	}

	// 2. Attempt json - a array of records
	err = protocol.DecodeJSON(data, &records)
	if err == nil {
		return
	}

	// 2. Attempt msgp - a array of records
	dec := protocol.NewDecoderBytes(data)
	for {
		err = dec.Decode(&record)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
		records = append(records, record)
	}

	return
}

type debugLedger struct {
	round    int
	balances map[basics.Address]basics.AccountData
}

func (l *debugLedger) Balance(addr basics.Address) (basics.MicroAlgos, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.MicroAlgos{}, fmt.Errorf("no such address %s", addr.String())
	}
	return br.MicroAlgos, nil
}

func (l *debugLedger) Round() basics.Round {
	return basics.Round(l.round)
}

func (l *debugLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	var ap basics.AppParams
	for _, br := range l.balances {
		var ok bool
		ap, ok = br.AppParams[appIdx]
		if ok {
			return ap.GlobalState, nil
		}

	}
	return basics.TealKeyValue{}, fmt.Errorf("no such application %d", appIdx)
}

func (l *debugLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.TealKeyValue{}, fmt.Errorf("no such address %s", addr.String())
	}
	ls, ok := br.AppLocalStates[appIdx]
	if !ok {
		return basics.TealKeyValue{}, fmt.Errorf("no local state for application %d", appIdx)
	}
	return ls.KeyValue, nil
}

func (l *debugLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.AssetHolding{}, fmt.Errorf("no such address %s", addr.String())
	}
	ah, ok := br.Assets[assetIdx]
	if !ok {
		return basics.AssetHolding{}, fmt.Errorf("no such asset %d", assetIdx)
	}
	return ah, nil
}

func (l *debugLedger) AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetParams, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no such address %s", addr.String())
	}
	ap, ok := br.AssetParams[assetIdx]
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no such asset %d", assetIdx)
	}
	return ap, nil
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

	records, err := balanceRecordsFromParams(dp)
	if err != nil {
		return
	}

	balances := make(map[basics.Address]basics.AccountData)
	for _, record := range records {
		balances[record.Addr] = record.AccountData
	}

	ledger := debugLedger{
		round:    dp.Round,
		balances: balances,
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

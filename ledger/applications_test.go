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

package ledger

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func commitRound(offset uint64, dbRound basics.Round, l *Ledger) {
	l.trackers.mu.Lock()
	l.trackers.lastFlushTime = time.Time{}
	l.trackers.mu.Unlock()

	l.trackers.scheduleCommit(l.Latest(), l.Latest()-(dbRound+basics.Round(offset)))
	// wait for the operation to complete. Once it does complete, the tr.lastFlushTime is going to be updated, so we can
	// use that as an indicator.
	for {
		l.trackers.mu.Lock()
		isDone := (!l.trackers.lastFlushTime.IsZero()) && (len(l.trackers.deferredCommits) == 0)
		l.trackers.mu.Unlock()
		if isDone {
			break
		}
		time.Sleep(time.Millisecond)

	}
}

// test ensures that
// 1) app's GlobalState and local state's KeyValue are stored in the same way
// before and after application code refactoring
// 2) writing into empty (opted-in) local state's KeyValue works after reloading
// Hardcoded values are from commit 9a0b439 (pre app refactor commit)

func TestAppAccountDataStorage(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	source := `#pragma version 2
// do not write local key on opt in or on app create
txn ApplicationID
int 0
==
bnz success
txn OnCompletion
int NoOp
==
bnz writetostate
txn OnCompletion
int OptIn
==
bnz checkargs
int 0
return
checkargs:
// if no args the success
// otherwise write data
txn NumAppArgs
int 0
==
bnz success
// write local or global key depending on arg1
writetostate:
txna ApplicationArgs 0
byte "local"
==
bnz writelocal
txna ApplicationArgs 0
byte "global"
==
bnz writeglobal
int 0
return
writelocal:
int 0
byte "lk"
byte "local"
app_local_put
b success
writeglobal:
byte "gk"
byte "global"
app_global_put
success:
int 1
return`

	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userOptin, err := basics.UnmarshalChecksumAddress("6S6UMUQ4462XRGNON5GKBHW55RUJGJ5INIRDFVFD6KSPHGWGRKPC6RK2O4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)
	userLocal2, err := basics.UnmarshalChecksumAddress("XNOGOJECWDOMVENCDJHNMOYVV7PIVIJXRWTSZUA3GSKYTVXH3VVGOXP7CU")
	a.NoError(err)

	a.Contains(genesisInitState.Accounts, creator)
	a.Contains(genesisInitState.Accounts, userOptin)
	a.Contains(genesisInitState.Accounts, userLocal)
	a.Contains(genesisInitState.Accounts, userLocal2)

	expectedCreator, err := hex.DecodeString("84a4616c676fce009d2290a461707070810184a6617070726f76c45602200200012604056c6f63616c06676c6f62616c026c6b02676b3118221240003331192212400010311923124000022243311b221240001c361a00281240000a361a0029124000092243222a28664200032b29672343a6636c65617270c40102a46773636881a36e627304a46c73636881a36e627301a36f6e6c01a47473636881a36e627304")
	a.NoError(err)
	expectedUserOptIn, err := hex.DecodeString("84a4616c676fce00a02fd0a46170706c810181a46873636881a36e627301a36f6e6c01a47473636881a36e627301")
	a.NoError(err)
	expectedUserLocal, err := hex.DecodeString("84a4616c676fce00a33540a46170706c810182a46873636881a36e627301a3746b7681a26c6b82a27462a56c6f63616ca2747401a36f6e6c01a47473636881a36e627301")
	a.NoError(err)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), "TestAppAccountData", true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: genesisInitState.GenesisHash,
	}

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x02") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 4},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 1},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: 1})
	a.NoError(err)

	appIdx := basics.AppIndex(1) // first tnx => idx = 1

	// opt-in, do no write
	txHeader.Sender = userOptin
	appCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.OptInOC,
		ApplicationID: appIdx,
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

	// opt-in + write
	txHeader.Sender = userLocal
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

	// save data into DB and write into local state
	commitRound(3, 0, l)

	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    0,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("local")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "local"}}}},
		})
	a.NoError(err)

	// save data into DB
	commitRound(1, 3, l)

	// dump accounts
	var rowid int64
	var dbRound basics.Round
	var buf []byte
	err = l.accts.accountsq.lookupStmt.QueryRow(creator[:]).Scan(&rowid, &dbRound, &buf)
	a.NoError(err)
	a.Equal(basics.Round(4), dbRound)
	a.Equal(expectedCreator, buf)

	err = l.accts.accountsq.lookupStmt.QueryRow(userOptin[:]).Scan(&rowid, &dbRound, &buf)
	a.NoError(err)
	a.Equal(basics.Round(4), dbRound)
	a.Equal(expectedUserOptIn, buf)
	pad, err := l.accts.accountsq.lookup(userOptin)
	a.NoError(err)
	a.Nil(pad.accountData.AppLocalStates[appIdx].KeyValue)
	ad, err := l.Lookup(dbRound, userOptin)
	a.NoError(err)
	a.Nil(ad.AppLocalStates[appIdx].KeyValue)

	err = l.accts.accountsq.lookupStmt.QueryRow(userLocal[:]).Scan(&rowid, &dbRound, &buf)
	a.NoError(err)
	a.Equal(basics.Round(4), dbRound)
	a.Equal(expectedUserLocal, buf)

	ad, err = l.Lookup(dbRound, userLocal)
	a.NoError(err)
	a.Equal("local", ad.AppLocalStates[appIdx].KeyValue["lk"].Bytes)

	// ensure writing into empty global state works as well
	l.reloadLedger()
	txHeader.Sender = creator
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    0,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("global")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: transactions.EvalDelta{
			GlobalDelta: basics.StateDelta{"gk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "global"}}},
		})
	a.NoError(err)

	// opt-in + write by during opt-in
	txHeader.Sender = userLocal2
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    transactions.OptInOC,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("local")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "local"}}}},
		})
	a.NoError(err)
}

func TestAppAccountDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	source := `#pragma version 2
txn ApplicationID
int 0
==
bnz success
// if no args then write local
// otherwise check args and write local or global
txn NumAppArgs
int 0
==
bnz writelocal
txna ApplicationArgs 0
byte "local"
==
bnz writelocal
txna ApplicationArgs 0
byte "local1"
==
bnz writelocal1
txna ApplicationArgs 0
byte "global"
==
bnz writeglobal
int 0
return
writelocal:
int 0
byte "lk"
byte "local"
app_local_put
b success
writelocal1:
int 0
byte "lk1"
byte "local1"
app_local_put
b success
writeglobal:
byte "gk"
byte "global"
app_global_put
success:
int 1
return`

	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)

	a.Contains(genesisInitState.Accounts, creator)
	a.Contains(genesisInitState.Accounts, userLocal)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	genesisID := t.Name()
	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x02") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 4},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 2},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: 1})
	a.NoError(err)

	appIdx := basics.AppIndex(1) // first tnx => idx = 1

	// opt-in, write to local
	txHeader.Sender = userLocal
	appCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.OptInOC,
		ApplicationID: appIdx,
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{
		EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk": basics.ValueDelta{
				Action: basics.SetBytesAction,
				Bytes:  "local",
			}}},
		},
	})
	a.NoError(err)

	txHeader.Sender = userLocal
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.NoOpOC,
		ApplicationID: appIdx,
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

	// save data into DB and write into local state
	commitRound(3, 0, l)

	// check first write
	blk, err := l.Block(2)
	a.NoError(err)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas, uint64(0))
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[0], "lk")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[0]["lk"].Bytes, "local")
	expectedAD := transactions.ApplyData{}
	dec, err := hex.DecodeString("81a2647481a26c64810081a26c6b82a2617401a26273a56c6f63616c")
	a.NoError(err)
	err = protocol.Decode(dec, &expectedAD)
	a.NoError(err)
	a.Equal(expectedAD, blk.Payset[0].ApplyData)

	// check repeated write
	blk, err = l.Block(3)
	a.NoError(err)
	a.Empty(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas)
	expectedAD = transactions.ApplyData{}
	dec, err = hex.DecodeString("80")
	a.NoError(err)
	err = protocol.Decode(dec, &expectedAD)
	a.NoError(err)
	a.Equal(expectedAD, blk.Payset[0].ApplyData)

	txHeader.Sender = creator
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    transactions.NoOpOC,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("global")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: transactions.EvalDelta{
			GlobalDelta: basics.StateDelta{"gk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "global"}}},
		})
	a.NoError(err)

	// repeat writing into global state
	txHeader.Lease = [32]byte{1}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

	// save data into DB
	commitRound(2, 3, l)

	// check first write
	blk, err = l.Block(4)
	a.NoError(err)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta, "gk")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta["gk"].Bytes, "global")
	expectedAD = transactions.ApplyData{}
	dec, err = hex.DecodeString("81a2647481a2676481a2676b82a2617401a26273a6676c6f62616c")
	a.NoError(err)
	err = protocol.Decode(dec, &expectedAD)
	a.NoError(err)
	a.Equal(expectedAD, blk.Payset[0].ApplyData)

	// check repeated write
	blk, err = l.Block(5)
	a.NoError(err)
	a.NotContains(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta, "gk")
	expectedAD = transactions.ApplyData{}
	dec, err = hex.DecodeString("80")
	a.NoError(err)
	err = protocol.Decode(dec, &expectedAD)
	a.NoError(err)
	a.Equal(expectedAD, blk.Payset[0].ApplyData)

	// check same key update in the same block
	txHeader.Sender = userLocal
	txHeader.Lease = [32]byte{2}
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    transactions.NoOpOC,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("local1")},
	}
	appCall1 := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}

	txHeader.Lease = [32]byte{3}
	appCall2 := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}

	stx1 := sign(initKeys, appCall1)
	stx2 := sign(initKeys, appCall2)

	blk = makeNewEmptyBlock(t, l, genesisID, genesisInitState.Accounts)
	ad1 := transactions.ApplyData{
		EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk1": basics.ValueDelta{
				Action: basics.SetBytesAction,
				Bytes:  "local1",
			}}},
		},
	}
	txib1, err := blk.EncodeSignedTxn(stx1, ad1)
	a.NoError(err)
	txib2, err := blk.EncodeSignedTxn(stx2, transactions.ApplyData{})
	a.NoError(err)
	blk.TxnCounter = blk.TxnCounter + 2
	blk.Payset = append(blk.Payset, txib1, txib2)
	blk.TxnRoot, err = blk.PaysetCommit()
	a.NoError(err)
	err = l.appendUnvalidated(blk)
	a.NoError(err)

	// first txn has delta
	blk, err = l.Block(6)
	a.NoError(err)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas, uint64(0))
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[0], "lk1")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[0]["lk1"].Bytes, "local1")
	expectedAD = transactions.ApplyData{}
	dec, err = hex.DecodeString("81a2647481a26c64810081a36c6b3182a2617401a26273a66c6f63616c31")
	a.NoError(err)
	err = protocol.Decode(dec, &expectedAD)
	a.NoError(err)
	a.Equal(expectedAD, blk.Payset[0].ApplyData)

	// second txn does not have delta (same key/value update)
	a.Empty(blk.Payset[1].ApplyData.EvalDelta.LocalDeltas)
	a.Equal(transactions.ApplyData{}, blk.Payset[1].ApplyData)
}

func TestAppEmptyAccountsLocal(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	source := `#pragma version 2
txn ApplicationID
int 0
==
bnz success
int 0
byte "lk"
byte "local"
app_local_put
success:
int 1
return`

	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)

	a.Contains(genesisInitState.Accounts, creator)
	a.Contains(genesisInitState.Accounts, userLocal)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	genesisID := t.Name()
	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x02") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 4},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 2},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: 1})
	a.NoError(err)

	appIdx := basics.AppIndex(1) // first tnx => idx = 1

	// opt-in, write to local
	txHeader.Sender = userLocal
	appCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.OptInOC,
		ApplicationID: appIdx,
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, nil, initKeys, appCall, transactions.ApplyData{
		EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk": basics.ValueDelta{
				Action: basics.SetBytesAction,
				Bytes:  "local",
			}}},
		},
	})
	a.NoError(err)

	// close out
	txHeader.Sender = userLocal
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.CloseOutOC,
		ApplicationID: appIdx,
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	paymentFields := transactions.PaymentTxnFields{
		Amount:           basics.MicroAlgos{Raw: 0},
		Receiver:         creator,
		CloseRemainderTo: creator,
	}
	payment := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           txHeader,
		PaymentTxnFields: paymentFields,
	}

	data := genesisInitState.Accounts[userLocal]
	balance := basics.MicroAlgos{Raw: data.MicroAlgos.Raw - txHeader.Fee.Raw*3}
	stx1 := sign(initKeys, appCall)
	stx2 := sign(initKeys, payment)

	blk := makeNewEmptyBlock(t, l, genesisID, genesisInitState.Accounts)
	txib1, err := blk.EncodeSignedTxn(stx1, transactions.ApplyData{})
	a.NoError(err)
	txib2, err := blk.EncodeSignedTxn(stx2, transactions.ApplyData{ClosingAmount: balance})
	a.NoError(err)
	blk.TxnCounter = blk.TxnCounter + 2
	blk.Payset = append(blk.Payset, txib1, txib2)
	blk.TxnRoot, err = blk.PaysetCommit()
	a.NoError(err)
	err = l.appendUnvalidated(blk)
	a.NoError(err)

	l.WaitForCommit(3)

	// save data into DB and write into local state
	commitRound(3, 0, l)

	// check first write
	blk, err = l.Block(2)
	a.NoError(err)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas, uint64(0))
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[0], "lk")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[0]["lk"].Bytes, "local")

	// check close out
	blk, err = l.Block(3)
	a.NoError(err)
	a.Empty(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas)

	pad, err := l.accts.accountsq.lookup(userLocal)
	a.NoError(err)
	a.Equal(basics.AccountData{}, pad.accountData)
	a.Zero(pad.rowid)
}

func TestAppEmptyAccountsGlobal(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	source := `#pragma version 2
txn ApplicationID
int 0
==
bnz success
byte "gk"
byte "global"
app_global_put
success:
int 1
return`

	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)

	a.Contains(genesisInitState.Accounts, creator)
	a.Contains(genesisInitState.Accounts, userLocal)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	genesisID := t.Name()
	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x02") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 4},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 2},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: 1})
	a.NoError(err)

	appIdx := basics.AppIndex(1) // first tnx => idx = 1

	// destoy the app
	txHeader.Sender = creator
	appCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.DeleteApplicationOC,
		ApplicationID: appIdx,
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	paymentFields := transactions.PaymentTxnFields{
		Amount:           basics.MicroAlgos{Raw: 0},
		Receiver:         userLocal,
		CloseRemainderTo: userLocal,
	}
	payment := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           txHeader,
		PaymentTxnFields: paymentFields,
	}

	data := genesisInitState.Accounts[creator]
	balance := basics.MicroAlgos{Raw: data.MicroAlgos.Raw - txHeader.Fee.Raw*3}
	stx1 := sign(initKeys, appCall)
	stx2 := sign(initKeys, payment)

	blk := makeNewEmptyBlock(t, l, genesisID, genesisInitState.Accounts)
	txib1, err := blk.EncodeSignedTxn(stx1, transactions.ApplyData{EvalDelta: transactions.EvalDelta{
		GlobalDelta: basics.StateDelta{
			"gk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "global"},
		}},
	})
	a.NoError(err)
	txib2, err := blk.EncodeSignedTxn(stx2, transactions.ApplyData{ClosingAmount: balance})
	a.NoError(err)
	blk.TxnCounter = blk.TxnCounter + 2
	blk.Payset = append(blk.Payset, txib1, txib2)
	blk.TxnRoot, err = blk.PaysetCommit()
	a.NoError(err)
	err = l.appendUnvalidated(blk)
	a.NoError(err)

	// save data into DB and write into local state
	commitRound(2, 0, l)

	// check first write
	blk, err = l.Block(1)
	a.NoError(err)
	a.Nil(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas)
	a.Nil(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta)

	// check deletion out
	blk, err = l.Block(2)
	a.NoError(err)
	a.Nil(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta, "gk")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta["gk"].Bytes, "global")

	pad, err := l.accts.accountsq.lookup(creator)
	a.NoError(err)
	a.Equal(basics.AccountData{}, pad.accountData)
	a.Zero(pad.rowid)
}

func TestAppAccountDeltaIndicesCompatibility1(t *testing.T) {
	partitiontest.PartitionTest(t)

	source := `#pragma version 2
txn ApplicationID
int 0
==
bnz success
int 0
byte "lk0"
byte "local0"
app_local_put
int 1
byte "lk1"
byte "local1"
app_local_put
success:
int 1
`
	// put into sender account as idx 0, expect 0
	testAppAccountDeltaIndicesCompatibility(t, source, 0)
}

func TestAppAccountDeltaIndicesCompatibility2(t *testing.T) {
	partitiontest.PartitionTest(t)

	source := `#pragma version 2
txn ApplicationID
int 0
==
bnz success
int 1
byte "lk1"
byte "local1"
app_local_put
int 0
byte "lk0"
byte "local0"
app_local_put
success:
int 1
`
	// put into sender account as idx 1, expect 1
	testAppAccountDeltaIndicesCompatibility(t, source, 1)
}

func TestAppAccountDeltaIndicesCompatibility3(t *testing.T) {
	partitiontest.PartitionTest(t)

	source := `#pragma version 2
txn ApplicationID
int 0
==
bnz success
int 1
byte "lk"
app_local_get
pop
int 0
byte "lk0"
byte "local0"
app_local_put
int 1
byte "lk1"
byte "local1"
app_local_put
success:
int 1
`
	// get sender account as idx 1 but put into sender account as idx 0, expect 1
	testAppAccountDeltaIndicesCompatibility(t, source, 1)
}

func testAppAccountDeltaIndicesCompatibility(t *testing.T, source string, accountIdx uint64) {
	a := require.New(t)
	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	// explicitly trigger compatibility mode
	proto := config.Consensus[protocol.ConsensusV24]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusV24, 100)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)

	a.Contains(genesisInitState.Accounts, creator)
	a.Contains(genesisInitState.Accounts, userLocal)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	genesisID := t.Name()
	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x02") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 4},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 2},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{})
	a.NoError(err)

	appIdx := basics.AppIndex(1) // first tnx => idx = 1

	// opt-in
	txHeader.Sender = userLocal
	appCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.OptInOC,
		ApplicationID: appIdx,
		Accounts:      []basics.Address{userLocal},
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{
		EvalDelta: transactions.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{
				accountIdx: {
					"lk0": basics.ValueDelta{
						Action: basics.SetBytesAction,
						Bytes:  "local0",
					},
					"lk1": basics.ValueDelta{
						Action: basics.SetBytesAction,
						Bytes:  "local1"},
				},
			},
		},
	})
	a.NoError(err)

	// save data into DB and write into local state
	commitRound(2, 0, l)

	// check first write
	blk, err := l.Block(2)
	a.NoError(err)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas, accountIdx)
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[accountIdx], "lk0")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[accountIdx]["lk0"].Bytes, "local0")
	a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[accountIdx], "lk1")
	a.Equal(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[accountIdx]["lk1"].Bytes, "local1")
}

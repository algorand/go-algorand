// Copyright (C) 2019-2023 Algorand, Inc.
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
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// commitRound schedules a commit for known offset and dbRound
// and waits for completion
func commitRound(offset uint64, dbRound basics.Round, l *Ledger) {
	commitRoundLookback(l.Latest().SubSaturate(dbRound+basics.Round(offset)), l)
}

func commitRoundLookback(lookback basics.Round, l *Ledger) {
	l.trackers.mu.Lock()
	l.trackers.lastFlushTime = time.Time{}
	l.trackers.mu.Unlock()

	l.trackers.scheduleCommit(l.Latest(), lookback)
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
// Hardcoded values were manually converted to new acctbase format during separation resources data from base account data
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

	var expectedCreatorBase, expectedCreatorResource, expectedUserOptInBase, expectedUserOptInResource, expectedUserLocalBase, expectedUserLocalResource []byte
	// the difference between these encoded structure is the UpdateRound variable. This variable is not being set before
	// the consensus upgrade, and affects only nodes that have been updated.
	if proto.EnableAccountDataResourceSeparation {
		expectedCreatorBase, err = hex.DecodeString("87a14301a144ce000186a0a16101a162ce009d2290a16704a16b01a17a01")
		a.NoError(err)
		expectedCreatorResource, err = hex.DecodeString("86a171c45602200200012604056c6f63616c06676c6f62616c026c6b02676b3118221240003331192212400010311923124000022243311b221240001c361a00281240000a361a0029124000092243222a28664200032b29672343a172c40102a17501a17704a17903a17a01")
		a.NoError(err)
		expectedUserOptInBase, err = hex.DecodeString("87a14301a144ce000186a0a16101a162ce00a02fd0a16701a16c01a17a02")
		a.NoError(err)
		expectedUserOptInResource, err = hex.DecodeString("82a16f01a17a02")
		a.NoError(err)
		expectedUserLocalBase, err = hex.DecodeString("87a14301a144ce000186a0a16101a162ce00a33540a16701a16c01a17a04")
		a.NoError(err)
		expectedUserLocalResource, err = hex.DecodeString("83a16f01a17081a26c6b82a27462a56c6f63616ca2747401a17a04")
		a.NoError(err)
	} else {
		expectedCreatorBase, err = hex.DecodeString("84a16101a162ce009d2290a16704a16b01")
		a.NoError(err)
		expectedCreatorResource, err = hex.DecodeString("85a171c45602200200012604056c6f63616c06676c6f62616c026c6b02676b3118221240003331192212400010311923124000022243311b221240001c361a00281240000a361a0029124000092243222a28664200032b29672343a172c40102a17501a17704a17903")
		a.NoError(err)
		expectedUserOptInBase, err = hex.DecodeString("84a16101a162ce00a02fd0a16701a16c01")
		a.NoError(err)
		expectedUserOptInResource, err = hex.DecodeString("81a16f01")
		a.NoError(err)
		expectedUserLocalBase, err = hex.DecodeString("84a16101a162ce00a33540a16701a16c01")
		a.NoError(err)
		expectedUserLocalResource, err = hex.DecodeString("82a16f01a17081a26c6b82a27462a56c6f63616ca2747401")
		a.NoError(err)
	}

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
	appIdx := basics.AppIndex(1001) // first tnx => idx = 1001
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: appIdx})
	a.NoError(err)

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
	entryAcc, err := l.accts.accountsq.LookupAccount(creator)
	a.NoError(err)
	a.Equal(basics.Round(4), entryAcc.Round)
	a.Equal(expectedCreatorBase, protocol.Encode(&entryAcc.AccountData))
	entryRes, err := l.accts.accountsq.LookupResources(creator, basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.Equal(basics.Round(4), entryRes.Round)
	a.Equal(expectedCreatorResource, protocol.Encode(&entryRes.Data))

	entryAcc, err = l.accts.accountsq.LookupAccount(userOptin)
	a.NoError(err)
	a.Equal(basics.Round(4), entryAcc.Round)
	a.Equal(expectedUserOptInBase, protocol.Encode(&entryAcc.AccountData))
	entryRes, err = l.accts.accountsq.LookupResources(userOptin, basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.Equal(basics.Round(4), entryRes.Round)
	a.Equal(expectedUserOptInResource, protocol.Encode(&entryRes.Data))

	pad, err := l.accts.accountsq.LookupAccount(userOptin)
	a.NoError(err)
	a.NotEmpty(pad)
	prd, err := l.accts.accountsq.LookupResources(userOptin, basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.Nil(prd.Data.GetAppLocalState().KeyValue)
	ad, rnd, _, err := l.LookupLatest(userOptin)
	a.Equal(basics.Round(4), rnd)
	a.NoError(err)
	a.Nil(ad.AppLocalStates[appIdx].KeyValue)

	entryAcc, err = l.accts.accountsq.LookupAccount(userLocal)
	a.NoError(err)
	a.Equal(basics.Round(4), entryAcc.Round)
	a.Equal(expectedUserLocalBase, protocol.Encode(&entryAcc.AccountData))
	entryRes, err = l.accts.accountsq.LookupResources(userLocal, basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.Equal(basics.Round(4), entryRes.Round)
	a.Equal(expectedUserLocalResource, protocol.Encode(&entryRes.Data))

	ar, err := l.LookupApplication(basics.Round(4), userLocal, appIdx)
	a.NoError(err)
	a.Equal("local", ar.AppLocalState.KeyValue["lk"].Bytes)

	// ensure writing into empty global state works as well
	err = l.reloadLedger()
	a.NoError(err)
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
	appIdx := basics.AppIndex(1001) // first txn => idx = 1001 since AppForbidLowResources sets tx counter to 1000
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: appIdx})
	a.NoError(err)

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
	blk.TxnCommitments, err = blk.PaysetCommit()
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
	appIdx := basics.AppIndex(1001) // first tnx => idx = 1001
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: appIdx})
	a.NoError(err)

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
	blk.TxnCommitments, err = blk.PaysetCommit()
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

	pad, err := l.accts.accountsq.LookupAccount(userLocal)
	a.NoError(err)
	a.Equal(trackerdb.BaseAccountData{}, pad.AccountData)
	a.Nil(pad.Ref)
	prd, err := l.accts.accountsq.LookupResources(userLocal, basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.Nil(prd.AcctRef)
	emptyResourceData := trackerdb.MakeResourcesData(0)
	a.Equal(emptyResourceData, prd.Data)
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
	appIdx := basics.AppIndex(1001) // first tnx => idx = 1001
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: appIdx})
	a.NoError(err)

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
	blk.TxnCommitments, err = blk.PaysetCommit()
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

	pad, err := l.accts.accountsq.LookupAccount(creator)
	a.NoError(err)
	a.Empty(pad.AccountData)
	a.Nil(pad.Ref)
	prd, err := l.accts.accountsq.LookupResources(creator, basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.Nil(prd.AcctRef)
	emptyResourceData := trackerdb.MakeResourcesData(0)
	a.Equal(emptyResourceData, prd.Data)
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

// TestParitalDeltaWrites checks account data consistency when app global state or app local state
// accessed in a block where app creator and local user do not have any state changes expect app storage
// Block 1: create app
// Block 2: opt in
// Block 3: write to global state (goes into creator's AD), write to local state of txn.Account[1] (not a txn sender)
// In this case StateDelta will not have base record modification, only storage
func TestParitalDeltaWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	source := `#pragma version 2
// app create is no-op
txn ApplicationID
int 0
==
bnz success
// opt-in is no-op
txn OnCompletion
int OptIn
==
bnz success
// a regular call:
// write into global
// write into txn.Accounts[1] local
byte "gk"
byte "global"
app_global_put
int 1
byte "lk"
byte "local"
app_local_put
success:
int 1
`

	a := require.New(t)
	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userOptin, err := basics.UnmarshalChecksumAddress("6S6UMUQ4462XRGNON5GKBHW55RUJGJ5INIRDFVFD6KSPHGWGRKPC6RK2O4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)

	var tests = []struct {
		name           string
		separateBlocks bool
	}{
		{"commit-each-block", true},
		{"commit-bulk", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
			a.Contains(genesisInitState.Accounts, creator)
			a.Contains(genesisInitState.Accounts, userOptin)
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
			appIdx := basics.AppIndex(1001) // first tnx => idx = 1001

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
			err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: appIdx})
			a.NoError(err)

			if test.separateBlocks {
				commitRound(1, 0, l)
			}

			// opt-in
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

			if test.separateBlocks {
				commitRound(1, 1, l)
			}

			// run state write transaction
			txHeader.Sender = userLocal
			appCallFields = transactions.ApplicationCallTxnFields{
				ApplicationID: appIdx,
				Accounts:      []basics.Address{userOptin},
			}
			appCall = transactions.Transaction{
				Type:                     protocol.ApplicationCallTx,
				Header:                   txHeader,
				ApplicationCallTxnFields: appCallFields,
			}
			err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{
				EvalDelta: transactions.EvalDelta{
					GlobalDelta: basics.StateDelta{
						"gk": basics.ValueDelta{
							Action: basics.SetBytesAction,
							Bytes:  "global",
						},
					},
					LocalDeltas: map[uint64]basics.StateDelta{
						1: {
							"lk": basics.ValueDelta{
								Action: basics.SetBytesAction,
								Bytes:  "local",
							},
						},
					},
				},
			})
			a.NoError(err)

			if test.separateBlocks {
				commitRound(1, 2, l)
			} else {
				commitRound(3, 0, l)
			}

			// check first write
			blk, err := l.Block(3)
			a.NoError(err)
			a.Contains(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta, "gk")
			a.Equal(blk.Payset[0].ApplyData.EvalDelta.GlobalDelta["gk"].Bytes, "global")
			a.Contains(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[1], "lk")
			a.Equal(blk.Payset[0].ApplyData.EvalDelta.LocalDeltas[1]["lk"].Bytes, "local")
		})
	}
}

// TestLogicSigValidation tests that LogicSig-signed transactions can be validated properly.
func TestLogicSigValidation(t *testing.T) {
	partitiontest.PartitionTest(t)

	source := `#pragma version 6
int 1
`

	a := require.New(t)
	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program
	pd := logic.HashProgram(program)
	lsigAddr := basics.Address(pd)

	funder, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	a.Contains(genesisInitState.Accounts, funder)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	genesisID := t.Name()
	txHeader := transactions.Header{
		Sender:      funder,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	// fund lsig account
	fundingPayment := transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: txHeader,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: lsigAddr,
			Amount:   basics.MicroAlgos{Raw: proto.MinBalance + proto.MinTxnFee},
		},
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, fundingPayment, transactions.ApplyData{})
	a.NoError(err)

	// send 0 Algos from lsig account to self
	txHeader.Sender = lsigAddr
	lsigPayment := transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: txHeader,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: lsigAddr,
		},
	}
	signedLsigPayment := transactions.SignedTxn{
		Lsig: transactions.LogicSig{Logic: program},
		Txn:  lsigPayment,
	}
	err = l.appendUnvalidatedSignedTx(t, genesisInitState.Accounts, signedLsigPayment, transactions.ApplyData{})
	a.NoError(err)
}

func TestAppEmptyBox(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	source := `#pragma version 8
txn ApplicationID
int 0
==
bnz create_box
// otherwise delete the box
byte "boxname"
box_del
return

create_box:
byte "boxname"
int 0
box_create
return
`

	ops, err := logic.AssembleString(source)
	a.NoError(err, ops.Errors)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	proto := config.Consensus[protocol.ConsensusFuture]
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusFuture, 1000000)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	a.Contains(genesisInitState.Accounts, creator)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	dbPrefix := filepath.Join(t.TempDir(), dbName)

	cfg := config.GetDefaultLocal()
	cfg.MaxAcctLookback = 2
	l1, err := OpenLedger(logging.Base(), dbPrefix, false, genesisInitState, cfg)
	a.NoError(err)
	defer l1.Close()

	genesisID := t.Name()
	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l1.Latest() + 1,
		LastValid:   l1.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	appIdx := basics.AppIndex(1002) // second tnx => idx = 1002

	// fund app account
	fundingPayment := transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: txHeader,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: appIdx.Address(),
			Amount:   basics.MicroAlgos{Raw: 100*proto.MinBalance + proto.MinTxnFee},
		},
	}
	err = l1.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, fundingPayment, transactions.ApplyData{})
	a.NoError(err)

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x08") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 0},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 0},
		Boxes:             []transactions.BoxRef{{Name: []byte("boxname")}},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l1.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{ApplicationID: appIdx})
	a.NoError(err)

	// few empty blocks to reset deltas and flush
	for i := 0; i < 10; i++ {
		blk := makeNewEmptyBlock(t, l1, genesisID, genesisInitState.Accounts)
		l1.AddBlock(blk, agreement.Certificate{})
	}

	app, err := l1.LookupApplication(l1.Latest(), creator, appIdx)
	a.NoError(err)
	a.Greater(len(app.AppParams.ApprovalProgram), 0)

	commitRound(10, 0, l1)

	// restart
	l1.Close()

	l2, err := OpenLedger(logging.Base(), dbPrefix, false, genesisInitState, cfg)
	a.NoError(err)
	defer l2.Close()

	app, err = l2.LookupApplication(l2.Latest(), creator, appIdx)
	a.NoError(err)
	a.Greater(len(app.AppParams.ApprovalProgram), 0)

	txHeader = transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l2.Latest() + 1,
		LastValid:   l2.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	appCallFields := transactions.ApplicationCallTxnFields{
		ApplicationID: appIdx,
		Boxes:         []transactions.BoxRef{{Name: []byte("boxname")}},
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l2.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

}

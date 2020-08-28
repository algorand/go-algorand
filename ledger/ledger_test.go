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

package ledger

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

var poolSecret, sinkSecret *crypto.SignatureSecrets

func init() {
	var seed crypto.Seed

	incentivePoolName := []byte("incentive pool")
	copy(seed[:], incentivePoolName)
	poolSecret = crypto.GenerateSignatureSecrets(seed)

	feeSinkName := []byte("fee sink")
	copy(seed[:], feeSinkName)
	sinkSecret = crypto.GenerateSignatureSecrets(seed)
}

func sign(secrets map[basics.Address]*crypto.SignatureSecrets, t transactions.Transaction) transactions.SignedTxn {
	var sig crypto.Signature
	_, ok := secrets[t.Sender]
	if ok {
		sig = secrets[t.Sender].Sign(t)
	}
	return transactions.SignedTxn{
		Txn: t,
		Sig: sig,
	}
}

func testGenerateInitState(t *testing.T, proto protocol.ConsensusVersion) (genesisInitState InitState, initKeys map[basics.Address]*crypto.SignatureSecrets) {
	params := config.Consensus[proto]
	poolAddr := testPoolAddr
	sinkAddr := testSinkAddr

	var zeroSeed crypto.Seed
	var genaddrs [10]basics.Address
	var gensecrets [10]*crypto.SignatureSecrets
	for i := range genaddrs {
		seed := zeroSeed
		seed[0] = byte(i)
		x := crypto.GenerateSignatureSecrets(seed)
		genaddrs[i] = basics.Address(x.SignatureVerifier)
		gensecrets[i] = x
	}

	initKeys = make(map[basics.Address]*crypto.SignatureSecrets)
	initAccounts := make(map[basics.Address]basics.AccountData)
	for i := range genaddrs {
		initKeys[genaddrs[i]] = gensecrets[i]
		// Give each account quite a bit more balance than MinFee or MinBalance
		initAccounts[genaddrs[i]] = basics.MakeAccountData(basics.Online, basics.MicroAlgos{Raw: uint64((i + 100) * 100000)})
	}
	initKeys[poolAddr] = poolSecret
	initAccounts[poolAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 1234567})
	initKeys[sinkAddr] = sinkSecret
	initAccounts[sinkAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 7654321})

	incentivePoolBalanceAtGenesis := initAccounts[poolAddr].MicroAlgos
	initialRewardsPerRound := incentivePoolBalanceAtGenesis.Raw / uint64(params.RewardsRateRefreshInterval)
	var emptyPayset transactions.Payset

	initBlock := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			GenesisID: t.Name(),
			Round:     0,
			RewardsState: bookkeeping.RewardsState{
				RewardsRate: initialRewardsPerRound,
				RewardsPool: poolAddr,
				FeeSink:     sinkAddr,
			},
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: proto,
			},
			TxnRoot: emptyPayset.Commit(params.PaysetCommitFlat),
		},
	}
	if params.SupportGenesisHash {
		initBlock.BlockHeader.GenesisHash = crypto.Hash([]byte(t.Name()))
	}

	genesisInitState.Block = initBlock
	genesisInitState.Accounts = initAccounts
	genesisInitState.GenesisHash = crypto.Hash([]byte(t.Name()))

	return
}

type DummyVerifiedTxnCache struct{}

func (x DummyVerifiedTxnCache) Verified(txn transactions.SignedTxn, params verify.Params) bool {
	return false
}
func (x DummyVerifiedTxnCache) EvalOk(cvers protocol.ConsensusVersion, txid transactions.Txid) (found bool, err error) {
	return false, nil
}
func (x DummyVerifiedTxnCache) EvalRemember(cvers protocol.ConsensusVersion, txid transactions.Txid, err error) {
}

func (l *Ledger) appendUnvalidated(blk bookkeeping.Block) error {
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	vb, err := l.Validate(context.Background(), blk, DummyVerifiedTxnCache{}, backlogPool)
	if err != nil {
		return fmt.Errorf("appendUnvalidated error in Validate: %s", err.Error())
	}

	return l.AddValidatedBlock(*vb, agreement.Certificate{})
}

func (l *Ledger) appendUnvalidatedTx(t *testing.T, initAccounts map[basics.Address]basics.AccountData, initSecrets map[basics.Address]*crypto.SignatureSecrets, tx transactions.Transaction, ad transactions.ApplyData) error {
	stx := sign(initSecrets, tx)
	return l.appendUnvalidatedSignedTx(t, initAccounts, stx, ad)
}

func (l *Ledger) appendUnvalidatedSignedTx(t *testing.T, initAccounts map[basics.Address]basics.AccountData, stx transactions.SignedTxn, ad transactions.ApplyData) error {
	a := require.New(t)

	lastBlock, err := l.Block(l.Latest())
	a.NoError(err, "could not get last block")

	var emptyPayset transactions.Payset

	proto := config.Consensus[lastBlock.CurrentProtocol]
	poolAddr := testPoolAddr
	var totalRewardUnits uint64
	for _, acctdata := range initAccounts {
		totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto)
	}
	poolBal, err := l.Lookup(l.Latest(), poolAddr)
	a.NoError(err, "could not get incentive pool balance")

	correctBlkHeader := bookkeeping.BlockHeader{
		GenesisID:    t.Name(),
		Round:        l.Latest() + 1,
		Branch:       lastBlock.Hash(),
		TxnRoot:      emptyPayset.Commit(proto.PaysetCommitFlat),
		TimeStamp:    0,
		RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits),
		UpgradeState: lastBlock.UpgradeState,
		// Seed:       does not matter,
		// UpgradeVote: empty,
	}

	if proto.SupportGenesisHash {
		correctBlkHeader.GenesisHash = crypto.Hash([]byte(t.Name()))
	}

	if proto.TxnCounter {
		correctBlkHeader.TxnCounter = lastBlock.TxnCounter + 1
	}

	var blk bookkeeping.Block
	blk.BlockHeader = correctBlkHeader
	txib, err := blk.EncodeSignedTxn(stx, ad)
	if err != nil {
		return fmt.Errorf("could not sign txn: %s", err.Error())
	}
	blk.Payset = append(blk.Payset, txib)
	blk.TxnRoot = blk.Payset.Commit(proto.PaysetCommitFlat)
	blk.RewardsPool = testPoolAddr
	blk.FeeSink = testSinkAddr

	return l.appendUnvalidated(blk)
}

func TestLedgerBasic(t *testing.T) {
	genesisInitState, _ := testGenerateInitState(t, protocol.ConsensusCurrentVersion)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer l.Close()
}

func TestLedgerBlockHeaders(t *testing.T) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	genesisInitState, _ := testGenerateInitState(t, protocol.ConsensusCurrentVersion)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer l.Close()

	lastBlock, err := l.Block(l.Latest())
	a.NoError(err, "could not get last block")

	var emptyPayset transactions.Payset

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	poolAddr := testPoolAddr
	var totalRewardUnits uint64
	for _, acctdata := range genesisInitState.Accounts {
		totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto)
	}
	poolBal, err := l.Lookup(l.Latest(), poolAddr)
	a.NoError(err, "could not get incentive pool balance")

	correctHeader := bookkeeping.BlockHeader{
		GenesisID:    t.Name(),
		Round:        l.Latest() + 1,
		Branch:       lastBlock.Hash(),
		TxnRoot:      emptyPayset.Commit(proto.PaysetCommitFlat),
		TimeStamp:    0,
		RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits),
		UpgradeState: lastBlock.UpgradeState,
		// Seed:       does not matter,
		// UpgradeVote: empty,
	}
	correctHeader.RewardsPool = testPoolAddr
	correctHeader.FeeSink = testSinkAddr

	if proto.SupportGenesisHash {
		correctHeader.GenesisHash = crypto.Hash([]byte(t.Name()))
	}

	var badBlock bookkeeping.Block

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.Round++
	a.Error(l.appendUnvalidated(badBlock), "added block header with round that was too high")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.Round--
	a.Error(l.appendUnvalidated(badBlock), "added block header with round that was too low")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.Round = 0
	a.Error(l.appendUnvalidated(badBlock), "added block header with round 0")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.GenesisID = ""
	a.Error(l.appendUnvalidated(badBlock), "added block header with empty genesis ID")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.GenesisID = "incorrect"
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect genesis ID")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.UpgradePropose = "invalid"
	a.Error(l.appendUnvalidated(badBlock), "added block header with invalid upgrade proposal")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.UpgradeApprove = true
	a.Error(l.appendUnvalidated(badBlock), "added block header with upgrade approve set but no open upgrade")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.CurrentProtocol = "incorrect"
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect current protocol")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.CurrentProtocol = ""
	a.Error(l.appendUnvalidated(badBlock), "added block header with empty current protocol")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.NextProtocol = "incorrect"
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect next protocol")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.NextProtocolApprovals++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect number of upgrade approvals")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.NextProtocolVoteBefore++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect next protocol vote deadline")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.NextProtocolSwitchOn++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect next protocol switch round")

	// TODO test upgrade cases with a valid upgrade in progress

	// TODO test timestamp bounds

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.Branch = bookkeeping.BlockHash{}
	a.Error(l.appendUnvalidated(badBlock), "added block header with empty previous-block hash")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.Branch[0]++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect previous-block hash")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.RewardsLevel++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect rewards level")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.RewardsRate++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect rewards rate")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.RewardsResidue++
	a.Error(l.appendUnvalidated(badBlock), "added block header with incorrect rewards residue")

	// TODO test rewards cases with changing poolAddr money, with changing round, and with changing total reward units

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.TxnRoot = crypto.Digest{}
	a.Error(l.appendUnvalidated(badBlock), "added block header with empty transaction root")

	badBlock = bookkeeping.Block{BlockHeader: correctHeader}
	badBlock.BlockHeader.TxnRoot[0]++
	a.Error(l.appendUnvalidated(badBlock), "added block header with invalid transaction root")

	correctBlock := bookkeeping.Block{BlockHeader: correctHeader}
	a.NoError(l.appendUnvalidated(correctBlock), "could not add block with correct header")
}

func TestLedgerSingleTx(t *testing.T) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	genesisInitState, initSecrets := testGenerateInitState(t, protocol.ConsensusV7)
	const inMem = true
	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer l.Close()

	proto := config.Consensus[protocol.ConsensusV7]
	poolAddr := testPoolAddr
	sinkAddr := testSinkAddr

	initAccounts := genesisInitState.Accounts
	var addrList []basics.Address
	for addr := range initAccounts {
		if addr != poolAddr && addr != sinkAddr {
			addrList = append(addrList, addr)
		}
	}

	correctTxHeader := transactions.Header{
		Sender:     addrList[0],
		Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid: l.Latest() + 1,
		LastValid:  l.Latest() + 10,
		GenesisID:  t.Name(),
	}

	correctPayFields := transactions.PaymentTxnFields{
		Receiver: addrList[1],
		Amount:   basics.MicroAlgos{Raw: initAccounts[addrList[0]].MicroAlgos.Raw / 10},
	}

	correctPay := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           correctTxHeader,
		PaymentTxnFields: correctPayFields,
	}

	correctCloseFields := transactions.PaymentTxnFields{
		CloseRemainderTo: addrList[2],
	}

	correctClose := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           correctTxHeader,
		PaymentTxnFields: correctCloseFields,
	}

	var votePK crypto.OneTimeSignatureVerifier
	var selPK crypto.VRFVerifier
	votePK[0] = 1
	selPK[0] = 2
	correctKeyregFields := transactions.KeyregTxnFields{
		VotePK:      votePK,
		SelectionPK: selPK,
	}

	correctKeyreg := transactions.Transaction{
		Type:            protocol.KeyRegistrationTx,
		Header:          correctTxHeader,
		KeyregTxnFields: correctKeyregFields,
	}
	correctKeyreg.Sender = addrList[1]

	var badTx transactions.Transaction
	var ad transactions.ApplyData

	// TODO spend into dust, spend to self, close to self, close to receiver, overspend with fee, ...

	badTx = correctPay
	badTx.GenesisID = "invalid"
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with invalid genesis ID")

	badTx = correctPay
	badTx.Type = "invalid"
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with invalid tx type")

	badTx = correctPay
	badTx.KeyregTxnFields = correctKeyregFields
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added pay tx with keyreg fields set")

	badTx = correctKeyreg
	badTx.PaymentTxnFields = correctPayFields
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added keyreg tx with pay fields set")

	badTx = correctKeyreg
	badTx.PaymentTxnFields = correctCloseFields
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added keyreg tx with pay (close) fields set")

	badTx = correctPay
	badTx.FirstValid = badTx.LastValid + 1
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with FirstValid > LastValid")

	badTx = correctPay
	badTx.LastValid += basics.Round(proto.MaxTxnLife)
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with overly long validity")

	badTx = correctPay
	badTx.LastValid = l.Latest()
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added expired tx")

	badTx = correctPay
	badTx.FirstValid = l.Latest() + 2
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx which is not valid yet")

	badTx = correctPay
	badTx.Note = make([]byte, proto.MaxTxnNoteBytes+1)
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with overly large note field")

	badTx = correctPay
	badTx.Sender = poolAddr
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx send from tx pool")

	badTx = correctPay
	badTx.Sender = basics.Address{}
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx send from zero address")

	badTx = correctPay
	badTx.Fee = basics.MicroAlgos{}
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with zero fee")

	badTx = correctPay
	badTx.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee - 1}
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with fee below minimum")

	badTx = correctKeyreg
	fee, overflow := basics.OAddA(initAccounts[badTx.Sender].MicroAlgos, basics.MicroAlgos{Raw: 1})
	a.False(overflow)
	badTx.Fee = fee
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added keyreg tx with fee above user balance")

	// TODO try excessive spending given distribution of some number of rewards

	badTx = correctPay
	sbadTx := sign(initSecrets, badTx)
	sbadTx.Sig = crypto.Signature{}
	a.Error(l.appendUnvalidatedSignedTx(t, initAccounts, sbadTx, ad), "added tx with no signature")

	badTx = correctPay
	sbadTx = sign(initSecrets, badTx)
	sbadTx.Sig[5]++
	a.Error(l.appendUnvalidatedSignedTx(t, initAccounts, sbadTx, ad), "added tx with corrupt signature")

	// TODO set multisig and test

	badTx = correctPay
	badTx.Sender = sinkAddr
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "sink spent to non-sink address")

	badTx = correctPay
	badTx.Sender = sinkAddr
	badTx.CloseRemainderTo = addrList[0]
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "sink closed to non-sink address")

	badTx = correctPay
	badTx.Sender = sinkAddr
	badTx.Receiver = poolAddr
	badTx.CloseRemainderTo = addrList[0]
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "sink closed to non-sink address")

	badTx = correctPay
	badTx.Sender = sinkAddr
	badTx.CloseRemainderTo = poolAddr
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "sink closed to pool address")

	badTx = correctPay
	remainder, overflow := basics.OSubA(initAccounts[badTx.Sender].MicroAlgos, badTx.Amount)
	a.False(overflow)
	fee, overflow = basics.OAddA(remainder, basics.MicroAlgos{Raw: 1})
	a.False(overflow)
	badTx.Fee = fee
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "overspent with (amount + fee)")

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPay, ad), "could not add payment transaction")
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctClose, ad), "could not add close transaction")
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctKeyreg, ad), "could not add key registration")

	correctPay.Sender = sinkAddr
	correctPay.Receiver = poolAddr
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPay, ad), "could not spend from sink to pool")

	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctKeyreg, ad), "added duplicate tx")
}

func TestLedgerSingleTxV24(t *testing.T) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	protoName := protocol.ConsensusV24
	genesisInitState, initSecrets := testGenerateInitState(t, protoName)
	const inMem = true
	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer l.Close()

	proto := config.Consensus[protoName]
	poolAddr := testPoolAddr
	sinkAddr := testSinkAddr

	initAccounts := genesisInitState.Accounts
	var addrList []basics.Address
	for addr := range initAccounts {
		if addr != poolAddr && addr != sinkAddr {
			addrList = append(addrList, addr)
		}
	}

	correctTxHeader := transactions.Header{
		Sender:      addrList[0],
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: genesisInitState.GenesisHash,
	}

	assetParam := basics.AssetParams{
		Total:    100,
		UnitName: "unit",
		Manager:  addrList[0],
	}
	correctAssetConfigFields := transactions.AssetConfigTxnFields{
		AssetParams: assetParam,
	}
	correctAssetConfig := transactions.Transaction{
		Type:                 protocol.AssetConfigTx,
		Header:               correctTxHeader,
		AssetConfigTxnFields: correctAssetConfigFields,
	}
	correctAssetTransferFields := transactions.AssetTransferTxnFields{
		AssetAmount:   10,
		AssetReceiver: addrList[1],
	}
	correctAssetTransfer := transactions.Transaction{
		Type:                   protocol.AssetTransferTx,
		Header:                 correctTxHeader,
		AssetTransferTxnFields: correctAssetTransferFields,
	}

	approvalProgram := []byte("\x02\x20\x01\x01\x22") // int 1
	clearStateProgram := []byte("\x02")               // empty
	correctAppCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
	}
	correctAppCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   correctTxHeader,
		ApplicationCallTxnFields: correctAppCreateFields,
	}

	correctAppCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion: 0,
	}
	correctAppCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   correctTxHeader,
		ApplicationCallTxnFields: correctAppCallFields,
	}

	var badTx transactions.Transaction
	var ad transactions.ApplyData

	var assetIdx basics.AssetIndex
	var appIdx basics.AppIndex

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctAssetConfig, ad))
	assetIdx = 1 // the first txn

	badTx = correctAssetConfig
	badTx.ConfigAsset = 2
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "asset 2 does not exist or has been deleted")

	badTx = correctAssetConfig
	badTx.ConfigAsset = assetIdx
	badTx.AssetFrozen = true
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "type acfg has non-zero fields for type afrz")

	badTx = correctAssetConfig
	badTx.ConfigAsset = assetIdx
	badTx.Sender = addrList[1]
	badTx.AssetParams.Freeze = addrList[0]
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "this transaction should be issued by the manager")

	badTx = correctAssetConfig
	badTx.AssetParams.UnitName = "very long unit name that exceeds the limit"
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "transaction asset unit name too big: 42 > 8")

	badTx = correctAssetTransfer
	badTx.XferAsset = assetIdx
	badTx.AssetAmount = 101
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "underflow on subtracting 101 from sender amount 100")

	badTx = correctAssetTransfer
	badTx.XferAsset = assetIdx
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("asset %d missing from", assetIdx))

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctAppCreate, ad))
	appIdx = 2 // the first txn

	badTx = correctAppCreate
	program := make([]byte, len(approvalProgram))
	copy(program, approvalProgram)
	program[0] = '\x01'
	badTx.ApprovalProgram = program
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "program version must be >= 2")

	badTx = correctAppCreate
	badTx.ApplicationID = appIdx
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "programs may only be specified during application creation or update")

	badTx = correctAppCall
	badTx.ApplicationID = 0
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.Error(err)
	a.Contains(err.Error(), "ApprovalProgram: invalid version")

	correctAppCall.ApplicationID = appIdx
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctAppCall, ad))
}

func testLedgerSingleTxApplyData(t *testing.T, version protocol.ConsensusVersion) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	genesisInitState, initSecrets := testGenerateInitState(t, version)
	const inMem = true
	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer l.Close()

	proto := config.Consensus[version]
	poolAddr := testPoolAddr
	sinkAddr := testSinkAddr

	var addrList []basics.Address
	initAccounts := genesisInitState.Accounts
	for addr := range initAccounts {
		if addr != poolAddr && addr != sinkAddr {
			addrList = append(addrList, addr)
		}
	}

	correctTxHeader := transactions.Header{
		Sender:      addrList[0],
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: crypto.Hash([]byte(t.Name())),
	}

	correctPayFields := transactions.PaymentTxnFields{
		Receiver: addrList[1],
		Amount:   basics.MicroAlgos{Raw: initAccounts[addrList[0]].MicroAlgos.Raw / 10},
	}

	correctPay := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           correctTxHeader,
		PaymentTxnFields: correctPayFields,
	}

	correctCloseFields := transactions.PaymentTxnFields{
		CloseRemainderTo: addrList[2],
	}

	correctClose := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           correctTxHeader,
		PaymentTxnFields: correctCloseFields,
	}

	var votePK crypto.OneTimeSignatureVerifier
	var selPK crypto.VRFVerifier
	votePK[0] = 1
	selPK[0] = 2
	correctKeyregFields := transactions.KeyregTxnFields{
		VotePK:      votePK,
		SelectionPK: selPK,
	}

	correctKeyreg := transactions.Transaction{
		Type:            protocol.KeyRegistrationTx,
		Header:          correctTxHeader,
		KeyregTxnFields: correctKeyregFields,
	}
	correctKeyreg.Sender = addrList[1]

	var badTx transactions.Transaction
	var ad transactions.ApplyData

	badTx = correctPay
	badTx.GenesisID = "invalid"
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with invalid genesis ID")

	badTx = correctPay
	badTx.Type = "invalid"
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with invalid tx type")

	badTx = correctPay
	badTx.KeyregTxnFields = correctKeyregFields
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added pay tx with keyreg fields set")

	badTx = correctKeyreg
	badTx.PaymentTxnFields = correctPayFields
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added keyreg tx with pay fields set")

	badTx = correctKeyreg
	badTx.PaymentTxnFields = correctCloseFields
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added keyreg tx with pay (close) fields set")

	badTx = correctPay
	badTx.FirstValid = badTx.LastValid + 1
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with FirstValid > LastValid")

	badTx = correctPay
	badTx.LastValid += basics.Round(proto.MaxTxnLife)
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with overly long validity")

	badTx = correctPay
	badTx.LastValid = l.Latest()
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added expired tx")

	badTx = correctPay
	badTx.FirstValid = l.Latest() + 2
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx which is not valid yet")

	badTx = correctPay
	badTx.Note = make([]byte, proto.MaxTxnNoteBytes+1)
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with overly large note field")

	badTx = correctPay
	badTx.Sender = basics.Address{}
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx send from zero address")

	badTx = correctPay
	badTx.Fee = basics.MicroAlgos{}
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with zero fee")

	badTx = correctPay
	badTx.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee - 1}
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added tx with fee below minimum")

	badTx = correctKeyreg
	fee, overflow := basics.OAddA(initAccounts[badTx.Sender].MicroAlgos, basics.MicroAlgos{Raw: 1})
	a.False(overflow)
	badTx.Fee = fee
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "added keyreg tx with fee above user balance")

	// TODO try excessive spending given distribution of some number of rewards

	badTx = correctPay
	sbadTx := sign(initSecrets, badTx)
	sbadTx.Sig = crypto.Signature{}
	a.Error(l.appendUnvalidatedSignedTx(t, initAccounts, sbadTx, ad), "added tx with no signature")

	badTx = correctPay
	remainder, overflow := basics.OSubA(initAccounts[badTx.Sender].MicroAlgos, badTx.Amount)
	a.False(overflow)
	fee, overflow = basics.OAddA(remainder, basics.MicroAlgos{Raw: 1})
	a.False(overflow)
	badTx.Fee = fee
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad), "overspent with (amount + fee)")

	adClose := ad
	adClose.ClosingAmount = initAccounts[correctClose.Sender].MicroAlgos
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctPay.Amount)
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctPay.Fee)
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctClose.Amount)
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctClose.Fee)

	adCloseWrong := adClose
	adCloseWrong.ClosingAmount.Raw++

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPay, ad), "could not add payment transaction")
	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctClose, adCloseWrong), "closed transaction with wrong ApplyData")
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctClose, adClose), "could not add close transaction")
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctKeyreg, ad), "could not add key registration")

	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctKeyreg, ad), "added duplicate tx")

	leaseReleaseRound := l.Latest() + 10
	correctPayLease := correctPay
	correctPayLease.Sender = addrList[3]
	correctPayLease.Lease[0] = 1
	correctPayLease.LastValid = leaseReleaseRound
	if proto.SupportTransactionLeases {
		a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "could not add payment transaction with payment lease")

		correctPayLease.Note = make([]byte, 1)
		correctPayLease.Note[0] = 1
		correctPayLease.LastValid += 10
		a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "added payment transaction with matching transaction lease")
		correctPayLeaseOther := correctPayLease
		correctPayLeaseOther.Sender = addrList[4]
		a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLeaseOther, ad), "could not add payment transaction with matching lease but different sender")
		correctPayLeaseOther = correctPayLease
		correctPayLeaseOther.Lease[0]++
		a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLeaseOther, ad), "could not add payment transaction with matching sender but different lease")

		for l.Latest() < leaseReleaseRound {
			a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "added payment transaction with matching transaction lease")

			var totalRewardUnits uint64
			for _, acctdata := range initAccounts {
				totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto)
			}
			poolBal, err := l.Lookup(l.Latest(), testPoolAddr)
			a.NoError(err, "could not get incentive pool balance")
			var emptyPayset transactions.Payset
			lastBlock, err := l.Block(l.Latest())
			a.NoError(err, "could not get last block")

			correctHeader := bookkeeping.BlockHeader{
				GenesisID:    t.Name(),
				Round:        l.Latest() + 1,
				Branch:       lastBlock.Hash(),
				TxnRoot:      emptyPayset.Commit(proto.PaysetCommitFlat),
				TimeStamp:    0,
				RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits),
				UpgradeState: lastBlock.UpgradeState,
				// Seed:       does not matter,
				// UpgradeVote: empty,
			}
			correctHeader.RewardsPool = testPoolAddr
			correctHeader.FeeSink = testSinkAddr

			if proto.SupportGenesisHash {
				correctHeader.GenesisHash = crypto.Hash([]byte(t.Name()))
			}

			if proto.TxnCounter {
				correctHeader.TxnCounter = lastBlock.TxnCounter
			}

			correctBlock := bookkeeping.Block{BlockHeader: correctHeader}
			a.NoError(l.appendUnvalidated(correctBlock), "could not add block with correct header")
		}

		a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "could not add payment transaction after lease was dropped")
	} else {
		a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "added payment transaction with transaction lease unsupported by protocol version")
	}
}

func TestLedgerSingleTxApplyData(t *testing.T) {
	testLedgerSingleTxApplyData(t, protocol.ConsensusCurrentVersion)
}

// SupportTransactionLeases was introduced after v18.
func TestLedgerSingleTxApplyDataV18(t *testing.T) {
	testLedgerSingleTxApplyData(t, protocol.ConsensusV18)
}

func TestLedgerSingleTxApplyDataFuture(t *testing.T) {
	testLedgerSingleTxApplyData(t, protocol.ConsensusFuture)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheckOld(t *testing.T) {
	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusV22)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheckV23(t *testing.T) {
	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusV23)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheck(t *testing.T) {
	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusCurrentVersion)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheckFuture(t *testing.T) {
	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusFuture)
}

func testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t *testing.T, version protocol.ConsensusVersion) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	genesisInitState, initSecrets := testGenerateInitState(t, version)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer l.Close()

	proto := config.Consensus[version]
	poolAddr := testPoolAddr
	sinkAddr := testSinkAddr

	initAccounts := genesisInitState.Accounts
	var addrList []basics.Address
	for addr := range initAccounts {
		if addr != poolAddr && addr != sinkAddr {
			addrList = append(addrList, addr)
		}
	}

	correctTxHeader := transactions.Header{
		Sender:      addrList[0],
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: crypto.Hash([]byte(t.Name())),
	}

	correctPayFields := transactions.PaymentTxnFields{
		Receiver: addrList[1],
		Amount:   basics.MicroAlgos{Raw: initAccounts[addrList[0]].MicroAlgos.Raw / 10},
	}

	correctPay := transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           correctTxHeader,
		PaymentTxnFields: correctPayFields,
	}

	var ad transactions.ApplyData

	correctPayLease := correctPay
	correctPayLease.Sender = addrList[3]
	correctPayLease.Lease[0] = 1

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "could not add initial payment transaction")

	correctPayLease.FirstValid = l.Latest() + 1
	correctPayLease.LastValid = l.Latest() + 10

	if proto.FixTransactionLeases {
		a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "added payment transaction with overlapping lease")
	} else {
		a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "should allow leasing payment transaction with newer FirstValid")
	}
}

func TestLedgerBlockHdrCaching(t *testing.T) {
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState := getInitState()
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blk := genesisInitState.Block

	for i := 0; i < 128; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err := l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)

		hdr, err := l.BlockHdr(blk.BlockHeader.Round)
		require.NoError(t, err)
		require.Equal(t, blk.BlockHeader, hdr)
	}
}

func TestLedgerReload(t *testing.T) {
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState := getInitState()
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blk := genesisInitState.Block
	for i := 0; i < 128; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err = l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)

		if i%7 == 0 {
			err = l.reloadLedger()
			require.NoError(t, err)

			// if we reloaded it before it got committed, we need to roll back the round counter.
			if l.LatestCommitted() != blk.BlockHeader.Round {
				blk.BlockHeader.Round = l.LatestCommitted()
			}
		}
		if i%13 == 0 {
			l.WaitForCommit(blk.Round())
		}
	}
}

// Copyright (C) 2019-2025 Algorand, Inc.
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
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-deadlock"
)

const preReleaseDBVersion = 6

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

func (l *Ledger) appendUnvalidated(blk bookkeeping.Block) error {
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()
	l.verifiedTxnCache = verify.GetMockedCache(false)
	vb, err := l.Validate(context.Background(), blk, backlogPool)
	if err != nil {
		return fmt.Errorf("appendUnvalidated error in Validate: %w", err)
	}

	return l.AddValidatedBlock(*vb, agreement.Certificate{})
}

func (l *Ledger) appendUnvalidatedTx(t *testing.T, initAccounts map[basics.Address]basics.AccountData, initSecrets map[basics.Address]*crypto.SignatureSecrets, tx transactions.Transaction, ad transactions.ApplyData) error {
	stx := sign(initSecrets, tx)
	return l.appendUnvalidatedSignedTx(t, initAccounts, stx, ad)
}

func initNextBlockHeader(correctHeader *bookkeeping.BlockHeader, lastBlock bookkeeping.Block, proto config.ConsensusParams) {
	if proto.TxnCounter {
		correctHeader.TxnCounter = lastBlock.TxnCounter
	}

	if proto.StateProofInterval > 0 {
		var ccBasic bookkeeping.StateProofTrackingData
		if lastBlock.StateProofTracking[protocol.StateProofBasic].StateProofNextRound == 0 {
			ccBasic.StateProofNextRound = (correctHeader.Round + basics.Round(proto.StateProofVotersLookback)).RoundUpToMultipleOf(basics.Round(proto.StateProofInterval)) + basics.Round(proto.StateProofInterval)
		} else {
			ccBasic.StateProofNextRound = lastBlock.StateProofTracking[protocol.StateProofBasic].StateProofNextRound
		}
		correctHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
			protocol.StateProofBasic: ccBasic,
		}
	}
}

// endOfBlock is simplified implementation of BlockEvaluator.endOfBlock so that
// our test blocks can pass validation.
func endOfBlock(blk *bookkeeping.Block) error {
	if blk.ConsensusProtocol().Payouts.Enabled {
		// This won't work for inner fees, and it's not bothering with overflow
		for _, txn := range blk.Payset {
			blk.FeesCollected.Raw += txn.Txn.Fee.Raw
		}
		// blk.ProposerPayout is allowed to be zero, so don't reproduce the calc here.
		blk.BlockHeader.Proposer = basics.Address{0x01} // Must be set to _something_.
	}
	var err error
	blk.TxnCommitments, err = blk.PaysetCommit()
	return err
}

func makeNewEmptyBlock(t *testing.T, l *Ledger, GenesisID string, initAccounts map[basics.Address]basics.AccountData) (blk bookkeeping.Block) {
	a := require.New(t)

	lastBlock, err := l.Block(l.Latest())
	a.NoError(err, "could not get last block")

	proto := config.Consensus[lastBlock.CurrentProtocol]
	poolAddr := testPoolAddr
	var totalRewardUnits uint64
	if l.Latest() == 0 {
		require.NotNil(t, initAccounts)
		for _, acctdata := range initAccounts {
			if acctdata.Status != basics.NotParticipating {
				totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto.RewardUnit)
			}
		}
	} else {
		latestRound, totals, err := l.LatestTotals()
		require.NoError(t, err)
		require.Equal(t, l.Latest(), latestRound)
		totalRewardUnits = totals.RewardUnits()
	}
	poolBal, _, _, err := l.LookupLatest(poolAddr)
	a.NoError(err, "could not get incentive pool balance")

	blk.BlockHeader = bookkeeping.BlockHeader{
		Round:  l.Latest() + 1,
		Branch: lastBlock.Hash(),
		// Seed:       does not matter,
		TimeStamp:    0,
		GenesisID:    GenesisID,
		Bonus:        bookkeeping.NextBonus(lastBlock.BlockHeader, &proto),
		RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits, logging.Base()),
		UpgradeState: lastBlock.UpgradeState,
		// UpgradeVote: empty,
	}

	if proto.Payouts.Enabled {
		blk.BlockHeader.Proposer = basics.Address{0x01} // Must be set to _something_.
	}
	if proto.EnableSha512BlockHash {
		blk.BlockHeader.Branch512 = lastBlock.Hash512()
	}

	blk.TxnCommitments, err = blk.PaysetCommit()
	require.NoError(t, err)

	if proto.SupportGenesisHash {
		blk.BlockHeader.GenesisHash = crypto.Hash([]byte(GenesisID))
	}

	initNextBlockHeader(&blk.BlockHeader, lastBlock, proto)

	blk.RewardsPool = testPoolAddr
	blk.FeeSink = testSinkAddr
	blk.CurrentProtocol = lastBlock.CurrentProtocol

	if proto.StateProofInterval != 0 && uint64(blk.Round())%proto.StateProofInterval == 0 && uint64(blk.Round()) != 0 {
		voters, err := l.VotersForStateProof(blk.Round() - basics.Round(proto.StateProofVotersLookback))
		require.NoError(t, err)
		stateProofTracking := bookkeeping.StateProofTrackingData{
			StateProofVotersCommitment:  voters.Tree.Root(),
			StateProofOnlineTotalWeight: voters.TotalWeight,
			StateProofNextRound:         blk.BlockHeader.StateProofTracking[protocol.StateProofBasic].StateProofNextRound,
		}
		blk.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateProofTracking
	}

	return
}

func (l *Ledger) appendUnvalidatedSignedTx(t *testing.T, initAccounts map[basics.Address]basics.AccountData, stx transactions.SignedTxn, ad transactions.ApplyData) error {
	blk := makeNewEmptyBlock(t, l, t.Name(), initAccounts)
	proto := config.Consensus[blk.CurrentProtocol]
	txib, err := blk.EncodeSignedTxn(stx, ad)
	if err != nil {
		return fmt.Errorf("could not sign txn: %s", err.Error())
	}
	blk.Payset = append(blk.Payset, txib)
	if proto.TxnCounter {
		blk.TxnCounter = blk.TxnCounter + 1
	}
	require.NoError(t, endOfBlock(&blk))
	return l.appendUnvalidated(blk)
}

func (l *Ledger) addBlockTxns(t *testing.T, accounts map[basics.Address]basics.AccountData, stxns []transactions.SignedTxn, ad transactions.ApplyData) error {
	blk := makeNewEmptyBlock(t, l, t.Name(), accounts)
	proto := config.Consensus[blk.CurrentProtocol]
	for _, stx := range stxns {
		txib, err := blk.EncodeSignedTxn(stx, ad)
		if err != nil {
			return fmt.Errorf("could not sign txn: %s", err.Error())
		}
		if proto.TxnCounter {
			blk.TxnCounter = blk.TxnCounter + 1
		}
		blk.Payset = append(blk.Payset, txib)
	}
	var err error
	blk.TxnCommitments, err = blk.PaysetCommit()
	require.NoError(t, err)
	return l.AddBlock(blk, agreement.Certificate{})
}

func testLedgerBasic(t *testing.T, cfg config.Local) {
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	const inMem = true
	log := logging.TestingLog(t)
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer l.Close()
}

func TestLedgerBasic(t *testing.T) {
	partitiontest.PartitionTest(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true

	ledgertesting.WithAndWithoutLRUCache(t, cfg, testLedgerBasic)
}

func TestLedgerBlockHeaders(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := assert.New(t)

	for _, cv := range []protocol.ConsensusVersion{
		protocol.ConsensusV25, // some oldish version to test against backward compatibility
		protocol.ConsensusCurrentVersion,
		protocol.ConsensusFuture,
	} {
		genesisInitState, _ := ledgertesting.GenerateInitState(t, cv, 100)
		const inMem = true
		cfg := config.GetDefaultLocal()
		cfg.Archival = true
		l, err := OpenLedger(logging.Base(), t.Name()+string(cv), inMem, genesisInitState, cfg)
		a.NoError(err, "could not open ledger")
		defer l.Close()

		lastBlock, err := l.Block(l.Latest())
		a.NoError(err, "could not get last block")

		proto := config.Consensus[genesisInitState.Block.CurrentProtocol]
		poolAddr := testPoolAddr
		var totalRewardUnits uint64
		for _, acctdata := range genesisInitState.Accounts {
			totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto.RewardUnit)
		}
		poolBal, _, _, err := l.LookupLatest(poolAddr)
		a.NoError(err, "could not get incentive pool balance")

		correctHeader := bookkeeping.BlockHeader{
			Round:  l.Latest() + 1,
			Branch: lastBlock.Hash(),
			// Seed:       does not matter,
			Bonus:        bookkeeping.NextBonus(lastBlock.BlockHeader, &proto),
			TimeStamp:    0,
			GenesisID:    t.Name(),
			RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits, logging.Base()),
			UpgradeState: lastBlock.UpgradeState,
			// UpgradeVote: empty,
		}
		if proto.Payouts.Enabled {
			correctHeader.Proposer = basics.Address{0x01} // Must be set to _something_.
		}

		emptyBlock := bookkeeping.Block{
			BlockHeader: correctHeader,
		}
		correctHeader.TxnCommitments, err = emptyBlock.PaysetCommit()
		require.NoError(t, err)

		correctHeader.RewardsPool = testPoolAddr
		correctHeader.FeeSink = testSinkAddr

		if proto.SupportGenesisHash {
			correctHeader.GenesisHash = crypto.Hash([]byte(t.Name()))
		}
		if proto.EnableSha512BlockHash {
			correctHeader.Branch512 = lastBlock.Hash512()
		}

		initNextBlockHeader(&correctHeader, lastBlock, proto)

		var badBlock bookkeeping.Block

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.Round++
		a.ErrorContains(l.appendUnvalidated(badBlock), "ledger does not have entry")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.Round--
		a.ErrorIs(l.appendUnvalidated(badBlock), eval.ErrRoundZero)

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.Round = 0
		a.ErrorIs(l.appendUnvalidated(badBlock), eval.ErrRoundZero)

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.GenesisID = ""
		a.ErrorContains(l.appendUnvalidated(badBlock), "genesis ID missing")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.GenesisID = "incorrect"
		a.ErrorContains(l.appendUnvalidated(badBlock), "genesis ID mismatch")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.UpgradePropose = "invalid"
		a.ErrorContains(l.appendUnvalidated(badBlock), "proposed upgrade wait rounds 0")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.UpgradePropose = "invalid"
		badBlock.BlockHeader.UpgradeDelay = 20000
		a.ErrorContains(l.appendUnvalidated(badBlock), "UpgradeState mismatch")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.UpgradeApprove = true
		a.ErrorContains(l.appendUnvalidated(badBlock), "approval without an active proposal")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.CurrentProtocol = "incorrect"
		a.ErrorContains(l.appendUnvalidated(badBlock), "protocol not supported")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.CurrentProtocol = ""
		a.ErrorContains(l.appendUnvalidated(badBlock), "protocol not supported", "header with empty current protocol")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		var wrongVersion protocol.ConsensusVersion
		for ver := range config.Consensus {
			if ver != correctHeader.CurrentProtocol {
				wrongVersion = ver
				break
			}
		}
		a.NotEmpty(wrongVersion)
		badBlock.BlockHeader.CurrentProtocol = wrongVersion
		// Handle Branch512 field mismatch between correctHeader and wrongVersion's expectations
		// We want to set the Branch512 header to match wrongVersion so that PreCheck will reach
		// the intended "UpgradeState mismatch" error, which happens after the Branch512 check.
		if !proto.EnableSha512BlockHash && config.Consensus[wrongVersion].EnableSha512BlockHash {
			// correctHeader has empty Branch512, but wrongVersion expects it during validation
			badBlock.BlockHeader.Branch512 = lastBlock.Hash512()
		} else if proto.EnableSha512BlockHash && !config.Consensus[wrongVersion].EnableSha512BlockHash {
			// correctHeader has non-zero Branch512, but wrongVersion doesn't support it
			badBlock.BlockHeader.Branch512 = crypto.Sha512Digest{}
		}
		// Otherwise, Branch512 is already correct (both support or both don't support SHA512)
		a.ErrorContains(l.appendUnvalidated(badBlock), "UpgradeState mismatch")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.NextProtocol = "incorrect"
		a.ErrorContains(l.appendUnvalidated(badBlock), "UpgradeState mismatch", "added block header with incorrect next protocol")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.NextProtocolApprovals++
		a.ErrorContains(l.appendUnvalidated(badBlock), "UpgradeState mismatch", "added block header with incorrect number of upgrade approvals")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.NextProtocolVoteBefore++
		a.ErrorContains(l.appendUnvalidated(badBlock), "UpgradeState mismatch", "added block header with incorrect next protocol vote deadline")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.NextProtocolSwitchOn++
		a.ErrorContains(l.appendUnvalidated(badBlock), "UpgradeState mismatch", "added block header with incorrect next protocol switch round")

		// TODO test upgrade cases with a valid upgrade in progress

		// TODO test timestamp bounds

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.Branch = bookkeeping.BlockHash{}
		a.ErrorContains(l.appendUnvalidated(badBlock), "block branch incorrect")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.Branch[0]++
		a.ErrorContains(l.appendUnvalidated(badBlock), "block branch incorrect")

		if proto.EnableSha512BlockHash {
			badBlock = bookkeeping.Block{BlockHeader: correctHeader}
			badBlock.BlockHeader.Branch512 = crypto.Sha512Digest{}
			a.ErrorContains(l.appendUnvalidated(badBlock), "block branch512 incorrect")

			badBlock = bookkeeping.Block{BlockHeader: correctHeader}
			badBlock.BlockHeader.Branch512[0]++
			a.ErrorContains(l.appendUnvalidated(badBlock), "block branch512 incorrect")
		}

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.RewardsLevel++
		a.ErrorContains(l.appendUnvalidated(badBlock), "bad rewards state")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.RewardsRate++
		a.ErrorContains(l.appendUnvalidated(badBlock), "bad rewards state")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.RewardsResidue++
		a.ErrorContains(l.appendUnvalidated(badBlock), "bad rewards state")

		// TODO test rewards cases with changing poolAddr money, with changing round, and with changing total reward units

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.TxnCommitments.NativeSha512_256Commitment = crypto.Hash([]byte{0})
		a.ErrorContains(l.appendUnvalidated(badBlock), "txn root wrong")

		badBlock = bookkeeping.Block{BlockHeader: correctHeader}
		badBlock.BlockHeader.TxnCommitments.NativeSha512_256Commitment[0]++
		a.ErrorContains(l.appendUnvalidated(badBlock), "txn root wrong")

		correctBlock := bookkeeping.Block{BlockHeader: correctHeader}
		a.NoError(l.appendUnvalidated(correctBlock), "could not add block with correct header")
	}
}

func TestLedgerSingleTx(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	// V15 is the earliest protocol version in active use.
	// The genesis for betanet and testnet is at V15
	// The genesis for mainnet is at V17
	genesisInitState, initSecrets := ledgertesting.GenerateInitState(t, protocol.ConsensusV15, 100)
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
		Sender:      addrList[0],
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: genesisInitState.GenesisHash,
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
		VotePK:          votePK,
		SelectionPK:     selPK,
		VoteKeyDilution: proto.DefaultKeyDilution,
		VoteFirst:       0,
		VoteLast:        10000,
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

	adClose := ad
	adClose.ClosingAmount = initAccounts[correctClose.Sender].MicroAlgos
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctPay.Amount)
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctPay.Fee)
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctClose.Amount)
	adClose.ClosingAmount, _ = basics.OSubA(adClose.ClosingAmount, correctClose.Fee)

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPay, ad), "could not add payment transaction")
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctClose, adClose), "could not add close transaction")
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctKeyreg, ad), "could not add key registration")

	correctPay.Sender = sinkAddr
	correctPay.Receiver = poolAddr
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPay, ad), "could not spend from sink to pool")

	a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctKeyreg, ad), "added duplicate tx")
}

func TestLedgerSingleTxV24(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	protoName := protocol.ConsensusV24
	genesisInitState, initSecrets := ledgertesting.GenerateInitState(t, protoName, 100)
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
	a.ErrorContains(err, "asset 2 does not exist or has been deleted")

	badTx = correctAssetConfig
	badTx.ConfigAsset = assetIdx
	badTx.AssetFrozen = true
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "type acfg has non-zero fields for type afrz")

	badTx = correctAssetConfig
	badTx.ConfigAsset = assetIdx
	badTx.Sender = addrList[1]
	badTx.AssetParams.Freeze = addrList[0]
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "this transaction should be issued by the manager")

	badTx = correctAssetConfig
	badTx.AssetParams.UnitName = "very long unit name that exceeds the limit"
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "transaction asset unit name too big: 42 > 8")

	badTx = correctAssetTransfer
	badTx.XferAsset = assetIdx
	badTx.AssetAmount = 101
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "underflow on subtracting 101 from sender amount 100")

	badTx = correctAssetTransfer
	badTx.XferAsset = assetIdx
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, fmt.Sprintf("asset %d missing from", assetIdx))

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctAppCreate, ad))
	appIdx = 2 // the second successful txn

	badTx = correctAppCreate
	program := slices.Clone(approvalProgram)
	program[0] = '\x01'
	badTx.ApprovalProgram = program
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "program version must be >= 2")

	badTx = correctAppCreate
	badTx.ApplicationID = appIdx
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "programs may only be specified during application creation or update")

	badTx = correctAppCall
	badTx.ApplicationID = 0
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "ApprovalProgram: invalid program (empty)")
	badTx.ApprovalProgram = []byte{242}
	err = l.appendUnvalidatedTx(t, initAccounts, initSecrets, badTx, ad)
	a.ErrorContains(err, "ApprovalProgram: invalid version")

	correctAppCall.ApplicationID = appIdx
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctAppCall, ad))
}

func addEmptyValidatedBlock(t *testing.T, l *Ledger, initAccounts map[basics.Address]basics.AccountData) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	blk := makeNewEmptyBlock(t, l, t.Name(), initAccounts)
	vb, err := l.Validate(context.Background(), blk, backlogPool)
	a.NoError(err)
	err = l.AddValidatedBlock(*vb, agreement.Certificate{})
	a.NoError(err)
}

// TestLedgerAppCrossRoundWrites ensures app state writes survive between rounds
func TestLedgerAppCrossRoundWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	protoName := protocol.ConsensusV24
	genesisInitState, initSecrets := ledgertesting.GenerateInitState(t, protoName, 100)
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

	creator := addrList[0]
	user := addrList[1]
	correctTxHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: genesisInitState.GenesisHash,
	}

	counter := `#pragma version 2
// a simple global and local calls counter app
byte "counter"
dup
app_global_get
int 1
+
app_global_put  // update the counter
int 0
int 0
app_opted_in
bnz opted_in
int 1
return
opted_in:
int 0  // account idx for app_local_put
byte "counter"
int 0
byte "counter"
app_local_get
int 1  // increment
+
app_local_put
int 1
`
	ops, err := logic.AssembleString(counter)
	a.NoError(err)
	approvalProgram := ops.Program

	clearStateProgram := []byte("\x02") // empty
	appcreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
		LocalStateSchema:  basics.StateSchema{NumUint: 1},
	}
	appcreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   correctTxHeader,
		ApplicationCallTxnFields: appcreateFields,
	}

	ad := transactions.ApplyData{EvalDelta: transactions.EvalDelta{GlobalDelta: basics.StateDelta{
		"counter": basics.ValueDelta{Action: basics.SetUintAction, Uint: 1},
	}}}
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, appcreate, ad))
	var appIdx basics.AppIndex = 1

	rnd := l.Latest()
	acctRes, err := l.LookupApplication(rnd, creator, appIdx)
	a.NoError(err)
	a.Equal(basics.TealValue{Type: basics.TealUintType, Uint: 1}, acctRes.AppParams.GlobalState["counter"])

	addEmptyValidatedBlock(t, l, initAccounts)
	addEmptyValidatedBlock(t, l, initAccounts)

	appcallFields := transactions.ApplicationCallTxnFields{
		OnCompletion: transactions.OptInOC,
	}

	correctTxHeader.Sender = user
	appcall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   correctTxHeader,
		ApplicationCallTxnFields: appcallFields,
	}
	appcall.ApplicationID = appIdx
	ad = transactions.ApplyData{EvalDelta: transactions.EvalDelta{
		GlobalDelta: basics.StateDelta{
			"counter": basics.ValueDelta{Action: basics.SetUintAction, Uint: 2},
		},
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {
				"counter": basics.ValueDelta{Action: basics.SetUintAction, Uint: 1},
			},
		},
	}}
	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, appcall, ad))

	rnd = l.Latest()
	acctworRes, err := l.LookupApplication(rnd, creator, appIdx)
	a.NoError(err)
	a.Equal(basics.TealValue{Type: basics.TealUintType, Uint: 2}, acctworRes.AppParams.GlobalState["counter"])

	addEmptyValidatedBlock(t, l, initAccounts)

	acctworRes, err = l.LookupApplication(l.Latest()-1, creator, appIdx)
	a.NoError(err)
	a.Equal(basics.TealValue{Type: basics.TealUintType, Uint: 2}, acctworRes.AppParams.GlobalState["counter"])

	acctRes, err = l.LookupApplication(rnd, user, appIdx)
	a.NoError(err)
	a.Equal(basics.TealValue{Type: basics.TealUintType, Uint: 1}, acctRes.AppLocalState.KeyValue["counter"])
}

// TestLedgerAppMultiTxnWrites ensures app state writes in multiple txn are applied
func TestLedgerAppMultiTxnWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	protoName := protocol.ConsensusV24
	genesisInitState, initSecrets := ledgertesting.GenerateInitState(t, protoName, 100)
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

	creator := addrList[0]
	user := addrList[1]
	genesisID := t.Name()
	correctTxHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   genesisID,
		GenesisHash: genesisInitState.GenesisHash,
	}

	value := byte(10)
	sum := `#pragma version 2
// add a value from args to a key
byte "key"              // [key]
dup                     // [key, key]
app_global_get          // [key, val]
txna ApplicationArgs 0  // [key, val, arg]
btoi                    // [key, val, arg]
+                       // [key, val+arg]
app_global_put          // []
int 1                   // [1]
`
	ops, err := logic.AssembleString(sum)
	a.NoError(err)
	approvalProgram := ops.Program

	clearStateProgram := []byte("\x02") // empty
	appcreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
		ApplicationArgs:   [][]byte{{value}},
	}
	correctTxHeader.Sender = creator
	appcreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   correctTxHeader,
		ApplicationCallTxnFields: appcreateFields,
	}

	ad := transactions.ApplyData{EvalDelta: transactions.EvalDelta{GlobalDelta: basics.StateDelta{
		"key": basics.ValueDelta{Action: basics.SetUintAction, Uint: uint64(value)},
	}}}

	a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, appcreate, ad))
	var appIdx basics.AppIndex = 1

	rnd := l.Latest()
	acctRes, err := l.LookupApplication(rnd, creator, appIdx)
	a.NoError(err)
	a.Equal(basics.TealValue{Type: basics.TealUintType, Uint: uint64(value)}, acctRes.AppParams.GlobalState["key"])

	// make two app call txns and put into the same block, with and without groupping
	var tests = []struct {
		groupped bool
		base     byte
		val1     byte
		val2     byte
	}{
		{true, byte(value), byte(11), byte(17)},
		{false, byte(value + 11 + 17), byte(13), byte(19)},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("groupped %v", test.groupped), func(t *testing.T) {
			a := require.New(t)

			base := test.base
			value1 := test.val1
			appcallFields1 := transactions.ApplicationCallTxnFields{
				ApplicationID:   appIdx,
				OnCompletion:    transactions.NoOpOC,
				ApplicationArgs: [][]byte{{value1}},
			}
			correctTxHeader.Sender = creator
			appcall1 := transactions.Transaction{
				Type:                     protocol.ApplicationCallTx,
				Header:                   correctTxHeader,
				ApplicationCallTxnFields: appcallFields1,
			}
			ad1 := transactions.ApplyData{EvalDelta: transactions.EvalDelta{GlobalDelta: basics.StateDelta{
				"key": basics.ValueDelta{Action: basics.SetUintAction, Uint: uint64(base + value1)},
			}}}

			value2 := test.val2
			appcallFields2 := transactions.ApplicationCallTxnFields{
				ApplicationID:   appIdx,
				OnCompletion:    transactions.NoOpOC,
				ApplicationArgs: [][]byte{{value2}},
			}
			correctTxHeader.Sender = user
			appcall2 := transactions.Transaction{
				Type:                     protocol.ApplicationCallTx,
				Header:                   correctTxHeader,
				ApplicationCallTxnFields: appcallFields2,
			}
			ad2 := transactions.ApplyData{EvalDelta: transactions.EvalDelta{GlobalDelta: basics.StateDelta{
				"key": basics.ValueDelta{Action: basics.SetUintAction, Uint: uint64(base + value1 + value2)},
			}}}

			a.NotEqual(appcall1.Sender, appcall2.Sender)

			if test.groupped {
				var group transactions.TxGroup
				group.TxGroupHashes = []crypto.Digest{crypto.HashObj(appcall1), crypto.HashObj(appcall2)}
				appcall1.Group = crypto.HashObj(group)
				appcall2.Group = crypto.HashObj(group)
			}

			stx1 := sign(initSecrets, appcall1)
			stx2 := sign(initSecrets, appcall2)

			blk := makeNewEmptyBlock(t, l, genesisID, initAccounts)
			txib1, err := blk.EncodeSignedTxn(stx1, ad1)
			a.NoError(err)
			txib2, err := blk.EncodeSignedTxn(stx2, ad2)
			a.NoError(err)
			blk.TxnCounter = blk.TxnCounter + 2
			blk.Payset = append(blk.Payset, txib1, txib2)
			blk.TxnCommitments, err = blk.PaysetCommit()
			a.NoError(err)
			err = l.appendUnvalidated(blk)
			a.NoError(err)

			expected := uint64(base + value1 + value2)
			rnd = l.Latest()
			acctworRes, err := l.LookupApplication(rnd, creator, appIdx)
			a.NoError(err)
			a.Equal(basics.TealValue{Type: basics.TealUintType, Uint: expected}, acctworRes.AppParams.GlobalState["key"])
		})
	}
}

func testLedgerSingleTxApplyData(t *testing.T, version protocol.ConsensusVersion) {
	a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	genesisInitState, initSecrets := ledgertesting.GenerateInitState(t, version, 100)
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
		VotePK:          votePK,
		SelectionPK:     selPK,
		VoteKeyDilution: proto.DefaultKeyDilution,
		VoteFirst:       0,
		VoteLast:        10000,
	}

	// depends on what the consensus is need to generate correct KeyregTxnFields.
	if proto.EnableStateProofKeyregCheck {
		frst, lst := uint64(correctKeyregFields.VoteFirst), uint64(correctKeyregFields.VoteLast)
		store, err := db.MakeAccessor("test-DB", false, true)
		a.NoError(err)
		defer store.Close()
		root, err := account.GenerateRoot(store)
		a.NoError(err)
		p, err := account.FillDBWithParticipationKeys(store, root.Address(), basics.Round(frst), basics.Round(lst), config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		signer := p.Participation.StateProofSecrets
		require.NoError(t, err)

		correctKeyregFields.StateProofPK = signer.GetVerifier().Commitment
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
				totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto.RewardUnit)
			}
			poolBal, _, _, err := l.LookupLatest(testPoolAddr)
			a.NoError(err, "could not get incentive pool balance")
			lastBlock, err := l.Block(l.Latest())
			a.NoError(err, "could not get last block")

			correctHeader := bookkeeping.BlockHeader{
				Round:  l.Latest() + 1,
				Branch: lastBlock.Hash(),
				// Seed:       does not matter,
				TimeStamp:    0,
				GenesisID:    t.Name(),
				Bonus:        bookkeeping.NextBonus(lastBlock.BlockHeader, &proto),
				RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits, logging.Base()),
				UpgradeState: lastBlock.UpgradeState,
				// UpgradeVote: empty,
			}
			correctHeader.RewardsPool = testPoolAddr
			correctHeader.FeeSink = testSinkAddr

			if proto.SupportGenesisHash {
				correctHeader.GenesisHash = crypto.Hash([]byte(t.Name()))
			}
			if proto.EnableSha512BlockHash {
				correctHeader.Branch512 = lastBlock.Hash512()
			}

			initNextBlockHeader(&correctHeader, lastBlock, proto)

			correctBlock := bookkeeping.Block{BlockHeader: correctHeader}
			a.NoError(endOfBlock(&correctBlock))

			a.NoError(l.appendUnvalidated(correctBlock), "could not add block with correct header")
		}

		a.NoError(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "could not add payment transaction after lease was dropped")
	} else {
		a.Error(l.appendUnvalidatedTx(t, initAccounts, initSecrets, correctPayLease, ad), "added payment transaction with transaction lease unsupported by protocol version")
	}
}

func TestLedgerSingleTxApplyData(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerSingleTxApplyData(t, protocol.ConsensusCurrentVersion)
}

// SupportTransactionLeases was introduced after v18.
func TestLedgerSingleTxApplyDataV18(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerSingleTxApplyData(t, protocol.ConsensusV18)
}

func TestLedgerSingleTxApplyDataFuture(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerSingleTxApplyData(t, protocol.ConsensusFuture)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheckOld(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusV22)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheckV23(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusV23)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheck(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusCurrentVersion)
}

func TestLedgerRegressionFaultyLeaseFirstValidCheckFuture(t *testing.T) {
	partitiontest.PartitionTest(t)

	testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t, protocol.ConsensusFuture)
}

func testLedgerRegressionFaultyLeaseFirstValidCheck2f3880f7(t *testing.T, version protocol.ConsensusVersion) {
	a := require.New(t)

	genesisInitState, initSecrets := ledgertesting.GenerateInitState(t, version, 100)
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

func BenchmarkLedgerBlockHdrCaching(b *testing.B) {
	benchLedgerCache(b, 1024-256+1)
}

func BenchmarkLedgerBlockHdrWithoutCaching(b *testing.B) {
	benchLedgerCache(b, 100)
}

type nullWriter struct{} // logging output not required

func (w nullWriter) Write(data []byte) (n int, err error) {
	return len(data), nil
}

func benchLedgerCache(b *testing.B, startRound basics.Round) {
	a := require.New(b)

	dbName := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())
	genesisInitState := getInitState()
	const inMem = false // benchmark actual DB stored in disk instead of on memory
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(b)
	log.SetOutput(nullWriter{})
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	a.NoError(err)
	defer func() { // close ledger and remove temporary DB file
		l.Close()
		err := os.Remove(dbName + ".tracker.sqlite")
		if err != nil {
			fmt.Printf("os.Remove: %v \n", err)
		}
		err = os.Remove(dbName + ".block.sqlite")
		if err != nil {
			fmt.Printf("os.Remove: %v \n", err)
		}

	}()

	blk := genesisInitState.Block

	// Fill ledger (and its cache) with blocks
	for i := 0; i < 1024; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err := l.AddBlock(blk, agreement.Certificate{})
		a.NoError(err)
	}

	for i := 0; i < b.N; i++ {
		for j := startRound; j < startRound+256; j++ { // these rounds should be in cache
			hdr, err := l.BlockHdr(j)
			a.NoError(err)
			a.Equal(j, hdr.Round)
		}
	}
}

// triggerTrackerFlush is based in the commit flow but executed it in a single (this) goroutine.
func triggerTrackerFlush(t *testing.T, l *Ledger) {
	l.trackers.mu.Lock()
	dbRound := l.trackers.dbRound
	l.trackers.mu.Unlock()

	rnd := l.Latest()
	minBlock := rnd
	maxLookback := basics.Round(0)
	for _, lt := range l.trackers.trackers {
		retainRound, lookback := lt.committedUpTo(rnd)
		if retainRound < minBlock {
			minBlock = retainRound
		}
		if lookback > maxLookback {
			maxLookback = lookback
		}
	}

	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: maxLookback,
		},
	}

	l.trackers.mu.RLock()
	cdr := l.trackers.produceCommittingTask(rnd, dbRound, &dcc.deferredCommitRange)
	if cdr != nil {
		dcc.deferredCommitRange = *cdr
	} else {
		dcc = nil
	}
	l.trackers.mu.RUnlock()
	if dcc != nil {
		l.trackers.accountsWriting.Add(1)
		l.trackers.commitRound(dcc)
	}
}

func testLedgerReload(t *testing.T, cfg config.Local) {
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState := getInitState()
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
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
			if latestCommitted, _ := l.LatestCommitted(); latestCommitted != blk.BlockHeader.Round {
				blk.BlockHeader.Round = latestCommitted
			}
		}
		if i%13 == 0 {
			l.WaitForCommit(blk.Round())
		}
	}
}

func TestLedgerReload(t *testing.T) {
	partitiontest.PartitionTest(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledgertesting.WithAndWithoutLRUCache(t, cfg, testLedgerReload)
}

// TestGetLastCatchpointLabel tests ledger.GetLastCatchpointLabel is returning the correct value.
func TestGetLastCatchpointLabel(t *testing.T) {
	partitiontest.PartitionTest(t)

	//initLedger
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	const inMem = true
	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer ledger.Close()

	// set some value
	lastCatchpointLabel := "someCatchpointLabel"
	ledger.catchpoint.lastCatchpointLabel = lastCatchpointLabel

	// verify the value is returned
	require.Equal(t, lastCatchpointLabel, ledger.GetLastCatchpointLabel())
}

// generate at least 3 asset and 3 app creatables, and return the ids
// of the asset/app with at least 3 elements less or equal.
func generateCreatables(numElementsPerSegement int) (
	randomCtbs map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	assetID3,
	appID3 basics.CreatableIndex,
	err error) {

	_, randomCtbs = randomCreatables(numElementsPerSegement)
	asCounter3 := 0
	apCounter3 := 0

	for x := 0; x < 10; x++ {
		// find the assetid greater than at least 2 assetids
		for cID, crtble := range randomCtbs {
			switch crtble.Ctype {
			case basics.AssetCreatable:
				if assetID3 == 0 {
					assetID3 = cID
					continue
				}
				asCounter3++
				if assetID3 < cID {
					assetID3 = cID
				}
			case basics.AppCreatable:
				if appID3 == 0 {
					appID3 = cID
					continue
				}
				apCounter3++
				if appID3 < cID {
					appID3 = cID
				}
			}
			if asCounter3 >= 3 && apCounter3 >= 3 {
				// found at least 3rd smallest of both
				break
			}
		}

		// there should be at least 3 asset and 3 app creatables generated.
		// In the rare event this does not happen, repeat... up to 10 times (x)
		if asCounter3 >= 3 && apCounter3 >= 3 {
			break
		}
	}
	if asCounter3 < 3 && apCounter3 < 3 {
		return nil, 0, 0, fmt.Errorf("could not generate 3 apps and 3 assets")
	}
	return
}

// TestLedgerVerifiesOldStateProofs test that if stateproof chain is delayed for X intervals (pass StateProofMaxRecoveryIntervals),
// The ledger will still be able to verify the state proof - i.e the ledger has the necessary data to verify it.
func TestLedgerVerifiesOldStateProofs(t *testing.T) {
	partitiontest.PartitionTest(t)

	// since the first state proof is expected to happen on stateproofInterval*2 we would start
	// give-up on state proofs only after stateproofInterval*3
	maxBlocks := int((config.Consensus[protocol.ConsensusFuture].StateProofMaxRecoveryIntervals + 2) * config.Consensus[protocol.ConsensusFuture].StateProofInterval)
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusFuture, 10000000000)

	// place real values on the participation period, so we would create a commitment with some stake.
	accountsWithValid := make(map[basics.Address]basics.AccountData)
	for addr, elem := range genesisInitState.Accounts {
		newAccount := elem
		newAccount.Status = basics.Online
		newAccount.VoteFirstValid = 1
		newAccount.VoteLastValid = 10000
		newAccount.VoteKeyDilution = 10
		crypto.RandBytes(newAccount.VoteID[:])
		crypto.RandBytes(newAccount.SelectionID[:])
		crypto.RandBytes(newAccount.StateProofID[:])
		accountsWithValid[addr] = newAccount
	}
	genesisInitState.Accounts = accountsWithValid

	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	const inMem = false
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer func() {
		l.Close()
		os.Remove(dbName + ".block.sqlite")
		os.Remove(dbName + ".tracker.sqlite")
	}()

	lastBlock, err := l.Block(l.Latest())
	require.NoError(t, err)
	proto := config.Consensus[lastBlock.CurrentProtocol]
	accounts := make(map[basics.Address]basics.AccountData, len(genesisInitState.Accounts)+maxBlocks)
	keys := make(map[basics.Address]*crypto.SignatureSecrets, len(initKeys)+maxBlocks)
	// regular addresses: all init accounts minus pools

	addresses := make([]basics.Address, len(genesisInitState.Accounts)-2, len(genesisInitState.Accounts)+maxBlocks)
	i := uint64(0)
	for addr := range genesisInitState.Accounts {
		if addr != testPoolAddr && addr != testSinkAddr {
			addresses[i] = addr
			i++
		}
		accounts[addr] = genesisInitState.Accounts[addr]
		keys[addr] = initKeys[addr]
	}

	for i = 0; i < uint64(maxBlocks)+proto.StateProofInterval; i++ {
		addDummyBlock(t, addresses, proto, l, initKeys, genesisInitState)
	}
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	// wait all pending commits to finish
	l.trackers.accountsWriting.Wait()

	// quit the commitSyncer goroutine: this test flushes manually with triggerTrackerFlush
	l.trackers.ctxCancel()
	l.trackers.ctxCancel = nil
	<-l.trackers.commitSyncerClosed
	l.trackers.commitSyncerClosed = nil

	triggerTrackerFlush(t, l)
	l.WaitForCommit(l.Latest())
	blk := createBlkWithStateproof(t, maxBlocks, proto, genesisInitState, l, accounts)
	_, err = l.Validate(context.Background(), blk, backlogPool)
	require.ErrorContains(t, err, "state proof crypto error")

	for i = 0; i < proto.StateProofInterval; i++ {
		addDummyBlock(t, addresses, proto, l, initKeys, genesisInitState)
	}

	triggerTrackerFlush(t, l)
	addDummyBlock(t, addresses, proto, l, initKeys, genesisInitState)
	l.WaitForCommit(l.Latest())
	// At this point the block queue go-routine will start removing block . However, it might not complete the task
	// for that reason, we wait for the next block to be committed.
	addDummyBlock(t, addresses, proto, l, initKeys, genesisInitState)
	l.WaitForCommit(l.Latest())

	// we make sure that the voters header does not exist and that the voters tracker
	// lost tracking of the top voters.
	_, err = l.BlockHdr(basics.Round(proto.StateProofInterval))
	require.Error(t, err)
	expectedErr := &ledgercore.ErrNoEntry{}
	require.ErrorAs(t, err, expectedErr, fmt.Sprintf("got error %s", err))

	l.acctsOnline.voters.votersMu.Lock()
	for k := range l.acctsOnline.voters.votersForRoundCache {
		require.NotEqual(t, k, basics.Round(proto.StateProofInterval-proto.StateProofVotersLookback), "found voters for round 200, it should have been removed")
	}
	l.acctsOnline.voters.votersMu.Unlock()

	// However, we are still able to very a state proof since we use the tracker
	blk = createBlkWithStateproof(t, maxBlocks, proto, genesisInitState, l, accounts)
	_, err = l.Validate(context.Background(), blk, backlogPool)
	require.ErrorContains(t, err, "state proof crypto error")
}

func createBlkWithStateproof(t *testing.T, maxBlocks int, proto config.ConsensusParams, genesisInitState ledgercore.InitState, l *Ledger, accounts map[basics.Address]basics.AccountData) bookkeeping.Block {
	sp := stateproof.StateProof{SignedWeight: 5000000000000000}
	var stxn transactions.SignedTxn
	stxn.Txn.Type = protocol.StateProofTx
	stxn.Txn.Sender = transactions.StateProofSender
	stxn.Txn.FirstValid = basics.Round(uint64(maxBlocks) - proto.StateProofInterval)
	stxn.Txn.LastValid = stxn.Txn.FirstValid + basics.Round(proto.MaxTxnLife)
	stxn.Txn.GenesisHash = genesisInitState.GenesisHash
	stxn.Txn.StateProofType = protocol.StateProofBasic
	stxn.Txn.Message.LastAttestedRound = 512
	stxn.Txn.StateProof = sp

	blk := makeNewEmptyBlock(t, l, t.Name(), accounts)
	proto = config.Consensus[blk.CurrentProtocol]
	for _, stx := range []transactions.SignedTxn{stxn} {
		txib, err := blk.EncodeSignedTxn(stx, transactions.ApplyData{})
		require.NoError(t, err)
		if proto.TxnCounter {
			blk.TxnCounter = blk.TxnCounter + 1
		}
		blk.Payset = append(blk.Payset, txib)
	}

	var err error
	blk.TxnCommitments, err = blk.PaysetCommit()
	require.NoError(t, err)
	return blk
}

func addDummyBlock(t *testing.T, addresses []basics.Address, proto config.ConsensusParams, l *Ledger, initKeys map[basics.Address]*crypto.SignatureSecrets, genesisInitState ledgercore.InitState) {
	numOfTransactions := 2
	stxns := make([]transactions.SignedTxn, numOfTransactions)
	for j := 0; j < numOfTransactions; j++ {
		txHeader := transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid:  l.Latest() + 1,
			LastValid:   l.Latest() + 10,
			GenesisID:   t.Name(),
			GenesisHash: crypto.Hash([]byte(t.Name())),
			Note:        []byte{uint8(j)},
		}

		payment := transactions.PaymentTxnFields{
			Receiver: addresses[0],
			Amount:   basics.MicroAlgos{Raw: 1000},
		}

		tx := transactions.Transaction{
			Type:             protocol.PaymentTx,
			Header:           txHeader,
			PaymentTxnFields: payment,
		}
		stxns[j] = sign(initKeys, tx)
	}
	err := l.addBlockTxns(t, genesisInitState.Accounts, stxns, transactions.ApplyData{})
	require.NoError(t, err)

}

func TestLedgerMemoryLeak(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip() // for manual runs only
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 10000000000)
	const inMem = false
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)   // prevent spamming with ledger.AddValidatedBlock debug message
	deadlock.Opts.Disable = true // catchpoint writing might take long
	defer func() {
		deadlock.Opts.Disable = false
	}()
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	const maxBlocks = 1_000_000
	nftPerAcct := make(map[basics.Address]int)
	lastBlock, err := l.Block(l.Latest())
	require.NoError(t, err)
	proto := config.Consensus[lastBlock.CurrentProtocol]
	accounts := make(map[basics.Address]basics.AccountData, len(genesisInitState.Accounts)+maxBlocks)
	keys := make(map[basics.Address]*crypto.SignatureSecrets, len(initKeys)+maxBlocks)
	// regular addresses: all init accounts minus pools
	addresses := make([]basics.Address, len(genesisInitState.Accounts)-2, len(genesisInitState.Accounts)+maxBlocks)
	i := 0
	for addr := range genesisInitState.Accounts {
		if addr != testPoolAddr && addr != testSinkAddr {
			addresses[i] = addr
			i++
		}
		accounts[addr] = genesisInitState.Accounts[addr]
		keys[addr] = initKeys[addr]
	}

	fmt.Printf("%s\t%s\t%s\t%s\n", "Round", "TotalAlloc, MB", "HeapAlloc, MB", "LiveObj")
	fmt.Printf("%s\t%s\t%s\t%s\n", "-----", "--------------", "-------------", "-------")

	curAddressIdx := 0
	// run for maxBlocks rounds
	// generate 1000 txn per block
	for i := 0; i < maxBlocks; i++ {
		stxns := make([]transactions.SignedTxn, 1000)
		for j := 0; j < 1000; j++ {
			txHeader := transactions.Header{
				Sender:      addresses[curAddressIdx],
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
				FirstValid:  l.Latest() + 1,
				LastValid:   l.Latest() + 10,
				GenesisID:   t.Name(),
				GenesisHash: crypto.Hash([]byte(t.Name())),
			}

			assetCreateFields := transactions.AssetConfigTxnFields{
				AssetParams: basics.AssetParams{
					Total:     10000000,
					UnitName:  fmt.Sprintf("unit_%d_%d", i, j),
					AssetName: fmt.Sprintf("asset_%d_%d", i, j),
				},
			}

			tx := transactions.Transaction{
				Type:                 protocol.AssetConfigTx,
				Header:               txHeader,
				AssetConfigTxnFields: assetCreateFields,
			}
			stxns[j] = sign(initKeys, tx)
			nftPerAcct[addresses[curAddressIdx]]++

			if nftPerAcct[addresses[curAddressIdx]] >= 990 {
				// switch to another account
				if curAddressIdx == len(addresses)-1 {
					// create new account
					var seed crypto.Seed
					seed[1] = byte(curAddressIdx % 256)
					seed[2] = byte((curAddressIdx >> 8) % 256)
					seed[3] = byte((curAddressIdx >> 16) % 256)
					seed[4] = byte((curAddressIdx >> 24) % 256)
					x := crypto.GenerateSignatureSecrets(seed)
					addr := basics.Address(x.SignatureVerifier)
					sender := addresses[rand.Intn(len(genesisInitState.Accounts)-2)] // one of init accounts
					correctTxHeader := transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
						FirstValid:  l.Latest() + 1,
						LastValid:   l.Latest() + 10,
						GenesisID:   t.Name(),
						GenesisHash: genesisInitState.GenesisHash,
					}

					correctPayFields := transactions.PaymentTxnFields{
						Receiver: addr,
						Amount:   basics.MicroAlgos{Raw: 1000 * 1000000},
					}

					correctPay := transactions.Transaction{
						Type:             protocol.PaymentTx,
						Header:           correctTxHeader,
						PaymentTxnFields: correctPayFields,
					}

					err = l.appendUnvalidatedTx(t, accounts, keys, correctPay, transactions.ApplyData{})
					require.NoError(t, err)
					ad, _, _, err := l.LookupLatest(addr)
					require.NoError(t, err)

					addresses = append(addresses, addr)
					keys[addr] = x
					accounts[addr] = ad
				}
				curAddressIdx++
			}
		}
		err = l.addBlockTxns(t, genesisInitState.Accounts, stxns, transactions.ApplyData{})
		require.NoError(t, err)

		latest := l.Latest()
		if latest%100 == 0 {
			l.WaitForCommit(latest)
		}
		if latest%1000 == 0 || i%1000 == 0 && i > 0 {
			// pct := debug.SetGCPercent(-1) // prevent CG in between memory stats reading and heap profiling

			var rtm runtime.MemStats
			runtime.ReadMemStats(&rtm)
			const meg = 1024 * 1024
			fmt.Printf("%5d\t%14d\t%13d\t%7d\n", latest, rtm.TotalAlloc/meg, rtm.HeapAlloc/meg, rtm.Mallocs-rtm.Frees)

			// Use the code below to generate memory profile if needed for debugging
			// memprofile := fmt.Sprintf("%s-memprof-%d", t.Name(), latest)
			// f, err := os.Create(memprofile)
			// require.NoError(t, err)
			// err = pprof.WriteHeapProfile(f)
			// require.NoError(t, err)
			// f.Close()

			// debug.SetGCPercent(pct)
		}
	}
}

// TestLookupAgreement ensures LookupAgreement return an empty data for offline accounts
func TestLookupAgreement(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	var addrOnline, addrOffline basics.Address
	for addr, ad := range genesisInitState.Accounts {
		if addrOffline.IsZero() {
			addrOffline = addr
			ad.Status = basics.Offline
			crypto.RandBytes(ad.VoteID[:]) // this is invalid but we set VoteID to ensure the account gets cleared
			genesisInitState.Accounts[addr] = ad
		} else if ad.Status == basics.Online {
			addrOnline = addr
			crypto.RandBytes(ad.VoteID[:])
			genesisInitState.Accounts[addr] = ad
			break
		}
	}

	const inMem = true
	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer ledger.Close()

	oad, err := ledger.LookupAgreement(0, addrOnline)
	require.NoError(t, err)
	require.NotEmpty(t, oad)
	ad, _, _, err := ledger.LookupLatest(addrOnline)
	require.NoError(t, err)
	require.NotEmpty(t, ad)
	require.Equal(t, oad, basics_testing.OnlineAccountData(ad))

	require.NoError(t, err)
	oad, err = ledger.LookupAgreement(0, addrOffline)
	require.NoError(t, err)
	require.Empty(t, oad)
	ad, _, _, err = ledger.LookupLatest(addrOffline)
	require.NoError(t, err)
	require.NotEmpty(t, ad)
	require.Equal(t, oad, basics_testing.OnlineAccountData(ad))
}

func TestGetKnockOfflineCandidates(t *testing.T) {
	partitiontest.PartitionTest(t)

	ver := protocol.ConsensusFuture
	genesisInitState, _ := ledgertesting.GenerateInitState(t, ver, 1_000_000)
	const inMem = true
	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer ledger.Close()

	accts, err := ledger.GetKnockOfflineCandidates(0, config.Consensus[ver])
	require.NoError(t, err)
	require.NotEmpty(t, accts)
	// get online genesis accounts
	onlineCnt := 0
	onlineAddrs := make(map[basics.Address]basics.OnlineAccountData)
	for addr, ad := range genesisInitState.Accounts {
		if ad.Status == basics.Online {
			onlineCnt++
			onlineAddrs[addr] = basics_testing.OnlineAccountData(ad)
		}
	}
	require.Len(t, accts, onlineCnt)
	require.Equal(t, onlineAddrs, accts)
}

func BenchmarkLedgerStartup(b *testing.B) {
	log := logging.TestingLog(b)
	tmpDir := b.TempDir()
	genesisInitState, _ := ledgertesting.GenerateInitState(b, protocol.ConsensusCurrentVersion, 100)

	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	testOpenLedger := func(b *testing.B, memory bool, cfg config.Local) {
		b.StartTimer()
		for n := 0; n < b.N; n++ {
			ledger, err := OpenLedger(log, tmpDir, memory, genesisInitState, cfg)
			require.NoError(b, err)
			ledger.Close()
			os.RemoveAll(tmpDir)
			os.Mkdir(tmpDir, 0766)
		}
	}

	b.Run("MemoryDatabase/NonArchival", func(b *testing.B) {
		testOpenLedger(b, true, cfg)
	})

	b.Run("DiskDatabase/NonArchival", func(b *testing.B) {
		testOpenLedger(b, false, cfg)
	})

	cfg.Archival = true
	b.Run("MemoryDatabase/Archival", func(b *testing.B) {
		testOpenLedger(b, true, cfg)
	})

	b.Run("DiskDatabase/Archival", func(b *testing.B) {
		testOpenLedger(b, false, cfg)
	})
}

// TestLedgerReloadShrinkDeltas checks the ledger has correct account state
// after reloading with new configuration with shorter in-memory deltas for trackers
func TestLedgerReloadShrinkDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 10_000_000_000)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	const inMem = false
	cfg := config.GetDefaultLocal()
	cfg.MaxAcctLookback = proto.MaxBalLookback
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info) // prevent spamming with ledger.AddValidatedBlock debug message
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer func() {
		l.Close()
		os.Remove(dbName + ".block.sqlite")
		os.Remove(dbName + ".tracker.sqlite")
	}()

	maxBlocks := int(proto.MaxBalLookback * 2)
	accounts := make(map[basics.Address]basics.AccountData, len(genesisInitState.Accounts))
	keys := make(map[basics.Address]*crypto.SignatureSecrets, len(initKeys))
	// regular addresses: all init accounts minus pools
	addresses := make([]basics.Address, len(genesisInitState.Accounts)-2, len(genesisInitState.Accounts))
	i := 0
	for addr := range genesisInitState.Accounts {
		if addr != testPoolAddr && addr != testSinkAddr {
			addresses[i] = addr
			i++
		}
		accounts[addr] = genesisInitState.Accounts[addr]
		keys[addr] = initKeys[addr]
	}
	sort.SliceStable(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) == -1 })

	onlineTotals := make([]basics.MicroAlgos, maxBlocks+1)
	curAddressIdx := 0
	maxValidity := basics.Round(20) // some number different from number of txns in blocks
	txnIDs := make(map[basics.Round]map[transactions.Txid]struct{})
	// run for maxBlocks rounds with random payment transactions
	// generate 1000 txn per block
	for i := 0; i < maxBlocks; i++ {
		stxns := make([]transactions.SignedTxn, 10)
		latest := l.Latest()
		txnIDs[latest+1] = make(map[transactions.Txid]struct{})
		for j := 0; j < 10; j++ {
			feeMult := rand.Intn(5) + 1
			amountMult := rand.Intn(1000) + 1
			receiver := ledgertesting.RandomAddress()
			txHeader := transactions.Header{
				Sender:      addresses[curAddressIdx],
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * uint64(feeMult)},
				FirstValid:  latest + 1,
				LastValid:   latest + maxValidity,
				GenesisID:   t.Name(),
				GenesisHash: crypto.Hash([]byte(t.Name())),
			}

			correctPayFields := transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: uint64(100 * amountMult)},
			}

			tx := transactions.Transaction{
				Type:             protocol.PaymentTx,
				Header:           txHeader,
				PaymentTxnFields: correctPayFields,
			}

			stxns[j] = sign(initKeys, tx)
			curAddressIdx = (curAddressIdx + 1) % len(addresses)
			txnIDs[latest+1][tx.ID()] = struct{}{}
		}
		err = l.addBlockTxns(t, genesisInitState.Accounts, stxns, transactions.ApplyData{})
		require.NoError(t, err)
		if i%100 == 0 || i == maxBlocks-1 {
			l.WaitForCommit(latest + 1)
		}
		onlineTotals[i+1], err = l.accts.onlineTotals(basics.Round(i + 1))
		require.NoError(t, err)
	}

	latest := l.Latest()
	nextRound := latest + 1
	balancesRound := nextRound.SubSaturate(basics.Round(proto.MaxBalLookback))

	origBalances := make([]basics.MicroAlgos, len(addresses))
	origRewardsBalances := make([]basics.MicroAlgos, len(addresses))
	origAgreementBalances := make([]basics.MicroAlgos, len(addresses))
	for i, addr := range addresses {
		ad, rnd, err := l.LookupWithoutRewards(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		origBalances[i] = ad.MicroAlgos

		acct, rnd, wo, err := l.LookupAccount(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		require.Equal(t, origBalances[i], wo)
		origRewardsBalances[i] = acct.MicroAlgos

		oad, err := l.LookupAgreement(balancesRound, addr)
		require.NoError(t, err)
		origAgreementBalances[i] = oad.MicroAlgosWithRewards
	}

	var nonZeros int
	for _, bal := range origAgreementBalances {
		if bal.Raw > 0 {
			nonZeros++
		}
	}
	require.Greater(t, nonZeros, 0)

	// at round "maxBlocks" the ledger must have maxValidity blocks of transactions
	for i := latest; i <= latest+maxValidity; i++ {
		for txid := range txnIDs[i] {
			require.NoError(t, l.CheckDup(proto, nextRound, i-maxValidity, i, txid, ledgercore.Txlease{}))
		}
	}

	// check an error latest-1
	for txid := range txnIDs[latest-1] {
		require.Error(t, l.CheckDup(proto, nextRound, latest-maxValidity, latest-1, txid, ledgercore.Txlease{}))
	}

	shorterLookback := config.GetDefaultLocal().MaxAcctLookback
	require.Less(t, shorterLookback, cfg.MaxAcctLookback)
	cfg.MaxAcctLookback = shorterLookback
	l.cfg = cfg
	l.reloadLedger()

	rnd := basics.Round(proto.MaxBalLookback - shorterLookback)
	_, err = l.OnlineCirculation(rnd, rnd+basics.Round(proto.MaxBalLookback))
	require.Error(t, err)
	for i := basics.Round(proto.MaxBalLookback - shorterLookback + 1); i <= l.Latest(); i++ {
		online, err := l.OnlineCirculation(i, i+basics.Round(proto.MaxBalLookback))
		require.NoError(t, err)
		require.Equal(t, onlineTotals[i], online)
	}

	for i, addr := range addresses {
		ad, rnd, err := l.LookupWithoutRewards(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		require.Equal(t, origBalances[i], ad.MicroAlgos)

		acct, rnd, wo, err := l.LookupAccount(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		require.Equal(t, origRewardsBalances[i], acct.MicroAlgos)
		require.Equal(t, origBalances[i], wo)

		oad, err := l.LookupAgreement(balancesRound, addr)
		require.NoError(t, err)
		require.Equal(t, origAgreementBalances[i], oad.MicroAlgosWithRewards)

		// TODO:
		// add a test checking all committed pre-reload entries are gone
		// add as a tracker test
	}

	// at round maxBlocks the ledger must have maxValidity blocks of transactions, check
	for i := latest; i <= latest+maxValidity; i++ {
		for txid := range txnIDs[i] {
			require.NoError(t, l.CheckDup(proto, nextRound, i-maxValidity, i, txid, ledgercore.Txlease{}))
		}
	}

	// check an error latest-1
	for txid := range txnIDs[latest-1] {
		require.Error(t, l.CheckDup(proto, nextRound, latest-maxValidity, latest-1, txid, ledgercore.Txlease{}))
	}
}

func resetAccountDBToV6(t *testing.T, l *Ledger) {
	// reset tables and re-init again, similarly to the catchpount apply code
	// since the ledger has only genesis accounts, this recreates them
	err := l.trackerDBs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		arw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		err0 := arw.AccountsReset(ctx)
		if err0 != nil {
			return err0
		}
		tp := trackerdb.Params{
			InitAccounts:      l.GenesisAccounts(),
			InitProto:         l.GenesisProtoVersion(),
			GenesisHash:       l.GenesisHash(),
			FromCatchpoint:    true,
			CatchpointEnabled: l.catchpoint.catchpointEnabled(),
			DbPathPrefix:      l.catchpoint.dbDirectory,
			BlockDb:           l.blockDBs,
		}
		_, err0 = tx.RunMigrations(ctx, tp, l.log, preReleaseDBVersion /*target database version*/)
		if err0 != nil {
			return err0
		}

		if err0 := tx.Testing().AccountsUpdateSchemaTest(ctx); err0 != nil {
			return err0
		}

		return nil
	})
	require.NoError(t, err)
}

// TestLedgerReloadTxTailHistoryAccess checks txtail has MaxTxnLife + DeeperBlockHeaderHistory block headers
// for TEAL after applying catchpoint.
// Simulate catchpoints by the following:
// 1. Say ledger is at version 6 (pre shorher deltas)
// 2. Put 2000 empty blocks
// 3. Reload and upgrade to version 7 (that's what catchpoint apply code does)
// 4. Add 2001 block with a txn first=1001, last=2001 and block data access for 1000
// 5. Expect the txn to be accepted
func TestLedgerReloadTxTailHistoryAccess(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 10_000_000_000)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	const inMem = true
	cfg := config.GetDefaultLocal()

	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer func() {
		l.Close()
	}()

	// reset tables and re-init again, similarly to the catchpount apply code
	// since the ledger has only genesis accounts, this recreates them
	err = l.trackerDBs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		arw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		err0 := arw.AccountsReset(ctx)
		if err0 != nil {
			return err0
		}
		tp := trackerdb.Params{
			InitAccounts:      l.GenesisAccounts(),
			InitProto:         l.GenesisProtoVersion(),
			GenesisHash:       l.GenesisHash(),
			FromCatchpoint:    true,
			CatchpointEnabled: l.catchpoint.catchpointEnabled(),
			DbPathPrefix:      l.catchpoint.dbDirectory,
			BlockDb:           l.blockDBs,
		}
		_, err0 = tx.RunMigrations(ctx, tp, l.log, preReleaseDBVersion /*target database version*/)
		if err0 != nil {
			return err0
		}

		return tx.Testing().AccountsUpdateSchemaTest(ctx)
	})
	require.NoError(t, err)

	var sender basics.Address
	var key *crypto.SignatureSecrets
	for addr := range genesisInitState.Accounts {
		if addr != testPoolAddr && addr != testSinkAddr {
			sender = addr
			key = initKeys[addr]
			break
		}
	}

	roundToTimeStamp := func(rnd int) int64 {
		return int64(rnd*1000 + rnd)
	}

	blk := genesisInitState.Block
	maxBlocks := 2 * int(proto.MaxTxnLife) // 2000 blocks to add
	for i := 1; i <= maxBlocks; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp = roundToTimeStamp(i)
		err = l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)
		if i%100 == 0 || i == maxBlocks-1 {
			l.WaitForCommit(blk.BlockHeader.Round)
		}
	}

	// drop new tables
	// reloadLedger should migrate db properly
	err = l.trackerDBs.ResetToV6Test(context.Background())
	require.NoError(t, err)

	err = l.reloadLedger()
	require.NoError(t, err)

	source := fmt.Sprintf(`#pragma version 7
int %d // 1000
block BlkTimestamp
int %d // 10001000
==
`, proto.MaxTxnLife, roundToTimeStamp(int(proto.MaxTxnLife)))

	ops, err := logic.AssembleString(source)
	require.NoError(t, err)
	approvalProgram := ops.Program

	clearStateProgram := []byte("\x07") // empty
	appcreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
		LocalStateSchema:  basics.StateSchema{NumUint: 1},
	}

	correctTxHeader := transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  basics.Round(proto.MaxTxnLife + 1),
		LastValid:   basics.Round(2*proto.MaxTxnLife + 1),
		GenesisID:   genesisInitState.Block.GenesisID(),
		GenesisHash: genesisInitState.GenesisHash,
	}

	appcreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   correctTxHeader,
		ApplicationCallTxnFields: appcreateFields,
	}

	stx := sign(map[basics.Address]*crypto.SignatureSecrets{sender: key}, appcreate)
	txib, err := blk.EncodeSignedTxn(stx, transactions.ApplyData{})
	require.NoError(t, err)

	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp++
	blk.TxnCounter++
	blk.Payset = append(blk.Payset, txib)
	blk.TxnCommitments, err = blk.PaysetCommit()
	require.NoError(t, err)

	err = l.AddBlock(blk, agreement.Certificate{})
	require.NoError(t, err)

	latest := l.Latest()
	require.Equal(t, basics.Round(2*proto.MaxTxnLife+1), latest)

	// add couple more blocks to have the block with `blk BlkTimestamp` to be dbRound + 1
	// reload again and ensure this block can be replayed
	programRound := blk.BlockHeader.Round
	target := latest + basics.Round(cfg.MaxAcctLookback) - 1
	blk = genesisInitState.Block
	blk.BlockHeader.Round = latest
	for i := latest + 1; i <= target; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp = roundToTimeStamp(int(i))
		err = l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)
	}

	commitRoundLookback(basics.Round(cfg.MaxAcctLookback), l)
	l.trackers.mu.RLock()
	require.Equal(t, programRound, l.trackers.dbRound+1) // programRound is next to be replayed
	l.trackers.mu.RUnlock()
	err = l.reloadLedger()
	require.NoError(t, err)
}

// TestLedgerMigrateV6ShrinkDeltas opens a ledger + dbV6, submits a bunch of txns,
// then migrates db and reopens ledger, and checks that the state is correct
func TestLedgerMigrateV6ShrinkDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	prevAccountDBVersion := trackerdb.AccountDBVersion
	trackerdb.AccountDBVersion = 6
	defer func() {
		trackerdb.AccountDBVersion = prevAccountDBVersion
	}()
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-migrate-shrink-deltas")
	proto := config.Consensus[protocol.ConsensusV31]
	proto.RewardsRateRefreshInterval = 200
	config.Consensus[testProtocolVersion] = proto
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, testProtocolVersion, 10_000_000_000)
	const inMem = false
	cfg := config.GetDefaultLocal()
	cfg.MaxAcctLookback = proto.MaxBalLookback
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info) // prevent spamming with ledger.AddValidatedBlock debug message
	// Set basic Directory for all resources
	dirs := DirsAndPrefix{
		DBFilePrefix: "",
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			RootGenesisDir:       dbName,
			HotGenesisDir:        dbName,
			ColdGenesisDir:       dbName,
			TrackerGenesisDir:    dbName,
			BlockGenesisDir:      dbName,
			CatchpointGenesisDir: dbName,
		},
	}
	trackerDB, blockDB, err := openLedgerDB(dirs, inMem, cfg, log)
	require.NoError(t, err)
	defer func() {
		trackerDB.Close()
		blockDB.Close()
	}()
	// create tables so online accounts can still be written
	err = trackerDB.Batch(func(ctx context.Context, tx trackerdb.BatchScope) error {
		return tx.Testing().AccountsUpdateSchemaTest(ctx)
	})
	require.NoError(t, err)

	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer func() {
		l.Close()
		os.Remove(dbName + ".block.sqlite")
		os.Remove(dbName + ".tracker.sqlite")
		os.Remove(dbName + ".block.sqlite-shm")
		os.Remove(dbName + ".tracker.sqlite-shm")
		os.Remove(dbName + ".block.sqlite-wal")
		os.Remove(dbName + ".tracker.sqlite-wal")
	}()

	// remove online tracker in order to make v6 schema work
	for i := range l.trackers.trackers {
		if l.trackers.trackers[i] == l.trackers.acctsOnline {
			l.trackers.trackers = append(l.trackers.trackers[:i], l.trackers.trackers[i+1:]...)
			break
		}
	}
	l.trackers.acctsOnline = nil
	l.acctsOnline = onlineAccounts{}

	maxBlocks := 1000
	accounts := make(map[basics.Address]basics.AccountData, len(genesisInitState.Accounts))
	keys := make(map[basics.Address]*crypto.SignatureSecrets, len(initKeys))
	// regular addresses: all init accounts minus pools
	addresses := make([]basics.Address, len(genesisInitState.Accounts)-2, len(genesisInitState.Accounts))
	i := 0
	for addr := range genesisInitState.Accounts {
		if addr != testPoolAddr && addr != testSinkAddr {
			addresses[i] = addr
			i++
		}
		accounts[addr] = genesisInitState.Accounts[addr]
		keys[addr] = initKeys[addr]
	}
	sort.SliceStable(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) == -1 })

	onlineTotals := make([]basics.MicroAlgos, maxBlocks+1)
	curAddressIdx := 0
	maxValidity := basics.Round(20) // some number different from number of txns in blocks
	txnIDs := make(map[basics.Round]map[transactions.Txid]struct{})
	// run for maxBlocks rounds with random payment transactions
	// generate numTxns txn per block
	for i := 0; i < maxBlocks; i++ {
		numTxns := crypto.RandUint64()%9 + 7
		stxns := make([]transactions.SignedTxn, numTxns)
		latest := l.Latest()
		txnIDs[latest+1] = make(map[transactions.Txid]struct{})
		for j := 0; j < int(numTxns); j++ {
			feeMult := rand.Intn(5) + 1
			amountMult := rand.Intn(1000) + 1
			receiver := ledgertesting.RandomAddress()
			txHeader := transactions.Header{
				Sender:      addresses[curAddressIdx],
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * uint64(feeMult)},
				FirstValid:  latest + 1,
				LastValid:   latest + maxValidity,
				GenesisID:   t.Name(),
				GenesisHash: crypto.Hash([]byte(t.Name())),
			}

			tx := transactions.Transaction{
				Header: txHeader,
			}

			// have one txn be a keyreg txn that flips online to offline
			// have all other txns be random payment txns
			if j == 0 {
				var keyregTxnFields transactions.KeyregTxnFields
				// keep low accounts online, high accounts offline
				// otherwise all accounts become offline eventually and no agreement balances to check
				if curAddressIdx < len(addresses)/2 {
					keyregTxnFields = transactions.KeyregTxnFields{
						VoteFirst: latest + 1,
						VoteLast:  latest + 100_000,
					}
					var votepk crypto.OneTimeSignatureVerifier
					votepk[0] = byte(j % 256)
					votepk[1] = byte(i % 256)
					votepk[2] = byte(254)
					var selpk crypto.VRFVerifier
					selpk[0] = byte(j % 256)
					selpk[1] = byte(i % 256)
					selpk[2] = byte(255)

					keyregTxnFields.VotePK = votepk
					keyregTxnFields.SelectionPK = selpk
				}
				tx.Type = protocol.KeyRegistrationTx
				tx.KeyregTxnFields = keyregTxnFields
			} else {
				correctPayFields := transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: uint64(100 * amountMult)},
				}
				tx.Type = protocol.PaymentTx
				tx.PaymentTxnFields = correctPayFields
			}

			stxns[j] = sign(initKeys, tx)
			curAddressIdx = (curAddressIdx + 1) % len(addresses)
			txnIDs[latest+1][tx.ID()] = struct{}{}
		}
		err = l.addBlockTxns(t, genesisInitState.Accounts, stxns, transactions.ApplyData{})
		require.NoError(t, err)
		if i%100 == 0 || i == maxBlocks-1 {
			l.WaitForCommit(latest + 1)
		}
		onlineTotals[i+1], err = l.accts.onlineTotals(basics.Round(i + 1))
		require.NoError(t, err)
	}

	latest := l.Latest()
	nextRound := latest + 1
	balancesRound := nextRound.SubSaturate(basics.Round(proto.MaxBalLookback))

	origBalances := make([]basics.MicroAlgos, len(addresses))
	origRewardsBalances := make([]basics.MicroAlgos, len(addresses))
	origAgreementBalances := make([]basics.MicroAlgos, len(addresses))
	for i, addr := range addresses {
		ad, rnd, err := l.LookupWithoutRewards(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		origBalances[i] = ad.MicroAlgos

		acct, rnd, wo, err := l.LookupAccount(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		require.Equal(t, origBalances[i], wo)
		origRewardsBalances[i] = acct.MicroAlgos

		acct, rnd, _, err = l.LookupAccount(balancesRound, addr)
		require.NoError(t, err)
		require.Equal(t, balancesRound, rnd)
		if acct.Status == basics.Online {
			origAgreementBalances[i] = acct.MicroAlgos
		} else {
			origAgreementBalances[i] = basics.MicroAlgos{}
		}
	}

	var nonZeros int
	for _, bal := range origAgreementBalances {
		if bal.Raw > 0 {
			nonZeros++
		}
	}
	require.Greater(t, nonZeros, 0)

	// at round "maxBlocks" the ledger must have maxValidity blocks of transactions
	for i := latest; i <= latest+maxValidity; i++ {
		for txid := range txnIDs[i] {
			require.NoError(t, l.CheckDup(proto, nextRound, i-maxValidity, i, txid, ledgercore.Txlease{}))
		}
	}

	// check an error latest-1
	for txid := range txnIDs[latest-1] {
		require.Error(t, l.CheckDup(proto, nextRound, latest-maxValidity, latest-1, txid, ledgercore.Txlease{}))
	}

	shorterLookback := config.GetDefaultLocal().MaxAcctLookback
	require.Less(t, shorterLookback, cfg.MaxAcctLookback)
	l.Close()

	cfg.MaxAcctLookback = shorterLookback
	trackerdb.AccountDBVersion = 7
	// delete tables since we want to check they can be made from other data
	err = trackerDB.ResetToV6Test(context.Background())
	require.NoError(t, err)

	l2, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer func() {
		l2.Close()
	}()

	rnd := basics.Round(proto.MaxBalLookback - shorterLookback)
	_, err = l2.OnlineCirculation(rnd, rnd+basics.Round(proto.MaxBalLookback))
	require.Error(t, err)
	for i := l2.Latest() - basics.Round(proto.MaxBalLookback-1); i <= l2.Latest(); i++ {
		online, err := l2.OnlineCirculation(i, i+basics.Round(proto.MaxBalLookback))
		require.NoError(t, err)
		require.Equal(t, onlineTotals[i], online)
	}

	for i, addr := range addresses {
		ad, rnd, err := l2.LookupWithoutRewards(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		require.Equal(t, origBalances[i], ad.MicroAlgos)

		acct, rnd, wo, err := l2.LookupAccount(latest, addr)
		require.NoError(t, err)
		require.Equal(t, latest, rnd)
		require.Equal(t, origRewardsBalances[i], acct.MicroAlgos)
		require.Equal(t, origBalances[i], wo)

		oad, err := l2.LookupAgreement(balancesRound, addr)
		require.NoError(t, err)
		require.Equal(t, origAgreementBalances[i], oad.MicroAlgosWithRewards)
	}

	// at round maxBlocks the ledger must have maxValidity blocks of transactions, check
	for i := latest; i <= latest+maxValidity; i++ {
		for txid := range txnIDs[i] {
			require.NoError(t, l2.CheckDup(proto, nextRound, i-maxValidity, i, txid, ledgercore.Txlease{}))
		}
	}

	// check an error latest-1
	for txid := range txnIDs[latest-1] {
		require.Error(t, l2.CheckDup(proto, nextRound, latest-maxValidity, latest-1, txid, ledgercore.Txlease{}))
	}
}

// TestLedgerTxTailCachedBlockHeaders checks [Latest - MaxTxnLife...Latest] block headers
// are available via txTail
func TestLedgerTxTailCachedBlockHeaders(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusFuture, 10_000_000_000)
	const inMem = true
	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info) // prevent spamming with ledger.AddValidatedBlock debug message
	l, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	proto := config.Consensus[protocol.ConsensusFuture]
	maxBlocks := 2 * proto.MaxTxnLife
	for i := uint64(0); i < maxBlocks; i++ {
		err = l.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
		require.NoError(t, err)
		if i%100 == 0 || i == maxBlocks-1 {
			l.WaitForCommit(l.Latest())
		}
	}

	latest := l.Latest()
	for i := latest - basics.Round(proto.MaxTxnLife); i <= latest; i++ {
		blk, err := l.BlockHdr(i)
		require.NoError(t, err)
		require.Equal(t, blk.Round, i)
	}

	// additional checks: the txTail should have additional blocks:
	// dbRound - (MaxTxnLife+1) is expected to be deleted and dbRound - (MaxTxnLife) is earliest available
	l.trackerMu.RLock()
	dbRound := l.trackers.dbRound
	l.trackerMu.RUnlock()

	start := dbRound - basics.Round(proto.MaxTxnLife)
	end := latest - basics.Round(proto.MaxTxnLife)
	for i := start; i < end; i++ {
		blk, err := l.BlockHdr(i)
		require.NoError(t, err)
		require.Equal(t, blk.Round, i)
	}

	_, ok := l.txTail.blockHeader(start - 1)
	require.False(t, ok)
}

// TestLedgerKeyregFlip generates keyreg transactions for flipping genesis accounts state.
// It checks 1) lookup returns correct values 2) lookup agreement returns correct values
func TestLedgerKeyregFlip(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, initKeys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 10_000_000_000)
	const inMem = false
	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info) // prevent spamming with ledger.AddValidatedBlock debug message
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer func() {
		l.Close()
		os.Remove(dbName + ".block.sqlite")
		os.Remove(dbName + ".tracker.sqlite")
	}()

	const numFullBlocks = 1000
	const numEmptyBlocks = 500

	require.Equal(t, len(genesisInitState.Accounts), 12)
	const numAccounts = 10 // 12 - pool and sink

	// preallocate data for saving account info
	var accounts [numFullBlocks][numAccounts]ledgercore.AccountData

	lastBlock, err := l.Block(l.Latest())
	require.NoError(t, err)
	proto := config.Consensus[lastBlock.CurrentProtocol]

	// regular addresses: all init accounts minus pools
	addresses := make([]basics.Address, numAccounts)
	i := 0
	for addr := range genesisInitState.Accounts {
		if addr != testPoolAddr && addr != testSinkAddr {
			addresses[i] = addr
			i++
		}
	}

	isOnline := func(rndIdx, acctIdx, seed int) bool {
		return (rndIdx+acctIdx+seed)%4 == 1
	}
	// run for numFullBlocks rounds
	// generate 10 txn per block
	for i := 0; i < numFullBlocks; i++ {
		stxns := make([]transactions.SignedTxn, numAccounts)
		latest := l.Latest()
		require.Equal(t, basics.Round(i), latest)
		seed := int(crypto.RandUint63() % 1_000_000)
		for j := 0; j < numAccounts; j++ {
			txHeader := transactions.Header{
				Sender:      addresses[j],
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
				FirstValid:  latest + 1,
				LastValid:   latest + 10,
				GenesisID:   t.Name(),
				GenesisHash: crypto.Hash([]byte(t.Name())),
			}

			keyregFields := transactions.KeyregTxnFields{
				VoteFirst: latest + 1,
				VoteLast:  latest + 100_000,
			}
			if isOnline(i, j, seed) {
				var votepk crypto.OneTimeSignatureVerifier
				votepk[0] = byte(j % 256)
				votepk[1] = byte(i % 256)
				votepk[2] = byte(254)
				var selpk crypto.VRFVerifier
				selpk[0] = byte(j % 256)
				selpk[1] = byte(i % 256)
				selpk[2] = byte(255)

				keyregFields.VotePK = votepk
				keyregFields.SelectionPK = selpk
			}

			tx := transactions.Transaction{
				Type:            protocol.KeyRegistrationTx,
				Header:          txHeader,
				KeyregTxnFields: keyregFields,
			}
			stxns[j] = sign(initKeys, tx)
		}
		err = l.addBlockTxns(t, genesisInitState.Accounts, stxns, transactions.ApplyData{})
		require.NoError(t, err)
		for k := 0; k < numAccounts; k++ {
			data, rnd, _, err := l.LookupAccount(basics.Round(i+1), addresses[k])
			require.NoError(t, err)
			require.Equal(t, rnd, basics.Round(i+1))
			online := isOnline(i, k, seed)
			require.Equal(t, online, data.Status == basics.Online)
			if online {
				require.Equal(t, byte(k%256), data.VoteID[0])
				require.Equal(t, byte(i%256), data.VoteID[1])
				require.Equal(t, byte(254), data.VoteID[2])
				require.Equal(t, byte(k%256), data.SelectionID[0])
				require.Equal(t, byte(i%256), data.SelectionID[1])
				require.Equal(t, byte(255), data.SelectionID[2])
				accounts[i][k] = data
			}
		}
	}
	l.WaitForCommit(l.Latest())
	require.Equal(t, basics.Round(numFullBlocks), l.Latest())

	for i := 0; i < numEmptyBlocks; i++ {
		nextRound := basics.Round(numFullBlocks + i + 1)
		balancesRound := nextRound.SubSaturate(basics.Round(proto.MaxBalLookback))
		acctRoundIdx := int(balancesRound) - 1
		if acctRoundIdx >= len(accounts) {
			// checked all saved history, stop
			break
		}
		for k := 0; k < numAccounts; k++ {
			od, err := l.LookupAgreement(balancesRound, addresses[k])
			require.NoError(t, err)
			data := accounts[acctRoundIdx][k]
			require.Equal(t, data.MicroAlgos, od.MicroAlgosWithRewards)
			require.Equal(t, data.VoteFirstValid, od.VoteFirstValid)
			require.Equal(t, data.VoteLastValid, od.VoteLastValid)
			require.Equal(t, data.VoteID, od.VoteID)
		}
		err = l.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
		require.NoError(t, err)
	}
	l.WaitForCommit(l.Latest())
}

func verifyVotersContent(t *testing.T, expected map[basics.Round]*ledgercore.VotersForRound, actual map[basics.Round]*ledgercore.VotersForRound) {
	require.Equal(t, len(expected), len(actual))
	for k, v := range actual {
		require.NoError(t, v.Wait())
		require.Equal(t, expected[k].Tree, v.Tree)
		require.Equal(t, expected[k].Participants, v.Participants)
	}
}

func triggerDeleteVoters(t *testing.T, l *Ledger, genesisInitState ledgercore.InitState) {
	// We make the ledger flush tracker data to allow votersTracker to advance lowestRound
	triggerTrackerFlush(t, l)

	// We add another block to make the block queue query the voter's tracker lowest round again, which allows it to forget
	// rounds based on the new lowest round.
	triggerTrackerFlush(t, l)
}

func testVotersReloadFromDisk(t *testing.T, cfg config.Local) {

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusFuture, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true

	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	// we add blocks to the ledger to test reload from disk. we would like the history of the acctonline to extend.
	// but we don't want to go behind  stateproof recovery interval
	for i := uint64(0); i < (proto.StateProofInterval*(proto.StateProofMaxRecoveryIntervals-2) - proto.StateProofVotersLookback); i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	// at this point the database should contain the voter for round 256 but the voters for round 512 should be in deltas
	l.WaitForCommit(l.Latest())
	triggerTrackerFlush(t, l)
	vtSnapshot := l.acctsOnline.voters.votersForRoundCache

	// ensuring no tree was evicted.
	for _, round := range []basics.Round{240, 496} {
		require.Contains(t, vtSnapshot, round)
	}

	err = l.reloadLedger()
	require.NoError(t, err)

	verifyVotersContent(t, vtSnapshot, l.acctsOnline.voters.votersForRoundCache)
}

func TestVotersReloadFromDisk(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	cfg.MaxAcctLookback = proto.StateProofInterval - proto.StateProofVotersLookback - 10

	ledgertesting.WithAndWithoutLRUCache(t, cfg, testVotersReloadFromDisk)
}

func testVotersReloadFromDiskAfterOneStateProofCommitted(t *testing.T, cfg config.Local) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true

	log := logging.TestingLog(t)
	log.SetLevel(logging.Debug)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	// quit the commitSyncer goroutine: this test flushes manually with triggerTrackerFlush
	l.trackers.ctxCancel()
	l.trackers.ctxCancel = nil
	<-l.trackers.commitSyncerClosed
	l.trackers.commitSyncerClosed = nil

	blk := genesisInitState.Block

	sp := bookkeeping.StateProofTrackingData{
		StateProofNextRound: basics.Round(proto.StateProofInterval * 2),
	}

	blk.BlockHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: sp,
	}

	for i := uint64(0); i < (proto.StateProofInterval*3 - proto.StateProofVotersLookback); i++ {
		blk.BlockHeader.Round++
		err = l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)
		if i > 0 && i%100 == 0 {
			triggerTrackerFlush(t, l)
		}
	}

	// we simulate that the stateproof for round 512 is confirmed on chain, and we can move to the next one.
	sp.StateProofNextRound = basics.Round(proto.StateProofInterval * 3)
	blk.BlockHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: sp,
	}

	for i := uint64(0); i < proto.StateProofInterval; i++ {
		blk.BlockHeader.Round++
		err = l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)
		if i%100 == 0 {
			triggerTrackerFlush(t, l)
		}
	}

	// flush remaining blocks
	triggerTrackerFlush(t, l)

	var vtSnapshot map[basics.Round]*ledgercore.VotersForRound
	func() {
		// grab internal lock in order to access the voters tracker
		// since the assert below might fail, use a nested scope to ensure the lock is released
		l.acctsOnline.voters.votersMu.Lock()
		defer l.acctsOnline.voters.votersMu.Unlock()

		vtSnapshot = l.acctsOnline.voters.votersForRoundCache

		// verifying that the tree for round 512 is still in the cache, but the tree for round 256 is evicted.
		require.Contains(t, vtSnapshot, basics.Round(496))
		require.NotContains(t, vtSnapshot, basics.Round(240))
	}()

	t.Log("reloading ledger")
	// drain any deferred commits since AddBlock above triggered scheduleCommit
outer:
	for {
		select {
		case <-l.trackers.deferredCommits:
			l.trackers.accountsWriting.Done()
		default:
			break outer
		}
	}

	err = l.reloadLedger()
	require.NoError(t, err)

	verifyVotersContent(t, vtSnapshot, l.acctsOnline.voters.votersForRoundCache)
}

func TestVotersReloadFromDiskAfterOneStateProofCommitted(t *testing.T) {
	partitiontest.PartitionTest(t)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	cfg.MaxAcctLookback = proto.StateProofInterval - proto.StateProofVotersLookback - 10
	cfg.CatchpointInterval = 0 // no need catchpoint for this test

	ledgertesting.WithAndWithoutLRUCache(t, cfg, testVotersReloadFromDiskAfterOneStateProofCommitted)
}

func testVotersReloadFromDiskPassRecoveryPeriod(t *testing.T, cfg config.Local) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true

	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blk := genesisInitState.Block
	var sp bookkeeping.StateProofTrackingData
	sp.StateProofNextRound = basics.Round(proto.StateProofInterval * 2)
	blk.BlockHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: sp,
	}

	// we push proto.StateProofInterval * (proto.StateProofMaxRecoveryIntervals + 2) block into the ledger
	// the reason for + 2 is the first state proof is on 2*stateproofinterval.
	for i := uint64(0); i < (proto.StateProofInterval * (proto.StateProofMaxRecoveryIntervals + 2)); i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	// the voters tracker should contain all the voters for each stateproof round. nothing should be removed
	l.WaitForCommit(l.Latest())
	triggerDeleteVoters(t, l, genesisInitState)

	vtSnapshot := l.acctsOnline.voters.votersForRoundCache
	beforeRemoveVotersLen := len(vtSnapshot)
	err = l.reloadLedger()
	require.NoError(t, err)
	_, found := l.acctsOnline.voters.votersForRoundCache[basics.Round(proto.StateProofInterval-proto.StateProofVotersLookback)]
	require.True(t, found)
	verifyVotersContent(t, vtSnapshot, l.acctsOnline.voters.votersForRoundCache)

	for i := uint64(0); i < proto.StateProofInterval; i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	triggerDeleteVoters(t, l, genesisInitState)

	// round 256 (240+16) should now be forgotten.
	_, found = l.acctsOnline.voters.votersForRoundCache[basics.Round(proto.StateProofInterval-proto.StateProofVotersLookback)]
	require.False(t, found)

	vtSnapshot = l.acctsOnline.voters.votersForRoundCache
	err = l.reloadLedger()
	require.NoError(t, err)

	verifyVotersContent(t, vtSnapshot, l.acctsOnline.voters.votersForRoundCache)
	_, found = l.acctsOnline.voters.votersForRoundCache[basics.Round(proto.StateProofInterval-proto.StateProofVotersLookback)]
	require.False(t, found)
	require.Equal(t, beforeRemoveVotersLen, len(l.acctsOnline.voters.votersForRoundCache))
}

func TestVotersReloadFromDiskPassRecoveryPeriod(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	cfg.MaxAcctLookback = 0

	ledgertesting.WithAndWithoutLRUCache(t, cfg, testVotersReloadFromDiskPassRecoveryPeriod)
}

type mockCommitListener struct{}

func (l *mockCommitListener) OnPrepareVoterCommit(oldBase basics.Round, newBase basics.Round, _ ledgercore.LedgerForSPBuilder) {
}

func TestVotersCallbackPersistsAfterLedgerReload(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true
	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	commitListener := mockCommitListener{}
	l.RegisterVotersCommitListener(&commitListener)
	listenerBeforeReload := l.acctsOnline.voters.commitListener

	require.NotNil(t, listenerBeforeReload)
	err = l.reloadLedger()
	require.NoError(t, err)

	listenerAfterReload := l.acctsOnline.voters.commitListener
	require.Equal(t, listenerBeforeReload, listenerAfterReload)
}

func TestLedgerSPVerificationTracker(t *testing.T) {
	partitiontest.PartitionTest(t)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	numOfStateProofs := uint64(3)
	firstStateProofContextConfirmedRound := proto.StateProofInterval
	firstStateProofContextTargetRound := firstStateProofContextConfirmedRound + proto.StateProofInterval

	lastStateProofContextConfirmedRound := firstStateProofContextConfirmedRound + proto.StateProofInterval*(numOfStateProofs-1)
	lastStateProofContextTargetRound := lastStateProofContextConfirmedRound + proto.StateProofInterval

	for i := uint64(0); i < firstStateProofContextConfirmedRound-1; i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		1, proto.StateProofInterval, false, spverDBLoc)

	addEmptyValidatedBlock(t, l, genesisInitState.Accounts)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		1, proto.StateProofInterval, true, trackerMemory)

	for i := firstStateProofContextConfirmedRound; i < lastStateProofContextConfirmedRound; i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	l.WaitForCommit(l.Latest())
	triggerTrackerFlush(t, l)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		numOfStateProofs-1, proto.StateProofInterval, true, trackerDB)
	// Last one should be in memory as a result of cfg.MaxAcctLookback not being equal to 0.
	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(lastStateProofContextTargetRound),
		1, proto.StateProofInterval, true, trackerMemory)

	l.WaitForCommit(l.Latest())
	triggerTrackerFlush(t, l)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		numOfStateProofs, proto.StateProofInterval, true, spverDBLoc)

	blk := makeNewEmptyBlock(t, l, t.Name(), genesisInitState.Accounts)
	var stateProofReceived bookkeeping.StateProofTrackingData
	stateProofReceived.StateProofNextRound = basics.Round(firstStateProofContextTargetRound + proto.StateProofInterval)
	blk.BlockHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: stateProofReceived,
	}

	// This implementation is an easy way to feed the delta, which the state proof verification tracker relies on,
	// to the ledger.
	delta, err := eval.Eval(context.Background(), l, blk, false, l.verifiedTxnCache, nil, l.tracer)
	require.NoError(t, err)
	delta.StateProofNext = stateProofReceived.StateProofNextRound
	vb := ledgercore.MakeValidatedBlock(blk, delta)
	err = l.AddValidatedBlock(vb, agreement.Certificate{})
	require.NoError(t, err)

	for i := uint64(0); i < proto.MaxBalLookback; i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	l.WaitForCommit(blk.BlockHeader.Round)
	triggerTrackerFlush(t, l)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		1, proto.StateProofInterval, false, spverDBLoc)
	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound+proto.StateProofInterval),
		numOfStateProofs-1, proto.StateProofInterval, true, spverDBLoc)
}

func TestLedgerReloadStateProofVerificationTracker(t *testing.T) {
	partitiontest.PartitionTest(t)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	numOfStateProofs := uint64(3)
	firstStateProofContextConfirmedRound := proto.StateProofInterval
	firstStateProofContextTargetRound := firstStateProofContextConfirmedRound + proto.StateProofInterval

	lastStateProofContextConfirmedRound := firstStateProofContextConfirmedRound + proto.StateProofInterval*(numOfStateProofs-1)
	lastStateProofContextTargetRound := lastStateProofContextConfirmedRound + proto.StateProofInterval

	for i := uint64(0); i < lastStateProofContextConfirmedRound; i++ {
		addEmptyValidatedBlock(t, l, genesisInitState.Accounts)
	}

	// trigger trackers flush
	// first ensure the block is committed into blockdb
	l.WaitForCommit(l.Latest())
	triggerTrackerFlush(t, l)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		numOfStateProofs-1, proto.StateProofInterval, true, trackerDB)
	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(lastStateProofContextTargetRound),
		1, proto.StateProofInterval, true, trackerMemory)

	err = l.reloadLedger()
	require.NoError(t, err)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofContextTargetRound),
		numOfStateProofs-1, proto.StateProofInterval, true, trackerDB)
	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(lastStateProofContextTargetRound),
		1, proto.StateProofInterval, true, trackerMemory)
}

func feedBlocksUntilRound(t *testing.T, l *Ledger, prevBlk bookkeeping.Block, targetRound basics.Round) bookkeeping.Block {
	for prevBlk.Round() < targetRound {
		prevBlk.BlockHeader.Round++
		err := l.AddBlock(prevBlk, agreement.Certificate{})
		require.NoError(t, err)
	}

	return prevBlk
}

func TestLedgerCatchpointSPVerificationTracker(t *testing.T) {
	partitiontest.PartitionTest(t)
	proto := config.Consensus[protocol.ConsensusFuture]

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, initkeys := ledgertesting.GenerateInitState(t, protocol.ConsensusFuture, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusFuture
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	// This assures us that the first catchpoint file will contain exactly 1 state proof data.
	cfg.CatchpointInterval = proto.StateProofInterval + proto.MaxBalLookback
	cfg.MaxAcctLookback = 4
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)

	firstStateProofDataConfirmedRound := proto.StateProofInterval
	firstStateProofDataTargetRound := firstStateProofDataConfirmedRound + proto.StateProofInterval

	blk := genesisInitState.Block
	var sp bookkeeping.StateProofTrackingData
	sp.StateProofNextRound = basics.Round(firstStateProofDataTargetRound)
	blk.BlockHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: sp,
	}

	// Feeding blocks until we can know for sure we have at least one catchpoint written.
	blk = feedBlocksUntilRound(t, l, blk, basics.Round(cfg.CatchpointInterval*2))
	l.WaitForCommit(basics.Round(cfg.CatchpointInterval * 2))
	triggerTrackerFlush(t, l)

	numTrackedDataFirstCatchpoint := (cfg.CatchpointInterval - proto.MaxBalLookback) / proto.StateProofInterval

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofDataTargetRound),
		numTrackedDataFirstCatchpoint, proto.StateProofInterval, true, spverDBLoc)
	l.Close()

	l, err = OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofDataTargetRound),
		numTrackedDataFirstCatchpoint, proto.StateProofInterval, false, spverDBLoc)

	catchpointAccessor, accessorProgress := initializeTestCatchupAccessor(t, l, uint64(len(initkeys)))

	relCatchpointFilePath := filepath.Join(dbName, trackerdb.CatchpointDirName, trackerdb.MakeCatchpointFilePath(basics.Round(cfg.CatchpointInterval)))

	catchpointData := readCatchpointFile(t, relCatchpointFilePath)

	err = catchpointAccessor.ProcessStagingBalances(context.Background(), catchpointData[1].headerName, catchpointData[1].data, &accessorProgress)
	require.NoError(t, err)
	err = catchpointAccessor.CompleteCatchup(context.Background())
	require.NoError(t, err)

	verifyStateProofVerificationTracking(t, &l.spVerification, basics.Round(firstStateProofDataTargetRound),
		numTrackedDataFirstCatchpoint, proto.StateProofInterval, true, spverDBLoc)
}

func TestLedgerSPTrackerAfterReplay(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	l, err := OpenLedger(log, dbName, inMem, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	// Add 1024 empty block without advancing NextStateProofRound
	firstStateProofRound := basics.Round(proto.StateProofInterval * 2) // 512
	blk := genesisInitState.Block
	var sp bookkeeping.StateProofTrackingData
	sp.StateProofNextRound = firstStateProofRound // 512
	blk.BlockHeader.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: sp,
	}

	for i := uint64(0); i < proto.StateProofInterval*4; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += 10
		err = l.AddBlock(blk, agreement.Certificate{})
		a.NoError(err)
	}

	// 1024
	verifyStateProofVerificationTracking(t, &l.spVerification, firstStateProofRound, 1, proto.StateProofInterval, true, spverDBLoc)
	a.Equal(0, len(l.spVerification.pendingDeleteContexts))

	// Add StateProof transaction (for round 512) and apply without validating, advancing the NextStateProofRound to 768
	spblk := createBlkWithStateproof(t, int(blk.BlockHeader.Round), proto, genesisInitState, l, genesisInitState.Accounts)
	err = l.AddBlock(spblk, agreement.Certificate{})
	a.NoError(err)
	a.Equal(1, len(l.spVerification.pendingDeleteContexts))
	// To be deleted, but not yet deleted (waiting for commit)
	verifyStateProofVerificationTracking(t, &l.spVerification, firstStateProofRound, 1, proto.StateProofInterval, true, spverDBLoc)

	// first ensure the block is committed into blockdb
	l.WaitForCommit(l.Latest())
	triggerTrackerFlush(t, l)

	err = l.reloadLedger()
	a.NoError(err)

	a.Equal(1, len(l.spVerification.pendingDeleteContexts))
	verifyStateProofVerificationTracking(t, &l.spVerification, firstStateProofRound, 1, proto.StateProofInterval, true, spverDBLoc)
}

func TestLedgerMaxBlockHistoryLookback(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, _, _ := ledgertesting.NewTestGenesis()
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	cfg := config.GetDefaultLocal()
	// set the max lookback to 1400
	cfg.MaxBlockHistoryLookback = 1400
	l := newSimpleLedgerFull(t, genBalances, protocol.ConsensusCurrentVersion, genHash, cfg, simpleLedgerNotArchival())
	defer l.Close()

	// make 1500 blocks
	for i := 0; i < 1500; i++ {
		eval := nextBlock(t, l)
		endBlock(t, l, eval)
	}
	require.Equal(t, basics.Round(1500), l.Latest())

	// make sure we can get the last 1400 blocks
	blk, err := l.Block(100)
	require.NoError(t, err)
	require.NotEmpty(t, blk)

	// make sure we can't get a block before the max lookback
	blk, err = l.Block(90)
	require.Error(t, err)
	require.Empty(t, blk)
}

func TestLedgerRetainMinOffCatchpointInterval(t *testing.T) {
	partitiontest.PartitionTest(t)
	// This test is to ensure that the ledger retains the minimum number of blocks off the catchpoint interval.
	blocksToMake := 2000

	// Cases:
	// 1. Base Case: Archival = false, Stores catchpoints returns true, CatchpointFileHistoryLength = >= 1 - implies catchpoint interval > 0 - min formula
	// 2. Archival = true, stores catchpoints returns false - we keep all blocks anyway
	// 3. Archival = false, stores catchpoints returns false - we don't modify minToSave
	// 4. Condition: Archival = false, storesCatchpoints returns true, CatchpointFileHistoryLength is -1 - keep all catchpoint files
	// 5. Condition: Archival = false, storesCatchpoints returns true, CatchpointFileHistoryLength is 365 - the config default setting

	catchpointIntervalBlockRetentionTestCases := []struct {
		storeCatchpoints            bool
		archival                    bool
		catchpointFileHistoryLength int
	}{
		{true, false, 1},   // should use min catchpoint formula
		{false, true, 1},   // all blocks get retained, archival mode dictates
		{false, false, 1},  // should not modify min blocks retained based on catchpoint interval
		{true, false, -1},  // should use min formula, this is the keep all catchpoints setting
		{true, false, 365}, // should use min formula, this is the default setting for catchpoint file history length
	}
	for _, tc := range catchpointIntervalBlockRetentionTestCases {
		func() {
			var genHash crypto.Digest
			crypto.RandBytes(genHash[:])
			cfg := config.GetDefaultLocal()
			// set config properties based on test case
			cfg.MaxBlockHistoryLookback = 0 // max block history lookback is not used in this test
			if tc.storeCatchpoints {
				cfg.CatchpointTracking = config.CatchpointTrackingModeStored
				cfg.CatchpointInterval = 100
			} else {
				cfg.CatchpointInterval = 0 // sufficient for cfg.StoresCatchpoints() to return false
			}
			cfg.CatchpointFileHistoryLength = tc.catchpointFileHistoryLength
			cfg.Archival = tc.archival

			l := &Ledger{}
			l.cfg = cfg
			l.archival = cfg.Archival
			l.trackers.log = logging.TestingLog(t)

			for i := 1; i <= blocksToMake; i++ {
				minBlockToKeep := l.notifyCommit(basics.Round(i))

				// In archival mode, all blocks should always be kept
				if cfg.Archival {
					require.Equal(t, basics.Round(0), minBlockToKeep)
				} else {
					// This happens to work for the test case where we don't store catchpoints since mintosave is always
					// 0 in that case.
					expectedCatchpointLookback := 2 * cfg.CatchpointInterval

					expectedMinBlockToKeep := basics.Round(uint64(i)).SubSaturate(
						basics.Round(expectedCatchpointLookback))
					require.Equal(t, expectedMinBlockToKeep, minBlockToKeep)
				}
			}
		}()
	}
}

type testBlockListener struct {
	id int
}

func (t *testBlockListener) OnNewBlock(bookkeeping.Block, ledgercore.StateDelta) {}

// TestLedgerRegisterBlockListeners ensures that the block listeners survive reloadLedger
func TestLedgerRegisterBlockListeners(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, _, _ := ledgertesting.NewTestGenesis()
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	cfg := config.GetDefaultLocal()
	l := newSimpleLedgerFull(t, genBalances, protocol.ConsensusCurrentVersion, genHash, cfg)
	defer l.Close()

	l.RegisterBlockListeners([]ledgercore.BlockListener{&testBlockListener{1}, &testBlockListener{2}})
	l.RegisterBlockListeners([]ledgercore.BlockListener{&testBlockListener{3}})

	require.Equal(t, 3, len(l.notifier.listeners))
	var ids []int
	for _, bl := range l.notifier.listeners {
		ids = append(ids, bl.(*testBlockListener).id)
	}
	require.Equal(t, []int{1, 2, 3}, ids)

	l.reloadLedger()

	ids = nil
	for _, bl := range l.notifier.listeners {
		ids = append(ids, bl.(*testBlockListener).id)
	}
	require.Equal(t, []int{1, 2, 3}, ids)
}

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

package test

import (
	"fmt"
	"math/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

var cannedStatusReportGolden = node.StatusReport{
	LastRound:                          basics.Round(1),
	LastVersion:                        protocol.ConsensusCurrentVersion,
	NextVersion:                        protocol.ConsensusCurrentVersion,
	NextVersionRound:                   basics.Round(1),
	NextVersionSupported:               true,
	StoppedAtUnsupportedRound:          true,
	Catchpoint:                         "",
	CatchpointCatchupAcquiredBlocks:    0,
	CatchpointCatchupProcessedAccounts: 0,
	CatchpointCatchupVerifiedAccounts:  0,
	CatchpointCatchupTotalAccounts:     0,
	CatchpointCatchupTotalKVs:          0,
	CatchpointCatchupProcessedKVs:      0,
	CatchpointCatchupVerifiedKVs:       0,
	CatchpointCatchupTotalBlocks:       0,
	LastCatchpoint:                     "",
}

var poolAddrRewardBaseGolden = uint64(0)
var poolAddrAssetsGolden = make([]model.AssetHolding, 0)
var poolAddrCreatedAssetsGolden = make([]model.Asset, 0)
var appLocalStates = make([]model.ApplicationLocalState, 0)
var appsTotalSchema = model.ApplicationStateSchema{}
var appCreatedApps = make([]model.Application, 0)
var poolAddrResponseGolden = model.AccountResponse{
	Address:                     poolAddr.String(),
	Amount:                      50000000000,
	AmountWithoutPendingRewards: 50000000000,
	Assets:                      &poolAddrAssetsGolden,
	CreatedAssets:               &poolAddrCreatedAssetsGolden,
	RewardBase:                  &poolAddrRewardBaseGolden,
	Status:                      "Not Participating",
	AppsLocalState:              &appLocalStates,
	AppsTotalSchema:             &appsTotalSchema,
	CreatedApps:                 &appCreatedApps,
	MinBalance:                  100000,
}
var txnPoolGolden = make([]transactions.SignedTxn, 2)

// ordinarily mockNode would live in `components/mocks`
// but doing this would create an import cycle, as mockNode needs
// package `data` and package `node`, which themselves import `mocks`
type mockNode struct {
	mock.Mock
	ledger          v2.LedgerForAPI
	genesisID       string
	config          config.Local
	err             error
	id              account.ParticipationID
	keys            account.StateProofKeys
	status          node.StatusReport
	devmode         bool
	timestampOffset *int64
	PartKeyBinary   []byte
}

func (m *mockNode) InstallParticipationKey(partKeyBinary []byte) (account.ParticipationID, error) {
	m.PartKeyBinary = partKeyBinary
	return account.ParticipationID{}, nil
}

func (m *mockNode) ListParticipationKeys() ([]account.ParticipationRecord, error) {
	panic("implement me")
}

func (m *mockNode) GetParticipationKey(id account.ParticipationID) (account.ParticipationRecord, error) {
	panic("implement me")
}

func (m *mockNode) RemoveParticipationKey(id account.ParticipationID) error {
	panic("implement me")
}

func (m *mockNode) SetSyncRound(rnd basics.Round) error {
	args := m.Called(rnd)
	return args.Error(0)
}

func (m *mockNode) UnsetSyncRound() {
}

func (m *mockNode) GetSyncRound() basics.Round {
	args := m.Called()
	return basics.Round(args.Int(0))
}

func (m *mockNode) AppendParticipationKeys(id account.ParticipationID, keys account.StateProofKeys) error {
	m.id = id
	m.keys = keys
	return m.err
}

func makeMockNode(ledger v2.LedgerForAPI, genesisID string, nodeError error, status node.StatusReport, devMode bool) *mockNode {
	return makeMockNodeWithConfig(ledger, genesisID, nodeError, status, devMode, config.GetDefaultLocal())
}

func makeMockNodeWithConfig(ledger v2.LedgerForAPI, genesisID string, nodeError error, status node.StatusReport, devMode bool, cfg config.Local) *mockNode {
	return &mockNode{
		ledger:    ledger,
		genesisID: genesisID,
		config:    cfg,
		err:       nodeError,
		status:    status,
		devmode:   devMode,
	}
}

func (m *mockNode) LedgerForAPI() v2.LedgerForAPI {
	return m.ledger
}
func (m *mockNode) Status() (node.StatusReport, error) {
	return m.status, nil
}
func (m *mockNode) GenesisID() string {
	return m.genesisID
}

func (m *mockNode) GenesisHash() crypto.Digest {
	return m.ledger.(*data.Ledger).GenesisHash()
}

func (m *mockNode) BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error {
	return m.err
}

func (m *mockNode) AsyncBroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error {
	return m.err
}

func (m *mockNode) Simulate(request simulation.Request) (simulation.Result, error) {
	simulator := simulation.MakeSimulator(m.ledger.(*data.Ledger), m.config.EnableDeveloperAPI)
	return simulator.Simulate(request)
}

func (m *mockNode) GetPendingTransaction(txID transactions.Txid) (res node.TxnWithStatus, found bool) {
	res = node.TxnWithStatus{}
	found = true
	return
}

func (m *mockNode) GetPendingTxnsFromPool() ([]transactions.SignedTxn, error) {
	return txnPoolGolden, m.err
}

func (m *mockNode) SuggestedFee() basics.MicroAlgos {
	return basics.MicroAlgos{Raw: 1}
}

// unused by handlers:
func (m *mockNode) Config() config.Local {
	return m.config
}

func (m *mockNode) GetPeers() (inboundPeers []network.Peer, outboundPeers []network.Peer, err error) {
	panic("not implemented")
}

func (m *mockNode) StartCatchup(catchpoint string) error {
	return m.err
}

func (m *mockNode) AbortCatchup(catchpoint string) error {
	return m.err
}

func (m *mockNode) SetBlockTimeStampOffset(offset int64) error {
	if !m.devmode {
		return fmt.Errorf("cannot set block timestamp when not in dev mode")
	}
	m.timestampOffset = &offset
	return nil
}

func (m *mockNode) GetBlockTimeStampOffset() (*int64, error) {
	if !m.devmode {
		return nil, fmt.Errorf("cannot get block timestamp when not in dev mode")
	} else if m.timestampOffset == nil {
		return nil, nil
	}
	return m.timestampOffset, nil
}

////// mock ledger testing environment follows

var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var genesisHash = crypto.Digest{0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}
var genesisID = "testingid"
var retOneProgram = []byte{2, 0x20, 1, 1, 0x22}

var proto = config.Consensus[protocol.ConsensusFuture]

func testingenv(t testing.TB, numAccounts, numTxs int, offlineAccounts bool) (*data.Ledger, []account.Root, []account.Participation, []transactions.SignedTxn, func()) {
	minMoneyAtStart := 100000  // min money start
	maxMoneyAtStart := 1000000 // max money start
	return testingenvWithBalances(t, minMoneyAtStart, maxMoneyAtStart, numAccounts, numTxs, offlineAccounts)
}

func testingenvWithBalances(t testing.TB, minMoneyAtStart, maxMoneyAtStart, numAccounts, numTxs int, offlineAccounts bool) (*data.Ledger, []account.Root, []account.Participation, []transactions.SignedTxn, func()) {
	P := numAccounts               // n accounts
	TXs := numTxs                  // n txns
	transferredMoney := 100        // max money/txn
	maxFee := 10                   // max maxFee/txn
	lastValid := basics.Round(500) // max round

	accessors := []db.Accessor{}

	release := func() {
		for _, acc := range accessors {
			acc.Close()
		}

	}

	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	roots := make([]account.Root, P)
	parts := make([]account.Participation, P)
	for i := 0; i < P; i++ {
		access, err := db.MakeAccessor(t.Name()+"_root_testingenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accessors = append(accessors, access)

		root, err := account.GenerateRoot(access)
		if err != nil {
			panic(err)
		}

		access, err = db.MakeAccessor(t.Name()+"_part_testingenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accessors = append(accessors, access)

		part, err := account.FillDBWithParticipationKeys(access, root.Address(), 0, lastValid, proto.DefaultKeyDilution)
		if err != nil {
			panic(err)
		}

		roots[i] = root
		parts[i] = part.Participation

		startamt := basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))}
		short := root.Address()

		if offlineAccounts && i > P/2 {
			genesis[short] = basics_testing.MakeAccountData(basics.Offline, startamt)
		} else {
			data := basics_testing.MakeAccountData(basics.Online, startamt)
			data.SelectionID = parts[i].VRFSecrets().PK
			data.VoteID = parts[i].VotingSecrets().OneTimeSignatureVerifier
			genesis[short] = data
		}
		part.Close()
	}

	genesis[poolAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 100000 * uint64(proto.RewardsRateRefreshInterval)})

	lhash := logic.HashProgram(retOneProgram)
	var addr basics.Address
	copy(addr[:], lhash[:])
	ad := basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 100000 * uint64(proto.RewardsRateRefreshInterval)})
	ad.AppLocalStates = map[basics.AppIndex]basics.AppLocalState{1: {}}
	genesis[addr] = ad

	bootstrap := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)

	// generate test transactions
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := data.LoadLedger(logging.Base(), t.Name(), inMem, protocol.ConsensusFuture, bootstrap, genesisID, genesisHash, cfg)
	if err != nil {
		panic(err)
	}

	tx := make([]transactions.SignedTxn, TXs)
	latest := ledger.Latest()
	if latest != 0 {
		panic(fmt.Errorf("newly created ledger doesn't start on round 0"))
	}
	bal := genesis // the current balance record is the same as the genesis balance record

	for i := 0; i < TXs; i++ {
		send := gen.Int() % P
		recv := gen.Int() % P

		saddr := roots[send].Address()
		raddr := roots[recv].Address()

		if proto.MinTxnFee+uint64(maxFee) > bal[saddr].MicroAlgos.Raw {
			continue
		}

		xferMax := transferredMoney
		if uint64(xferMax) > bal[saddr].MicroAlgos.Raw-proto.MinTxnFee-uint64(maxFee) {
			xferMax = int(bal[saddr].MicroAlgos.Raw - proto.MinTxnFee - uint64(maxFee))
		}

		if xferMax == 0 {
			continue
		}

		amt := basics.MicroAlgos{Raw: uint64(gen.Int() % xferMax)}
		fee := basics.MicroAlgos{Raw: uint64(gen.Int()%maxFee) + proto.MinTxnFee}

		t := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      saddr,
				Fee:         fee,
				FirstValid:  ledger.LastRound(),
				LastValid:   ledger.LastRound() + lastValid,
				Note:        make([]byte, 4),
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: raddr,
				Amount:   amt,
			},
		}

		rand.Read(t.Note)
		tx[i] = t.Sign(roots[send].Secrets())

		sbal := bal[saddr]
		sbal.MicroAlgos.Raw -= fee.Raw
		sbal.MicroAlgos.Raw -= amt.Raw
		bal[saddr] = sbal

		ibal := bal[poolAddr]
		ibal.MicroAlgos.Raw += fee.Raw
		bal[poolAddr] = ibal

		rbal := bal[raddr]
		rbal.MicroAlgos.Raw += amt.Raw
		bal[raddr] = rbal
	}

	return ledger, roots, parts, tx, release
}

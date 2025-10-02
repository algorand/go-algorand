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
	"encoding/binary"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// onlineAcctModel provides a simple interface for tracking accounts
// as they come online, go offline, and change their amount of stake.
// It is implemented by a real ledger (doubleLedgerAcctModel) for testing
// against a reference implementation (mapOnlineAcctModel).
type onlineAcctModel interface {
	currentRound() basics.Round
	nextRound()
	advanceToRound(rnd basics.Round)
	goOnline(addr basics.Address, firstvalid, lastvalid basics.Round)
	goOffline(addr basics.Address)
	updateStake(addr basics.Address, stake basics.MicroAlgos)
	teardown()

	LookupAgreement(rnd basics.Round, addr basics.Address) onlineAcctModelAcct
	OnlineCirculation(rnd basics.Round, voteRnd basics.Round) basics.MicroAlgos
	expiredOnlineCirculation(rnd, voteRnd basics.Round) basics.MicroAlgos
}

// mapOnlineAcctModel provides a reference implementation for tracking online accounts used
// for testing TopOnlineAccounts, ExpiredOnlineCirculation, and onlineAcctsExpiredByRound.
// It is an oracle that the doubleLedgerAcctModel is compared against.
type mapOnlineAcctModel struct {
	t        *testing.T
	cur      basics.Round
	accts    map[basics.Address]map[basics.Round]onlineAcctModelAcct
	expiring map[basics.Round]map[basics.Address]struct{}
}

type onlineAcctModelAcct struct {
	Status                        basics.Status
	VoteFirstValid, VoteLastValid basics.Round
	Stake                         basics.MicroAlgos
}

func newMapOnlineAcctModel(t *testing.T) *mapOnlineAcctModel {
	return &mapOnlineAcctModel{
		t:        t,
		cur:      1,
		accts:    make(map[basics.Address]map[basics.Round]onlineAcctModelAcct),
		expiring: make(map[basics.Round]map[basics.Address]struct{}),
	}
}

func (m *mapOnlineAcctModel) teardown()                  {}
func (m *mapOnlineAcctModel) currentRound() basics.Round { return m.cur }
func (m *mapOnlineAcctModel) nextRound()                 { m.cur++ }
func (m *mapOnlineAcctModel) advanceToRound(rnd basics.Round) {
	if rnd == m.cur {
		return
	}
	require.Greater(m.t, rnd, m.cur, "cannot advance to previous round")
	m.cur = rnd
}

func (m *mapOnlineAcctModel) lookupAcctAsOf(rnd basics.Round, addr basics.Address) onlineAcctModelAcct {
	require.LessOrEqual(m.t, rnd, m.cur, "cannot lookup acct for future round")
	acctRounds, ok := m.accts[addr]
	if !ok {
		return onlineAcctModelAcct{}
	}
	// find the acct record for the most recent round <= rnd
	for r := rnd; r > 0; r-- {
		if acct, ok := acctRounds[r]; ok {
			return acct
		}
	}
	// not found
	return onlineAcctModelAcct{}
}

func (m *mapOnlineAcctModel) LookupAgreement(rnd basics.Round, addr basics.Address) onlineAcctModelAcct {
	return m.lookupAcctAsOf(rnd, addr)
}

// look up all online accounts as of the given round
func (m *mapOnlineAcctModel) allOnlineAsOf(rnd basics.Round) map[basics.Address]onlineAcctModelAcct {
	require.LessOrEqual(m.t, rnd, m.cur, "cannot lookup acct for future round")
	accts := make(map[basics.Address]onlineAcctModelAcct)
	for addr, acctRounds := range m.accts {
		// find the acct record for the most recent round <= rnd
		for r := rnd; r > 0; r-- {
			if acct, ok := acctRounds[r]; ok {
				if acct.Status == basics.Online {
					accts[addr] = acct
				}
				// found the most recent round <= rnd, so stop looking
				// we will break even if the acct is offline
				break
			}
		}
	}
	return accts
}

func (m *mapOnlineAcctModel) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) basics.MicroAlgos {
	accts := m.allOnlineAsOf(rnd)
	return m.sumAcctStake(accts)
}

func (m *mapOnlineAcctModel) expiredOnlineCirculation(rnd, voteRnd basics.Round) basics.MicroAlgos {
	accts := m.onlineAcctsExpiredByRound(rnd, voteRnd)
	return m.sumAcctStake(accts)
}

func (m *mapOnlineAcctModel) sumAcctStake(accts map[basics.Address]onlineAcctModelAcct) basics.MicroAlgos {
	algops := MicroAlgoOperations{a: require.New(m.t)}
	var ret basics.MicroAlgos
	for _, acct := range accts {
		ret = algops.Add(ret, acct.Stake)
	}
	return ret
}

func (m *mapOnlineAcctModel) setAcct(rnd basics.Round, addr basics.Address, acct onlineAcctModelAcct) {
	require.Equal(m.t, rnd, m.cur, "cannot set acct for round other than current round")

	acctRounds, ok := m.accts[addr]
	if !ok {
		acctRounds = make(map[basics.Round]onlineAcctModelAcct)
	}
	acctRounds[rnd] = acct
	m.accts[addr] = acctRounds
}

func (m *mapOnlineAcctModel) goOnline(addr basics.Address, firstvalid, lastvalid basics.Round) {
	rnd := m.cur
	oldAcct := m.lookupAcctAsOf(rnd, addr)

	// if is already online, remove old lastvalid round from expiring map
	if oldAcct.Status == basics.Online {
		require.Contains(m.t, m.expiring, oldAcct.VoteLastValid, "round should be in expiring map")
		require.Contains(m.t, m.expiring[oldAcct.VoteLastValid], addr, "address should be in expiring map")
		delete(m.expiring[oldAcct.VoteLastValid], addr)
	}

	// create new acct record
	newAcct := onlineAcctModelAcct{
		Status:         basics.Online,
		VoteFirstValid: firstvalid,
		VoteLastValid:  lastvalid,
		Stake:          oldAcct.Stake,
	}
	m.setAcct(rnd, addr, newAcct)

	// remember when this account will expire
	expiring, ok := m.expiring[lastvalid]
	if !ok {
		expiring = make(map[basics.Address]struct{})
	}
	expiring[addr] = struct{}{}
	m.expiring[lastvalid] = expiring

}

func (m *mapOnlineAcctModel) goOffline(addr basics.Address) {
	rnd := m.cur
	oldAcct := m.lookupAcctAsOf(rnd, addr)

	// must already be online: remove old lastvalid round from expiring map
	require.Equal(m.t, basics.Online, oldAcct.Status, "cannot go offline if not online")
	require.Contains(m.t, m.expiring, oldAcct.VoteLastValid, "round should be in expiring map")
	require.Contains(m.t, m.expiring[oldAcct.VoteLastValid], addr, "address should be in expiring map")
	delete(m.expiring[oldAcct.VoteLastValid], addr)

	newAcct := onlineAcctModelAcct{
		Status:         basics.Offline,
		VoteFirstValid: 0,
		VoteLastValid:  0,
		Stake:          oldAcct.Stake,
	}
	m.setAcct(rnd, addr, newAcct)
}

func (m *mapOnlineAcctModel) updateStake(addr basics.Address, stake basics.MicroAlgos) {
	rnd := m.cur
	acct := m.lookupAcctAsOf(rnd, addr)
	acct.Stake = stake
	m.setAcct(rnd, addr, acct)
}

func (m *mapOnlineAcctModel) onlineAcctsExpiredByRound(rnd, voteRnd basics.Round) map[basics.Address]onlineAcctModelAcct {
	require.LessOrEqual(m.t, rnd, m.cur, "cannot lookup expired accts for future round")

	// get all online addresses as of rnd
	ret := make(map[basics.Address]onlineAcctModelAcct)
	for addr, acct := range m.allOnlineAsOf(rnd) {
		require.NotZero(m.t, acct.VoteLastValid, "offline acct returned by allOnlineAsOf")
		// will this acct be expired by voteRnd?
		if voteRnd > acct.VoteLastValid {
			ret[addr] = acct
		}
	}
	return ret
}

// doubleLedgerAcctModel implements an onlineAcctModel using DoubleLedger, which starts up two
// Ledger instances, a generator and a validator.
type doubleLedgerAcctModel struct {
	t           testing.TB
	params      *config.ConsensusParams
	dl          *DoubleLedger
	ops         *MicroAlgoOperations
	genAddrs    []basics.Address
	genBalances bookkeeping.GenesisBalances
	genSecrets  []*crypto.SignatureSecrets
	// new accounts made by goOnline, balance value tracks uncommitted balance changes before dl.endBlock()
	accts map[basics.Address]basics.MicroAlgos
}

func newDoubleLedgerAcctModel(t testing.TB, proto protocol.ConsensusVersion, inMem bool) *doubleLedgerAcctModel {
	// rewards math not supported by newMapOnlineAcctModel
	genBalances, genAddrs, genSecrets := ledgertesting.NewTestGenesis(ledgertesting.TurnOffRewards)
	cfg := config.GetDefaultLocal()
	opts := []simpleLedgerOption{simpleLedgerNotArchival()}
	if !inMem {
		opts = append(opts, simpleLedgerOnDisk())
	}
	dl := NewDoubleLedger(t, genBalances, proto, cfg, opts...)
	dl.beginBlock()
	params := config.Consensus[proto]
	return &doubleLedgerAcctModel{
		t:           t,
		params:      &params,
		ops:         &MicroAlgoOperations{a: require.New(t)},
		dl:          &dl,
		genAddrs:    genAddrs,
		genBalances: genBalances,
		genSecrets:  genSecrets,
		accts:       make(map[basics.Address]basics.MicroAlgos),
	}
}

func (m *doubleLedgerAcctModel) teardown() { m.dl.Close() }

func (m *doubleLedgerAcctModel) nextRound() {
	m.dl.endBlock()
	m.dl.beginBlock()
}

func (m *doubleLedgerAcctModel) currentRound() basics.Round {
	genRound := m.dl.generator.Latest()
	valRound := m.dl.validator.Latest()
	require.Equal(m.t, genRound, valRound)
	return genRound + 1
}

func (m *doubleLedgerAcctModel) advanceToRound(rnd basics.Round) {
	if rnd == m.currentRound() {
		return
	}
	require.Greater(m.t, rnd, m.currentRound(), "cannot advance to previous round")
	for m.currentRound() < rnd {
		m.nextRound()
	}
	require.Equal(m.t, rnd, m.currentRound())
}

const doubleLedgerAcctModelAcctInitialBalance = 1_234_567

func (m *doubleLedgerAcctModel) goOnline(addr basics.Address, firstvalid, lastvalid basics.Round) {
	if _, ok := m.accts[addr]; !ok {
		// not yet in the ledger: send 1 algo from a genesis account
		m.dl.txn(&txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   m.genAddrs[0],
			Receiver: addr,
			Amount:   doubleLedgerAcctModelAcctInitialBalance,
		})
		m.accts[addr] = basics.MicroAlgos{Raw: doubleLedgerAcctModelAcctInitialBalance}
	}

	require.NotZero(m.t, addr, "cannot go online with zero address")

	minFee := m.params.MinTxnFee // subtract minFee from account balance
	m.dl.txn(&txntest.Txn{
		Type:      protocol.KeyRegistrationTx,
		Sender:    addr,
		VoteFirst: firstvalid,
		VoteLast:  lastvalid,
		Fee:       minFee,

		Nonparticipation: false, // XXX test nonparticipating accounts

		// meaningless non-zero voting data
		VotePK:          crypto.OneTimeSignatureVerifier(addr),
		SelectionPK:     crypto.VRFVerifier(addr),
		StateProofPK:    merklesignature.Commitment{1},
		VoteKeyDilution: 1024,
	})
	m.accts[addr] = m.ops.Sub(m.accts[addr], basics.MicroAlgos{Raw: minFee})
}

func (m *doubleLedgerAcctModel) goOffline(addr basics.Address) {
	require.Contains(m.t, m.accts, addr, "cannot go offline with unknown address")

	minFee := m.params.MinTxnFee // subtract minFee from account balance
	m.dl.txn(&txntest.Txn{
		Type:   protocol.KeyRegistrationTx,
		Sender: addr,
		Fee:    minFee,

		// not necessary to specify
		VoteFirst:       0,
		VoteLast:        0,
		VotePK:          crypto.OneTimeSignatureVerifier{},
		SelectionPK:     crypto.VRFVerifier{},
		VoteKeyDilution: 0,
	})
	m.accts[addr] = m.ops.Sub(m.accts[addr], basics.MicroAlgos{Raw: minFee})
}

func (m *doubleLedgerAcctModel) updateStake(addr basics.Address, amount basics.MicroAlgos) {
	curStake := m.accts[addr]
	require.GreaterOrEqual(m.t, amount.Raw, curStake.Raw, "currently cannot decrease stake")
	if amount == curStake {
		return
	}
	if amount.Raw > curStake.Raw {
		sendAmt := m.ops.Sub(amount, curStake)
		// send more algo from a genesis account
		m.dl.txn(&txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   m.genAddrs[0],
			Receiver: addr,
			Amount:   sendAmt.Raw,
			Fee:      m.params.MinTxnFee,
		})
		m.accts[addr] = amount
		m.t.Logf("updateStake addr %s sent %d, bal %d", addr, sendAmt, amount)
	}
}

// OnlineCirculation returns the total online stake at rnd this model produced, while
// also asserting that the validator and generator Ledgers both agree, and that different
// Ledger/tracker methods used to retrieve and calculate the stake internally agree.
func (m *doubleLedgerAcctModel) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) basics.MicroAlgos {
	valTotal, err := m.dl.validator.OnlineTotalStake(rnd)
	require.NoError(m.t, err)
	genTotal, err := m.dl.generator.OnlineTotalStake(rnd)
	require.NoError(m.t, err)
	require.Equal(m.t, valTotal, genTotal)

	valStake, err := m.dl.validator.OnlineCirculation(rnd, voteRnd)
	require.NoError(m.t, err)
	genStake, err := m.dl.generator.OnlineCirculation(rnd, voteRnd)
	require.NoError(m.t, err)
	require.Equal(m.t, valStake, genStake)

	// If ExcludeExpiredCirculation is set, this means OnlineCirculation
	// has already subtracted the expired stake. So to get the total, add
	// it back in by querying ExpiredOnlineCirculation.
	if m.params.ExcludeExpiredCirculation {
		expiredStake := m.expiredOnlineCirculation(rnd, rnd+320)
		valStake = m.ops.Add(valStake, expiredStake)
	}

	// This should equal the value of onlineTotalsImpl(rnd) which provides
	// the total online stake without subtracting expired stake.
	require.Equal(m.t, valTotal, valStake)

	return valStake
}

// OnlineTotalStake is a wrapper to access onlineAccounts.onlineTotalsImpl safely.
func (l *Ledger) OnlineTotalStake(rnd basics.Round) (basics.MicroAlgos, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	totalStake, _, err := l.acctsOnline.onlineTotals(rnd)
	return totalStake, err
}

// expiredOnlineCirculation is a wrapper to call onlineAccounts.expiredOnlineCirculation safely.
func (l *Ledger) expiredOnlineCirculation(rnd, voteRnd basics.Round) (basics.MicroAlgos, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.acctsOnline.expiredOnlineCirculation(rnd, voteRnd)
}

// expiredOnlineCirculation returns the total expired stake at rnd this model produced, while
// also asserting that the validator and generator Ledgers both agree.
func (m *doubleLedgerAcctModel) expiredOnlineCirculation(rnd, voteRnd basics.Round) basics.MicroAlgos {
	valStake, err := m.dl.validator.expiredOnlineCirculation(rnd, voteRnd)
	require.NoError(m.t, err)
	valCachedStake, has := m.dl.validator.acctsOnline.expiredCirculationCache.get(rnd, voteRnd)
	require.True(m.t, has)
	require.Equal(m.t, valStake, valCachedStake)
	genStake, err := m.dl.generator.expiredOnlineCirculation(rnd, voteRnd)
	require.NoError(m.t, err)
	genCachedStake, has := m.dl.generator.acctsOnline.expiredCirculationCache.get(rnd, voteRnd)
	require.True(m.t, has)
	require.Equal(m.t, genStake, genCachedStake)
	require.Equal(m.t, valStake, genStake)
	return valStake
}

func (m *doubleLedgerAcctModel) LookupAgreement(rnd basics.Round, addr basics.Address) onlineAcctModelAcct {
	valAcct, err := m.dl.validator.LookupAgreement(rnd, addr)
	require.NoError(m.t, err)
	genAcct, err := m.dl.generator.LookupAgreement(rnd, addr)
	require.NoError(m.t, err)
	require.Equal(m.t, valAcct, genAcct)

	status := basics.Offline
	if valAcct.VoteLastValid > 0 || valAcct.VoteFirstValid > 0 {
		status = basics.Online
	}
	return onlineAcctModelAcct{
		VoteFirstValid: valAcct.VoteFirstValid,
		VoteLastValid:  valAcct.VoteLastValid,
		Status:         status,
		Stake:          valAcct.MicroAlgosWithRewards,
	}
}

//nolint:paralleltest // don't want to parallelize this test
func TestOnlineAcctModelSimple(t *testing.T) {
	partitiontest.PartitionTest(t)

	// first test using the in-memory model
	t.Run("Map", func(t *testing.T) {
		m := newMapOnlineAcctModel(t)
		testOnlineAcctModelSimple(t, m)
	})
	// test same scenario on double ledger
	t.Run("DoubleLedger", func(t *testing.T) {
		m := newDoubleLedgerAcctModel(t, protocol.ConsensusFuture, true)
		defer m.teardown()
		testOnlineAcctModelSimple(t, m)
	})
}

func testOnlineAcctModelSimple(t *testing.T, m onlineAcctModel) {
	// acct 1 has 10 algos expiring at round 2000
	m.goOnline(basics.Address{1}, 1, 2000)
	m.updateStake(basics.Address{1}, basics.MicroAlgos{Raw: 10_000_000})
	// acct 2 has 11 algos expiring at round 999
	m.goOnline(basics.Address{2}, 1, 999)
	m.updateStake(basics.Address{2}, basics.MicroAlgos{Raw: 11_000_000})

	m.advanceToRound(500)
	// acct 3 has 11.1 algos expiring at round 2500
	m.goOnline(basics.Address{3}, 500, 2500)
	m.updateStake(basics.Address{3}, basics.MicroAlgos{Raw: 11_100_000})

	m.advanceToRound(600)
	// acct 4 has 11.11 algos expiring at round 900
	m.goOnline(basics.Address{4}, 600, 900)
	m.updateStake(basics.Address{4}, basics.MicroAlgos{Raw: 11_110_000})

	m.advanceToRound(1000)
	// total stake is all 4 accounts
	a := require.New(t)
	onlineStake := m.OnlineCirculation(680, 1000)
	a.Equal(basics.MicroAlgos{Raw: 43_210_000}, onlineStake)

	// expired stake is acct 2 + acct 4
	expiredStake := m.expiredOnlineCirculation(680, 1000)
	a.Equal(basics.MicroAlgos{Raw: 22_110_000}, expiredStake)
}

// An onlineScenario is a list of actions to take at each round, which are
// applied to the onlineAcctModel implementations (real and oracle) being tested.
type onlineScenario struct {
	// roundActions is a list of actions to take in each round, must be in rnd order
	roundActions []onlineScenarioRound
}

type onlineScenarioRound struct {
	rnd     basics.Round
	actions []onlineScenarioRoundAction
}

// An onlineScenarioRoundAction is an action to take on an onlineAcctModel in a given round.
type onlineScenarioRoundAction interface {
	apply(t *testing.T, m onlineAcctModel)
}

type goOnlineWithStakeAction struct {
	addr   basics.Address
	fv, lv basics.Round
	stake  uint64
}

func (a goOnlineWithStakeAction) apply(t *testing.T, m onlineAcctModel) {
	m.goOnline(a.addr, a.fv, a.lv)
	m.updateStake(a.addr, basics.MicroAlgos{Raw: a.stake})
}

type goOfflineAction struct{ addr basics.Address }

func (a goOfflineAction) apply(t *testing.T, m onlineAcctModel) { m.goOffline(a.addr) }

type checkOnlineStakeAction struct {
	rnd, voteRnd    basics.Round
	online, expired uint64
}

func (a checkOnlineStakeAction) apply(t *testing.T, m onlineAcctModel) {
	onlineStake := m.OnlineCirculation(a.rnd, a.voteRnd)
	expiredStake := m.expiredOnlineCirculation(a.rnd, a.voteRnd)
	require.Equal(t, basics.MicroAlgos{Raw: a.online}, onlineStake, "round %d, cur %d", a.rnd, m.currentRound())
	require.Equal(t, basics.MicroAlgos{Raw: a.expired}, expiredStake, "rnd %d voteRnd %d, cur %d", a.rnd, a.voteRnd, m.currentRound())
}

// simpleOnlineScenario is the same as the TestOnlineAcctModelSimple test
// but expressed as an onlineScenario
var simpleOnlineScenario = onlineScenario{
	roundActions: []onlineScenarioRound{
		{1, []onlineScenarioRoundAction{
			// acct 1 has 10 algos expiring at round 2000
			goOnlineWithStakeAction{basics.Address{1}, 1, 2000, 10_000_000},
			// acct 2 has 11 algos expiring at round 999
			goOnlineWithStakeAction{basics.Address{2}, 1, 999, 11_000_000},
		}},
		{500, []onlineScenarioRoundAction{
			// acct 3 has 11.1 algos expiring at round 2500
			goOnlineWithStakeAction{basics.Address{3}, 500, 2500, 11_100_000},
		}},
		{600, []onlineScenarioRoundAction{
			// acct 4 has 11.11 algos expiring at round 900
			goOnlineWithStakeAction{basics.Address{4}, 600, 900, 11_110_000},
		}},
		{681, []onlineScenarioRoundAction{
			// total stake is all 4 accounts
			// expired stake is acct 2 + acct 4
			checkOnlineStakeAction{680, 1000, 43_210_000, 22_110_000},
		}},
		{1000, []onlineScenarioRoundAction{
			// check total & expired stake again at round 1000, should be the same
			checkOnlineStakeAction{680, 1000, 43_210_000, 22_110_000},
		}},
	},
}

// a quick helper function for making it easier to identify whose balances are missing
func shift1AlgoBy(n uint64) uint64 { return 1_000_000 << n }

// simpleOfflineOnlineScenario is like simpleOnlineScenario but with acct 2
// going from online+expired to offline at round 999.
var simpleOfflineOnlineScenario = onlineScenario{
	roundActions: []onlineScenarioRound{
		{1, []onlineScenarioRoundAction{
			goOnlineWithStakeAction{basics.Address{1}, 1, 2000, shift1AlgoBy(1)},
			goOnlineWithStakeAction{basics.Address{2}, 1, 999, shift1AlgoBy(2)},
		}},
		{500, []onlineScenarioRoundAction{
			goOnlineWithStakeAction{basics.Address{3}, 500, 2500, shift1AlgoBy(3)},
		}},
		{600, []onlineScenarioRoundAction{
			goOnlineWithStakeAction{basics.Address{4}, 600, 900, shift1AlgoBy(4)}, // expired by 1000
		}},
		{679, []onlineScenarioRoundAction{
			goOnlineWithStakeAction{basics.Address{5}, 679, 999, shift1AlgoBy(5)}, // expired by 1000
			goOfflineAction{basics.Address{2}},                                    // was going to expire at 999 but now is offline
		}},
		{680, []onlineScenarioRoundAction{
			goOnlineWithStakeAction{basics.Address{6}, 680, 999, shift1AlgoBy(6)}, // expired by 1000
			goOnlineWithStakeAction{basics.Address{7}, 680, 1000, shift1AlgoBy(7)},
		}},
		{1000, []onlineScenarioRoundAction{
			checkOnlineStakeAction{680, 1000, 250_000_000, 112_000_000},
		}},
	},
}

//nolint:paralleltest // don't want to parallelize this test
func TestOnlineAcctModelScenario(t *testing.T) {
	partitiontest.PartitionTest(t)

	runScenario := func(t *testing.T, m onlineAcctModel, s onlineScenario) {
		for _, ra := range s.roundActions {
			m.advanceToRound(ra.rnd)
			for _, action := range ra.actions {
				action.apply(t, m)
			}
		}
	}

	for _, tc := range []struct {
		name     string
		scenario onlineScenario
	}{
		{"Simple", simpleOnlineScenario},
		{"SimpleOffline", simpleOfflineOnlineScenario},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// first test using the in-memory model
			t.Run("Map", func(t *testing.T) {
				m := newMapOnlineAcctModel(t)
				runScenario(t, m, tc.scenario)
			})
			// test same scenario on double ledger
			t.Run("DoubleLedger", func(t *testing.T) {
				m := newDoubleLedgerAcctModel(t, protocol.ConsensusFuture, true)
				defer m.teardown()
				runScenario(t, m, tc.scenario)
			})
		})
	}
}

func BenchmarkExpiredOnlineCirculation(b *testing.B) {
	// set up totalAccounts online accounts in 10k batches
	totalAccounts := 100_000
	const maxKeyregPerBlock = 10_000
	// if TOTAL_ACCOUNTS env var set, override totalAccounts
	if n, err := strconv.Atoi(os.Getenv("TOTAL_ACCOUNTS")); err == nil {
		b.Logf("using %d accounts", n)
		if n%maxKeyregPerBlock != 0 {
			b.Fatalf("TOTAL_ACCOUNTS %d must be a multiple of %d", n, maxKeyregPerBlock)
		}
		totalAccounts = n
	}

	proto := protocol.ConsensusFuture
	m := newDoubleLedgerAcctModel(b, proto, false)
	defer m.teardown()

	addrFromUint64 := func(n uint64) basics.Address {
		var addr basics.Address
		binary.BigEndian.PutUint64(addr[:], n)
		return addr
	}

	var blockCounter basics.Round
	var acctCounter uint64
	for i := 0; i < totalAccounts/maxKeyregPerBlock; i++ {
		blockCounter++
		for j := 0; j < maxKeyregPerBlock; j++ {
			acctCounter++
			// go online for a random number of rounds, from 400 to 1600
			validFor := 400 + basics.Round(rand.Intn(1200))
			m.goOnline(addrFromUint64(acctCounter), blockCounter, blockCounter+validFor)
		}
		b.Log("built block", blockCounter, "accts", acctCounter)
		m.nextRound()
	}
	// then advance ~1K rounds to exercise the exercise accounts going offline
	m.advanceToRound(blockCounter + 1000)
	b.Log("advanced to round", m.currentRound())

	b.ResetTimer()
	for i := range basics.Round(b.N) {
		// query expired circulation across the available range (last 320 rounds, from ~680 to ~1000)
		startRnd := m.currentRound() - 320
		offset := i % 320
		_, err := m.dl.validator.expiredOnlineCirculation(startRnd+offset, startRnd+offset+320)
		require.NoError(b, err)
		//total, err := m.dl.validator.OnlineTotalStake(startRnd + offset)
		//b.Log("expired circulation", startRnd+offset, startRnd+offset+320, "returned", expiredStake, "total", total)
	}
}

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

package agreementtest

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var deadline = time.Second * 5

var proto = protocol.ConsensusCurrentVersion

type signal struct {
	ch    chan struct{}
	fired bool
}

func makeSignal() signal {
	var s signal
	s.ch = make(chan struct{})
	return s
}

func (s signal) wait() {
	<-s.ch
}

func (s signal) fire() signal {
	if !s.fired {
		close(s.ch)
	}
	return signal{s.ch, true}
}

type testValidatedBlock struct {
	Inside bookkeeping.Block
}

func (b testValidatedBlock) Block() bookkeeping.Block {
	return b.Inside
}

func (b testValidatedBlock) WithSeed(s committee.Seed) agreement.ValidatedBlock {
	b.Inside.BlockHeader.Seed = s
	return b
}

type testBlockValidator struct{}

func (v testBlockValidator) Validate(ctx context.Context, e bookkeeping.Block) (agreement.ValidatedBlock, error) {
	return testValidatedBlock{Inside: e}, nil
}

type testBlockFactory struct {
	Owner int
}

func (f testBlockFactory) AssembleBlock(r basics.Round, deadline time.Time) (agreement.ValidatedBlock, error) {
	return testValidatedBlock{Inside: bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: r}}}, nil
}

func (f testBlockFactory) ReconstructBlock(block bookkeeping.Block) error {return nil}

// If we try to read from high rounds, we panic and do not emit an error to find bugs during testing.
type testLedger struct {
	mu deadlock.Mutex

	entries   map[basics.Round]bookkeeping.Block
	certs     map[basics.Round]agreement.Certificate
	nextRound basics.Round

	// constant
	state map[basics.Address]basics.AccountData

	notifications map[basics.Round]signal
}

func makeTestLedger(state map[basics.Address]basics.AccountData) agreement.Ledger {
	l := new(testLedger)
	l.entries = make(map[basics.Round]bookkeeping.Block)
	l.certs = make(map[basics.Round]agreement.Certificate)
	l.nextRound = 1
	l.state = state
	l.notifications = make(map[basics.Round]signal)
	return l
}

func (l *testLedger) copy() *testLedger {
	dup := new(testLedger)

	dup.entries = make(map[basics.Round]bookkeeping.Block)
	dup.certs = make(map[basics.Round]agreement.Certificate)
	dup.state = make(map[basics.Address]basics.AccountData)
	dup.notifications = make(map[basics.Round]signal)

	for k, v := range l.entries {
		dup.entries[k] = v
	}
	for k, v := range l.certs {
		dup.certs[k] = v
	}
	for k, v := range l.state {
		dup.state[k] = v
	}
	for k, v := range dup.notifications {
		// note that old opened channels will now fire when these are closed
		dup.notifications[k] = v
	}
	dup.nextRound = l.nextRound

	return dup
}

func (l *testLedger) NextRound() basics.Round {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.nextRound
}

func (l *testLedger) Wait(r basics.Round) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.notifications[r]; !ok {
		l.notifications[r] = makeSignal()
	}

	if l.nextRound > r {
		l.notify(r)
	}

	return l.notifications[r].ch
}

// note: this must be called when any new entry is written
// this should be called while the lock l.mu is held
func (l *testLedger) notify(r basics.Round) {
	if _, ok := l.notifications[r]; !ok {
		l.notifications[r] = makeSignal()
	}

	l.notifications[r] = l.notifications[r].fire()
}

func (l *testLedger) Seed(r basics.Round) (committee.Seed, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Seed called on future round: %v > %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	b := l.entries[r]
	return b.Seed(), nil
}

func (l *testLedger) LookupDigest(r basics.Round) (crypto.Digest, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Seed called on future round: %v > %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	return l.entries[r].Digest(), nil
}

func (l *testLedger) Lookup(r basics.Round, a basics.Address) (basics.AccountData, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Lookup called on future round: %v > %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}
	return l.state[a], nil
}

func (l *testLedger) Circulation(r basics.Round) (basics.MicroAlgos, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Circulation called on future round: %v > %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	var sum basics.MicroAlgos
	var overflowed bool
	for _, rec := range l.state {
		sum, overflowed = basics.OAddA(sum, rec.VotingStake())
		if overflowed {
			panic("circulation computation overflowed")
		}
	}
	return sum, nil
}

func (l *testLedger) ConsensusParams(basics.Round) (config.ConsensusParams, error) {
	return config.Consensus[protocol.ConsensusCurrentVersion], nil
}

func (l *testLedger) ConsensusVersion(basics.Round) (protocol.ConsensusVersion, error) {
	return protocol.ConsensusCurrentVersion, nil
}

func (l *testLedger) EnsureValidatedBlock(e agreement.ValidatedBlock, c agreement.Certificate) {
	l.EnsureBlock(e.Block(), c)
}

func (l *testLedger) EnsureBlock(e bookkeeping.Block, c agreement.Certificate) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.entries[e.Round()]; ok {
		if l.entries[e.Round()].Digest() != e.Digest() {
			err := fmt.Errorf("testLedger.EnsureBlock called with conflicting entries in round %d", e.Round())
			panic(err)
		}
	}

	l.entries[e.Round()] = e
	l.certs[e.Round()] = c

	if l.nextRound < e.Round()+1 {
		l.nextRound = e.Round() + 1
	}

	l.notify(e.Round())
}

func (l *testLedger) EnsureDigest(c agreement.Certificate, verifier *agreement.AsyncVoteVerifier) {
	r := c.Round
	consistencyCheck := func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()

		if r < l.nextRound {
			if l.entries[r].Digest() != c.Proposal.BlockDigest {
				err := fmt.Errorf("testLedger.EnsureDigest called with conflicting entries in round %d", r)
				panic(err)
			}
			return true
		}
		return false
	}

	if consistencyCheck() {
		return
	}

	<-l.Wait(r)
	if !consistencyCheck() {
		err := fmt.Errorf("Wait channel fired without matching block in round %d", r)
		panic(err)
	}
}

func TestSimulate(t *testing.T) {
	f, _ := os.Create(t.Name() + ".log")
	logging.Base().SetJSONFormatter()
	logging.Base().SetOutput(f)
	logging.Base().SetLevel(logging.Debug)

	numAccounts := 10
	maxMoneyAtStart := 100001 // max money start
	minMoneyAtStart := 100000 // max money start
	E := basics.Round(50)     // max round

	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	incentivePoolAtStart := uint64(1000 * 1000)
	accData := basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: incentivePoolAtStart})
	genesis[poolAddr] = accData
	gen := rand.New(rand.NewSource(2))

	_, accs, release := generateNAccounts(t, numAccounts, 0, E, minMoneyAtStart)
	defer release()
	for _, account := range accs {
		amount := basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))}
		genesis[account.Address()] = basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  amount,
			SelectionID: account.VRFSecrets().PK,
			VoteID:      account.VotingSecrets().OneTimeSignatureVerifier,
		}
	}

	l := makeTestLedger(genesis)
	err := Simulate(t.Name(), 10, deadline, l, SimpleKeyManager(accs), testBlockFactory{}, testBlockValidator{}, logging.Base())
	require.NoError(t, err)
}

func generateNAccounts(t *testing.T, N int, firstRound, lastRound basics.Round, fee int) (roots []account.Root, accounts []account.Participation, release func()) {
	allocatedAccessors := []db.Accessor{}
	release = func() {
		for _, acc := range allocatedAccessors {
			acc.Close()
		}
	}
	for i := 0; i < N; i++ {
		access, err := db.MakeAccessor(t.Name()+"_root_testingenv_"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		allocatedAccessors = append(allocatedAccessors, access)
		root, err := account.GenerateRoot(access)
		if err != nil {
			panic(err)
		}
		roots = append(roots, root)

		access, err = db.MakeAccessor(t.Name()+"_part_testingenv_"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		allocatedAccessors = append(allocatedAccessors, access)
		part, err := account.FillDBWithParticipationKeys(access, root.Address(), firstRound, lastRound, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		if err != nil {
			panic(err)
		}
		accounts = append(accounts, part)
	}
	return
}

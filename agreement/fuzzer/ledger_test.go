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

package fuzzer

import (
	"context"
	"fmt"
	"maps"
	"math/rand"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
)

const randseed = 0
const keysForward = 10
const minMoneyAtStart = 10000
const maxMoneyAtStart = 100000

var readOnlyParticipationVotes = []*crypto.OneTimeSignatureSecrets{}

func init() {
	rand.Seed(randseed)
	for i := 0; i < 64; i++ {
		prngSeed := []byte(fmt.Sprintf("Fuzzer-OTSS-PRNG-%d", i))
		rng := crypto.MakePRNG(prngSeed)
		readOnlyParticipationVotes = append(readOnlyParticipationVotes, crypto.GenerateOneTimeSignatureSecretsRNG(0, 1000, rng))
	}
}

func generatePseudoRandomVRF(keynum int) *crypto.VRFSecrets {
	seed := [32]byte{}
	seed[0] = byte(keynum % 255)
	seed[1] = byte(keynum / 255)
	pk, sk := crypto.VrfKeygenFromSeed(seed)
	return &crypto.VRFSecrets{
		PK: pk,
		SK: sk,
	}
}

func randomBlockHash() (h crypto.Digest) {
	rand.Read(h[:])
	return
}

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

func (b testValidatedBlock) Round() basics.Round {
	return b.Inside.Round()
}

func (b testValidatedBlock) FinishBlock(s committee.Seed, proposer basics.Address, eligible bool) agreement.Block {
	b.Inside.BlockHeader.Seed = s
	b.Inside.BlockHeader.Proposer = proposer
	if !eligible {
		b.Inside.BlockHeader.ProposerPayout = basics.MicroAlgos{}
	}
	return agreement.Block(b.Inside)
}

type testBlockValidator struct{}

func (v testBlockValidator) Validate(ctx context.Context, e bookkeeping.Block) (agreement.ValidatedBlock, error) {
	return testValidatedBlock{Inside: e}, nil
}

type testBlockFactory struct {
	Owner int
}

func (f testBlockFactory) AssembleBlock(r basics.Round, _ []basics.Address) (agreement.UnfinishedBlock, error) {
	return testValidatedBlock{Inside: bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: r}}}, nil
}

type testLedgerSyncFunc func(l *testLedger, r basics.Round, c agreement.Certificate) bool

// If we try to read from high rounds, we panic and do not emit an error to find bugs during testing.
type testLedger struct {
	mu deadlock.Mutex

	entries   map[basics.Round]bookkeeping.Block
	certs     map[basics.Round]agreement.Certificate
	nextRound basics.Round

	// constant
	state map[basics.Address]basics.AccountData

	notifications map[basics.Round]signal

	Sync                  testLedgerSyncFunc
	EnsuringDigestStartCh chan struct{}
	EnsuringDigestDoneCh  chan struct{}
	ensuringDigestMu      deadlock.Mutex
	ensuringDigest        bool
	ensuringDigestTry     chan struct{}
	catchingUp            bool
}

func makeTestLedger(state map[basics.Address]basics.AccountData, sync testLedgerSyncFunc) *testLedger {
	l := new(testLedger)
	l.Sync = sync
	l.entries = make(map[basics.Round]bookkeeping.Block)
	l.certs = make(map[basics.Round]agreement.Certificate)
	l.nextRound = 1

	l.state = make(map[basics.Address]basics.AccountData)
	maps.Copy(l.state, state)

	l.notifications = make(map[basics.Round]signal)
	l.EnsuringDigestStartCh = make(chan struct{})
	l.EnsuringDigestDoneCh = make(chan struct{})
	close(l.EnsuringDigestDoneCh)
	l.ensuringDigestTry = make(chan struct{}, 1)

	return l
}

func (l *testLedger) EnsureValidatedBlock(e agreement.ValidatedBlock, c agreement.Certificate) {
	l.EnsureBlock(e.Block(), c)
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

func (l *testLedger) ClearNotifications() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.notifications = make(map[basics.Round]signal)
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
		err := fmt.Errorf("Seed for round %d doesn't exists in ledger. Current ledger round is %d", r, l.nextRound-1)
		return committee.Seed{}, err
	}

	b := l.entries[r]
	return b.Seed(), nil
}

func (l *testLedger) LookupDigest(r basics.Round) (crypto.Digest, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("LookupDigest called on future round: %d >= %d! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	return l.entries[r].Digest(), nil
}

func (l *testLedger) LookupAgreement(r basics.Round, a basics.Address) (basics.OnlineAccountData, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Lookup called on future round: %d >= %d! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}
	return basics_testing.OnlineAccountData(l.state[a]), nil
}

func (l *testLedger) Circulation(r basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Circulation called on future round: %d >= %d! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	var sum basics.MicroAlgos
	var overflowed bool
	for _, rec := range l.state {
		sum, overflowed = basics.OAddA(sum, basics_testing.OnlineAccountData(rec).VotingStake())
		if overflowed {
			panic("circulation computation overflowed")
		}
	}
	return sum, nil
}

func (l *testLedger) EnsureBlock(e bookkeeping.Block, c agreement.Certificate) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.entries[e.Round()]; ok {
		if l.entries[e.Round()].Digest() != e.Digest() {
			err := fmt.Errorf("testLedger.EnsureBlock: called with conflicting entries in round %d", e.Round())
			panic(err)
		}
	}

	l.entries[e.Round()] = e
	l.certs[e.Round()] = c

	if l.nextRound == e.Round() {
		l.nextRound = e.Round() + 1
	} else if l.nextRound < e.Round() {
		err := fmt.Errorf("testLedger.EnsureBlock: attempted to write block in future round: %d < %d", l.nextRound, e.Round())
		panic(err)
	}

	l.notify(e.Round())
	l.catchingUp = false
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
	// try without any locks.
	if l.Sync(l, r, c) {
		return
	}

	l.ensuringDigestMu.Lock()
	l.ensuringDigest = true
	l.EnsuringDigestDoneCh = make(chan struct{})
	close(l.EnsuringDigestStartCh)
	select {
	case <-l.ensuringDigestTry:
	default:
	}
	l.ensuringDigestMu.Unlock()

	for exitSync := false; exitSync == false; {
		if l.Sync(l, r, c) {
			exitSync = true
			continue
		}
		<-l.ensuringDigestTry
	}

	l.ensuringDigestMu.Lock()
	select {
	case <-l.ensuringDigestTry:
	default:
	}
	l.ensuringDigest = false
	close(l.EnsuringDigestDoneCh)
	l.EnsuringDigestStartCh = make(chan struct{})
	l.ensuringDigestMu.Unlock()
}

func (l *testLedger) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	ver, _ := l.ConsensusVersion(r)
	return config.Consensus[ver], nil
}

func (l *testLedger) ConsensusVersion(r basics.Round) (protocol.ConsensusVersion, error) {
	return protocol.ConsensusCurrentVersion, nil
}

func (l *testLedger) TryEnsuringDigest() bool {
	l.ensuringDigestMu.Lock()
	defer l.ensuringDigestMu.Unlock()
	select {
	case l.ensuringDigestTry <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *testLedger) GetEnsuringDigestCh(start bool) chan struct{} {
	l.ensuringDigestMu.Lock()
	defer l.ensuringDigestMu.Unlock()
	if start {
		return l.EnsuringDigestStartCh
	}
	return l.EnsuringDigestDoneCh
}

func (l *testLedger) IsEnsuringDigest() bool {
	l.ensuringDigestMu.Lock()
	defer l.ensuringDigestMu.Unlock()
	return l.ensuringDigest
}

func (l *testLedger) Catchup(o *testLedger, targetNextRound basics.Round) {
	l.mu.Lock()
	o.mu.Lock()

	startRound := l.nextRound
	for l.nextRound < targetNextRound {
		l.entries[l.nextRound] = o.entries[l.nextRound]
		l.certs[l.nextRound] = o.certs[l.nextRound]
		l.nextRound++
	}

	o.mu.Unlock()

	for r := startRound; r < l.nextRound; r++ {
		l.notify(r)
	}

	l.mu.Unlock()
}

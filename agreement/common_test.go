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

package agreement

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const randseed = 0
const keyBatchesForward = 10
const minMoneyAtStart = 10000
const maxMoneyAtStart = 100000

var readOnlyGenesis10 map[basics.Address]basics.AccountData
var readOnlyAddrs10 []basics.Address
var readOnlyVRF10 []*crypto.VRFSecrets
var readOnlyOT10 []crypto.OneTimeSigner

var readOnlyGenesis100 map[basics.Address]basics.AccountData
var readOnlyAddrs100 []basics.Address
var readOnlyVRF100 []*crypto.VRFSecrets
var readOnlyOT100 []crypto.OneTimeSigner

var readOnlyGenesis7000 map[basics.Address]basics.AccountData
var readOnlyAddrs7000 []basics.Address
var readOnlyVRF7000 []*crypto.VRFSecrets
var readOnlyOT7000 []crypto.OneTimeSigner

var routerFixture rootRouter

func init() {
	rand.Seed(randseed)

	readOnlyGenesis10, readOnlyAddrs10, readOnlyVRF10, readOnlyOT10 = generateEnvironment(10)
	readOnlyGenesis100, readOnlyAddrs100, readOnlyVRF100, readOnlyOT100 = generateEnvironment(100)
	readOnlyGenesis7000, readOnlyAddrs7000, readOnlyVRF7000, readOnlyOT7000 = generateEnvironment(7000)
}

func readOnlyFixture10() (Ledger, []basics.Address, []*crypto.VRFSecrets, []crypto.OneTimeSigner) {
	// generate accounts
	ledger := makeTestLedger(readOnlyGenesis10)
	return ledger, readOnlyAddrs10, readOnlyVRF10, readOnlyOT10
}

func readOnlyFixture100() (Ledger, []basics.Address, []*crypto.VRFSecrets, []crypto.OneTimeSigner) {
	// generate accounts
	ledger := makeTestLedger(readOnlyGenesis100)
	return ledger, readOnlyAddrs100, readOnlyVRF100, readOnlyOT100
}

func readOnlyFixture7000() (Ledger, []basics.Address, []*crypto.VRFSecrets, []crypto.OneTimeSigner) {
	// generate accounts
	ledger := makeTestLedger(readOnlyGenesis7000)
	return ledger, readOnlyAddrs7000, readOnlyVRF7000, readOnlyOT7000
}

func generateKeys(latest basics.Round, keyBatchesForward uint) (basics.Address, *crypto.VRFSecrets, *crypto.OneTimeSignatureSecrets) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	v := crypto.GenerateVRFSecrets()
	o := crypto.GenerateOneTimeSignatureSecrets(basics.OneTimeIDForRound(latest, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution).Batch, uint64(keyBatchesForward))
	addr := basics.Address(s.SignatureVerifier)
	return addr, v, o
}

func generateEnvironment(numAccounts int) (map[basics.Address]basics.AccountData, []basics.Address, []*crypto.VRFSecrets, []crypto.OneTimeSigner) {
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	addrs := make([]basics.Address, numAccounts)
	vrfSecrets := make([]*crypto.VRFSecrets, numAccounts)
	otSecrets := make([]crypto.OneTimeSigner, numAccounts)
	var total basics.MicroAlgos
	for i := 0; i < numAccounts; i++ {
		addr, vrfSec, otSec := generateKeys(0, keyBatchesForward)
		addrs[i] = addr
		vrfSecrets[i] = vrfSec
		otSecrets[i].OneTimeSignatureSecrets = otSec

		startamt := uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))
		genesis[addr] = basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  basics.MicroAlgos{Raw: startamt},
			SelectionID: vrfSec.PK,
			VoteID:      otSec.OneTimeSignatureVerifier,
		}
		total.Raw += startamt
	}

	return genesis, addrs, vrfSecrets, otSecrets
}

func makeRoundRandomBranch(r basics.Round) round {
	return makeRoundBranch(r, bookkeeping.BlockHash(randomBlockHash()))
}

func randomBlockHash() (h crypto.Digest) {
	rand.Read(h[:])
	return
}

func randomVRFProof() (v crypto.VRFProof) {
	rand.Read(v[:])
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

type nullWriter struct{}

func (w nullWriter) Write(data []byte) (n int, err error) {
	return len(data), nil
}

type testValidatedBlock struct {
	Inside bookkeeping.Block
}

func (b testValidatedBlock) Block() bookkeeping.Block {
	return b.Inside
}

func (b testValidatedBlock) WithSeed(s committee.Seed) ValidatedBlock {
	b.Inside.BlockHeader.Seed = s
	return b
}

type testBlockValidator struct{}

func (v testBlockValidator) Validate(ctx context.Context, e bookkeeping.Block) (ValidatedBlock, error) {
	return testValidatedBlock{Inside: e}, nil
}

type testBlockFactory struct {
	Owner int
	ConsensusVersion func(basics.Round) (protocol.ConsensusVersion, error)
}

func (f testBlockFactory) AssembleSpeculativeBlock(r basics.Round, prev bookkeeping.BlockHash, deadline time.Time) (ValidatedBlock, error) {
	proto, err := f.ConsensusVersion(r)
	if err != nil {
		return testValidatedBlock{}, err
	}

	return testValidatedBlock{Inside: bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:  r,
			Branch: prev,
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: proto,
			},
		}}}, nil
}

type blockAndCert struct {
	block bookkeeping.Block
	cert  Certificate
}

type blockAndMaybeCert struct {
	block bookkeeping.Block
	cert  *Certificate
}

// If we try to read from high rounds, we panic and do not emit an error to find bugs during testing.
type testLedger struct {
	mu deadlock.Mutex

	blocks    map[basics.Round]blockAndCert
	nextRound basics.Round

	speculative map[bookkeeping.BlockHash]blockAndMaybeCert

	maxNumBlocks uint64

	// constant
	state map[basics.Address]basics.AccountData

	notifications map[basics.Round]signal

	consensusVersion func(basics.Round) (protocol.ConsensusVersion, error)
}

func makeTestLedger(state map[basics.Address]basics.AccountData) Ledger {
	l := new(testLedger)
	l.blocks = make(map[basics.Round]blockAndCert)
	l.speculative = make(map[bookkeeping.BlockHash]blockAndMaybeCert)
	l.nextRound = 1

	l.state = make(map[basics.Address]basics.AccountData)
	for k, v := range state {
		l.state[k] = v
	}

	l.notifications = make(map[basics.Round]signal)

	l.consensusVersion = func(r basics.Round) (protocol.ConsensusVersion, error) {
		return protocol.ConsensusCurrentVersion, nil
	}
	return l
}

func makeTestLedgerWithConsensusVersion(state map[basics.Address]basics.AccountData, consensusVersion func(basics.Round) (protocol.ConsensusVersion, error)) Ledger {
	l := new(testLedger)
	l.blocks = make(map[basics.Round]blockAndCert)
	l.speculative = make(map[bookkeeping.BlockHash]blockAndMaybeCert)
	l.nextRound = 1

	l.state = make(map[basics.Address]basics.AccountData)
	for k, v := range state {
		l.state[k] = v
	}

	l.notifications = make(map[basics.Round]signal)

	l.consensusVersion = consensusVersion
	return l
}

func makeTestLedgerMaxBlocks(state map[basics.Address]basics.AccountData, maxNumBlocks uint64) Ledger {
	l := new(testLedger)
	l.blocks = make(map[basics.Round]blockAndCert)
	l.speculative = make(map[bookkeeping.BlockHash]blockAndMaybeCert)
	l.nextRound = 1

	l.maxNumBlocks = maxNumBlocks

	l.state = make(map[basics.Address]basics.AccountData)
	for k, v := range state {
		l.state[k] = v
	}

	l.notifications = make(map[basics.Round]signal)

	l.consensusVersion = func(r basics.Round) (protocol.ConsensusVersion, error) {
		return protocol.ConsensusCurrentVersion, nil
	}
	return l
}

func (l *testLedger) NextRound() basics.Round {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.nextRound
}

func (l *testLedger) Wait(r basics.Round, leafBranch bookkeeping.BlockHash) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check for speculative blocks
	for {
		bc, ok := l.speculative[leafBranch]
		if !ok {
			break
		}

		if bc.block.Round() == r {
			c := make(chan struct{})
			close(c)
			return c
		}

		leafBranch = bc.block.Branch
	}

	if _, ok := l.notifications[r]; !ok {
		l.notifications[r] = makeSignal()
	}

	if l.nextRound > r {
		l.notify(r)
	}

	return l.notifications[r].ch
}

// note: this must be called when any new block is written
// this should be called while the lock l.mu is held
func (l *testLedger) notify(r basics.Round) {
	if _, ok := l.notifications[r]; !ok {
		l.notifications[r] = makeSignal()
	}

	l.notifications[r] = l.notifications[r].fire()
}

func (l *testLedger) Seed(r basics.Round, leafBranch bookkeeping.BlockHash) (committee.Seed, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check for speculative blocks
	for {
		bc, ok := l.speculative[leafBranch]
		if !ok {
			break
		}

		if bc.block.Round() == r {
			return bc.block.Seed(), nil
		}

		leafBranch = bc.block.Branch
	}

	if r >= l.nextRound {
		err := fmt.Errorf("Seed called on future round: %v >= %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	b := l.blocks[r]
	return b.block.Seed(), nil
}

func (l *testLedger) LookupDigest(r basics.Round, leafBranch bookkeeping.BlockHash) (crypto.Digest, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("LookupDigest called on future round: %v >= %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	if l.maxNumBlocks != 0 && r+basics.Round(l.maxNumBlocks) < l.nextRound {
		return crypto.Digest{}, &LedgerDroppedRoundError{}
	}

	return l.blocks[r].block.Digest(), nil
}

func (l *testLedger) Lookup(r basics.Round, leafBranch bookkeeping.BlockHash, a basics.Address) (basics.AccountData, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Lookup called on future round: %v >= %v! (this is probably a bug)", r, l.nextRound)
		panic(err)
	}

	if l.maxNumBlocks != 0 && r+basics.Round(l.maxNumBlocks) < l.nextRound {
		return basics.AccountData{}, &LedgerDroppedRoundError{}
	}

	return l.state[a], nil
}

func (l *testLedger) Circulation(r basics.Round, leafBranch bookkeeping.BlockHash) (basics.MicroAlgos, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r >= l.nextRound {
		err := fmt.Errorf("Circulation called on future round: %v >= %v! (this is probably a bug)", r, l.nextRound)
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

func (l *testLedger) EnsureValidatedBlock(e ValidatedBlock, c Certificate) {
	l.EnsureBlock(e.Block(), c)
}

func (l *testLedger) EnsureSpeculativeBlock(e ValidatedBlock) {
	l.mu.Lock()
	defer l.mu.Unlock()

	blk := e.Block()
	l.speculative[blk.Hash()] = blockAndMaybeCert{block: blk}
}

func (l *testLedger) EnsureBlock(e bookkeeping.Block, c Certificate) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if this is a speculative block.  If so, install the
	// certificate for it.
	_, specok := l.speculative[e.Hash()]
	if specok {
		l.speculative[e.Hash()] = blockAndMaybeCert{block: e, cert: &c}
		l.advanceSpeculative()
		return
	}

	if _, ok := l.blocks[e.Round()]; ok {
		if l.blocks[e.Round()].block.Digest() != e.Digest() {
			err := fmt.Errorf("testLedger.EnsureBlock: called with conflicting entries in round %d", e.Round())
			panic(err)
		}
	}

	l.blocks[e.Round()] = blockAndCert{
		block: e,
		cert:  c,
	}

	if l.nextRound == e.Round() {
		l.nextRound = e.Round() + 1
	} else if l.nextRound < e.Round() {
		err := fmt.Errorf("testLedger.EnsureBlock: attempted to write block in future round: %d < %d", l.nextRound, e.Round())
		panic(err)
	}

	l.notify(e.Round())
	l.advanceSpeculative()
}

func (l *testLedger) advanceSpeculative() {
again:
	for h, e := range l.speculative {
		blk := e.block
		if blk.Round() < l.nextRound {
			delete(l.speculative, h)
			continue
		}
		if blk.Round() == l.nextRound && e.cert != nil {
			l.blocks[blk.Round()] = blockAndCert{block: e.block, cert: *e.cert}
			l.nextRound = blk.Round() + 1
			l.notify(blk.Round())
			goto again
		}
	}
}

func (l *testLedger) EnsureDigest(c Certificate, verifier *AsyncVoteVerifier) {
	r := c.Round
	l.mu.Lock()
	defer l.mu.Unlock()

	if r < l.nextRound {
		if l.blocks[r].block.Digest() != c.Proposal.BlockDigest {
			err := fmt.Errorf("testLedger.EnsureDigest called with conflicting entries in round %d", r)
			panic(err)
		}
	}
	// the mock ledger does not actually need to wait for the block.
	// Agreement should function properly even if it never happens.
	// No test right now expects the ledger to eventually ensure digest (we can add one if need be)
	return
}

func (l *testLedger) ConsensusParams(r basics.Round, leafBranch bookkeeping.BlockHash) (config.ConsensusParams, error) {
	version, err := l.ConsensusVersion(r, leafBranch)
	if err != nil {
		return config.ConsensusParams{}, err
	}
	return config.Consensus[version], nil
}

func (l *testLedger) ConsensusVersion(r basics.Round, leafBranch bookkeeping.BlockHash) (protocol.ConsensusVersion, error) {
	return l.consensusVersion(r)
}

// simulation helpers

type testAccountData struct {
	addresses []basics.Address
	vrfs      []*crypto.VRFSecrets
	ots       []crypto.OneTimeSigner
}

func makeProposalsTesting(accs testAccountData, round round, period period, factory BlockFactory, xledger Ledger) (ps []proposal, vs []vote) {
	ledger := LedgerWithoutBranch(xledger)

	ve, err := factory.AssembleSpeculativeBlock(round.Number, round.Branch, time.Now().Add(time.Minute))
	if err != nil {
		logging.Base().Errorf("Could not generate a proposal for round %d: %v", round, err)
		return nil, nil
	}

	params, err := ledger.ConsensusParams(ParamsRound(round.Number))
	if err != nil {
		logging.Base().Errorf("Could not get params for %v (proposal round %d): %v", round, ParamsRound(round.Number), err)
		return nil, nil
	}

	// TODO this common code should be refactored out
	var votes []vote
	proposals := make([]proposal, 0)
	for i := range accs.addresses {
		payload, proposal, err := proposalForBlock(accs.addresses[i], accs.vrfs[i], ve, period, ledger)
		if err != nil {
			logging.Base().Errorf("proposalForBlock could not create proposal under address %v (corrupt VRF key?): %v", accs.addresses[i], err)
			return
		}

		// attempt to make the vote
		rv := rawVote{Sender: accs.addresses[i], Round: round.Number, Period: period, Step: propose, Proposal: proposal}
		if params.AgreementMessagesContainBranch {
			rv.Branch = round.Branch
		}
		uv, err := makeVote(rv, accs.ots[i], accs.vrfs[i], ledger)
		if err != nil {
			logging.Base().Errorf("AccountManager.makeVotes: Could not create vote: %v", err)
			return
		}
		vote, err := uv.verify(ledger)
		if err != nil {
			continue
		}

		// create the block proposal
		proposals = append(proposals, payload)
		votes = append(votes, vote)
	}
	return proposals, votes
}

// makeVotes creates a slice of votes for a given proposal value in a given
// round, period, and step.
func makeVotesTesting(accs testAccountData, round round, period period, step step, proposal proposalValue, xledger Ledger) (vs []vote) {
	ledger := LedgerWithoutBranch(xledger)

	params, err := ledger.ConsensusParams(ParamsRound(round.Number))
	if err != nil {
		return nil
	}

	// TODO this common code should be refactored out
	votes := make([]vote, 0)
	for i := range accs.addresses {
		rv := rawVote{Sender: accs.addresses[i], Round: round.Number, Branch: maybeBranch(params, round.Branch), Period: period, Step: step, Proposal: proposal}
		uv, err := makeVote(rv, accs.ots[i], accs.vrfs[i], ledger)
		if err != nil {
			logging.Base().Errorf("AccountManager.makeVotes: Could not create vote: %v", err)
			return
		}

		vote, err := uv.verify(ledger)
		if err == nil {
			votes = append(votes, vote)
		}
	}

	return votes
}

func makeRandomBlock(rnd basics.Round) bookkeeping.Block {
	return bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: rnd, Branch: bookkeeping.BlockHash(randomBlockHash())}}
}

// equals returns true if and only if two votes are from the same sender and voted for the same thing.
func (v vote) equals(other vote) bool {
	if v.R.Sender != other.R.Sender {
		return false
	}

	if v.R.Round != other.R.Round {
		return false
	}

	if v.R.Period != other.R.Period {
		return false
	}

	if v.R.Step != other.R.Step {
		return false
	}

	if !v.Cred.Equals(other.Cred) {
		return false
	}

	if v.R.Proposal.BlockDigest != other.R.Proposal.BlockDigest {
		return false
	}

	return true
}

/* Fine-grained unit test helpers */

type voteMakerHelper struct {
	proposal  *proposalValue
	addresses map[int]basics.Address
}

func (v *voteMakerHelper) Setup() {
	if v.proposal == nil {
		v.proposal = v.MakeRandomProposalValue()
		v.addresses = make(map[int]basics.Address)
	}
}

func (v *voteMakerHelper) MakeRandomProposalValue() *proposalValue {
	return &proposalValue{
		BlockDigest: randomBlockHash(),
	}
}

func (v *voteMakerHelper) MakeRandomBlock(t *testing.T, r round, proto protocol.ConsensusVersion) ValidatedBlock {
	f := testBlockFactory{Owner: 1, ConsensusVersion: func(basics.Round) (protocol.ConsensusVersion, error) { return proto, nil }}
	ve, err := f.AssembleSpeculativeBlock(r.Number, r.Branch, time.Now().Add(time.Minute))
	require.NoError(t, err)
	return ve
}

func (v *voteMakerHelper) MakeProposalPayload(t *testing.T, r round, ve ValidatedBlock) (*proposal, *proposalValue) {
	var payload unauthenticatedProposal
	payload.Block = ve.Block()
	require.Equal(t, r.Number, payload.Round())
	require.Equal(t, r.Branch, payload.Branch)
	payload.SeedProof = randomVRFProof()

	propVal := proposalValue{
		BlockDigest:    payload.Digest(),
		EncodingDigest: crypto.HashObj(payload),
	}

	return &proposal{unauthenticatedProposal: payload, ve: ve}, &propVal
}

func (v *voteMakerHelper) MakeRandomProposalPayload(t *testing.T, r round, proto protocol.ConsensusVersion) (*proposal, *proposalValue) {
	f := testBlockFactory{Owner: 1, ConsensusVersion: func(basics.Round) (protocol.ConsensusVersion, error) { return proto, nil }}
	ve, err := f.AssembleSpeculativeBlock(r.Number, r.Branch, time.Now().Add(time.Minute))
	require.NoError(t, err)

	var payload unauthenticatedProposal
	payload.Block = ve.Block()
	require.Equal(t, r.Branch, payload.Branch)
	payload.SeedProof = randomVRFProof()

	propVal := proposalValue{
		BlockDigest:    payload.Digest(),
		EncodingDigest: crypto.HashObj(payload),
	}

	return &proposal{unauthenticatedProposal: payload, ve: ve}, &propVal
}

// make a vote for a fixed proposal value
func (v *voteMakerHelper) MakeValidVoteAccepted(t *testing.T, index int, step step) voteAcceptedEvent {
	return v.MakeValidVoteAcceptedVal(t, index, step, *v.proposal)
}

func (v *voteMakerHelper) MakeRawVote(t *testing.T, index int, r round, p period, s step, value proposalValue, params config.ConsensusParams) rawVote {
	if _, ok := v.addresses[index]; !ok {
		v.addresses[index] = basics.Address(randomBlockHash())
	}
	return rawVote{Sender: v.addresses[index], Round: r.Number, Branch: maybeBranch(params, r.Branch), Period: p, Step: s, Proposal: value}
}

func (v *voteMakerHelper) MakeVerifiedVote(t *testing.T, index int, r round, p period, s step, value proposalValue, params config.ConsensusParams) vote {
	return vote{
		R:    v.MakeRawVote(t, index, r, p, s, value, params),
		Cred: committee.Credential{Weight: 1},
	}
}
func (v *voteMakerHelper) MakeEquivocationVote(t *testing.T, index int, r round, p period, s step, weight uint64, params config.ConsensusParams) equivocationVote {
	if _, ok := v.addresses[index]; !ok {
		v.addresses[index] = basics.Address(randomBlockHash())
	}
	pV1 := v.MakeRandomProposalValue()
	pV2 := v.MakeRandomProposalValue()
	return equivocationVote{
		Sender:    v.addresses[index],
		Round:     r.Number,
		Branch:    maybeBranch(params, r.Branch),
		Period:    p,
		Step:      s,
		Cred:      committee.Credential{Weight: weight},
		Proposals: [2]proposalValue{*pV1, *pV2},
	}
}

// make a vote for specified proposal value
func (v *voteMakerHelper) MakeValidVoteAcceptedVal(t *testing.T, index int, step step, value proposalValue) voteAcceptedEvent {
	// these unit tests assume that the vote tracker doesn't validate the integrity of the vote event itself
	vt := v.MakeVerifiedVote(t, index, roundZero, period(8), step, value, config.Consensus[protocol.ConsensusCurrentVersion]) // XXX round(0) ?
	return voteAcceptedEvent{vt, protocol.ConsensusCurrentVersion}
}

func (v *voteMakerHelper) MakeUnauthenticatedVote(t *testing.T, index int, r round, p period, s step, value proposalValue, params config.ConsensusParams) unauthenticatedVote {
	return unauthenticatedVote{
		R:    v.MakeRawVote(t, index, r, p, s, value, params),
		Cred: committee.UnauthenticatedCredential{},
	}
}

// MakeUnauthenticatedBundle creates a bundle where no participant has more than 1 weight
func (v *voteMakerHelper) MakeUnauthenticatedBundle(t *testing.T, r round, p period, s step, value proposalValue, params config.ConsensusParams) unauthenticatedBundle {
	return v.MakeVerifiedBundle(t, r, p, s, value, params).U
}

func (v *voteMakerHelper) MakeVerifiedBundle(t *testing.T, r round, p period, s step, value proposalValue, params config.ConsensusParams) bundle {
	votes := make([]vote, int(s.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(s.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = v.MakeVerifiedVote(t, i, r, p, s, value, params)
	}
	bun := unauthenticatedBundle{
		Round:    r.Number,
		Branch:   maybeBranch(params, r.Branch),
		Period:   p,
		Step:     s,
		Proposal: value,
	}
	return bundle{
		U:     bun,
		Votes: votes,
	}
}

type simpleKeyManager []account.Participation

func (m simpleKeyManager) VotingKeys(votingRound, _ basics.Round) []account.Participation {
	var km []account.Participation
	for _, acc := range m {
		if acc.OverlapsInterval(votingRound, votingRound) {
			km = append(km, acc)
		}
	}
	return km
}

func (m simpleKeyManager) DeleteOldKeys(basics.Round) {
	// noop
}

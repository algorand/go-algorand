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

package catchup

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

var defaultConfig = config.GetDefaultLocal()
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

// Mocked Fetcher will mock UniversalFetcher
type MockedFetcher struct {
	ledger      Ledger
	timeout     bool
	tries       map[basics.Round]int
	latency     time.Duration
	predictable bool
	mu          deadlock.Mutex
}

func (m *MockedFetcher) fetchBlock(ctx context.Context, round basics.Round, peer network.Peer) (*bookkeeping.Block, *agreement.Certificate, time.Duration, error) {
	if m.OutOfPeers(round) {
		return nil, nil, time.Duration(0), nil
	}
	if m.timeout {
		time.Sleep(time.Duration(config.GetDefaultLocal().CatchupHTTPBlockFetchTimeoutSec)*time.Second + time.Second)
	}
	time.Sleep(m.latency)

	if !m.predictable {
		// Add random delay to get it out of sync
		time.Sleep(time.Duration(rand.Int()%50) * time.Millisecond)
	}
	block, err := m.ledger.Block(round)
	if round > m.ledger.LastRound() {
		return nil, nil, time.Duration(0), errors.New("no block")
	} else if err != nil {
		panic(err)
	}

	var cert agreement.Certificate
	cert.Proposal.BlockDigest = block.Digest()
	return &block, &cert, time.Duration(0), nil
}

func (m *MockedFetcher) NumPeers() int {
	return 10
}

func (m *MockedFetcher) OutOfPeers(round basics.Round) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tries[round]; !ok {
		m.tries[round] = 0
	}
	m.tries[round]++
	return m.tries[round] > m.NumPeers()
}

func (m *MockedFetcher) Close() { // noop
}

type mockedAuthenticator struct {
	mu deadlock.Mutex

	errorRound int
	fail       bool
}

func (auth *mockedAuthenticator) Authenticate(blk *bookkeeping.Block, cert *agreement.Certificate) error {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	if (auth.errorRound >= 0 && basics.Round(auth.errorRound) == blk.Round()) || auth.fail {
		// change reply so that block is malformed
		return errors.New("mockedAuthenticator: block is malformed")
	}
	return nil
}

func (auth *mockedAuthenticator) Quit() {}

func (auth *mockedAuthenticator) alter(errorRound int, fail bool) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	auth.errorRound = errorRound
	auth.fail = fail
}

func TestServiceFetchBlocksSameRange(t *testing.T) {
	// Make Ledgers
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, 10)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: -1}, nil)

	syncer.testStart()
	syncer.sync()
	rr, lr := remote.LastRound(), local.LastRound()
	require.Equal(t, rr, lr)
}

func TestPeriodicSync(t *testing.T) {
	// Make Ledger
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, 10)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	auth := &mockedAuthenticator{fail: true}
	initialLocalRound := local.LastRound()
	require.True(t, 0 == initialLocalRound)

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, auth, nil)
	s.deadlineTimeout = 2 * time.Second

	s.Start()
	defer s.Stop()
	time.Sleep(s.deadlineTimeout*2 - 200*time.Millisecond)
	require.Equal(t, initialLocalRound, local.LastRound())
	auth.alter(-1, false)
	time.Sleep(2 * time.Second)

	// Asserts that the last block is the one we expect
	rr, lr := remote.LastRound(), local.LastRound()
	require.Equal(t, rr, lr)
	for r := basics.Round(1); r < remote.LastRound(); r++ {
		localBlock, err := local.Block(r)
		require.NoError(t, err)
		remoteBlock, err := remote.Block(r)
		require.NoError(t, err)
		require.Equal(t, remoteBlock.Hash(), localBlock.Hash())
	}
}

func TestServiceFetchBlocksOneBlock(t *testing.T) {
	// Make Ledger
	numBlocks := 10
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})
	lastRoundAtStart := local.LastRound()

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, numBlocks-1)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: -1}, nil)

	// Get last round

	// Start the service ( dummy )
	s.testStart()

	// Fetch blocks
	s.sync()

	// Asserts that the last block is the one we expect
	require.Equal(t, lastRoundAtStart+basics.Round(numBlocks), local.LastRound())

	// Get the same block we wrote
	block, _, _, err := makeUniversalBlockFetcher(logging.Base(),
		net,
		defaultConfig).fetchBlock(context.Background(), lastRoundAtStart+1, net.peers[0])

	require.NoError(t, err)

	//Check we wrote the correct block
	localBlock, err := local.Block(lastRoundAtStart + 1)
	require.NoError(t, err)
	require.Equal(t, *block, localBlock)
}

func TestAbruptWrites(t *testing.T) {
	numberOfBlocks := 100

	if testing.Short() {
		numberOfBlocks = 10
	}

	// Make Ledger
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	lastRound := local.LastRound()

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, numberOfBlocks-1)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: -1}, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		for i := basics.Round(lastRound + 1); i <= basics.Round(numberOfBlocks); i++ {
			time.Sleep(time.Duration(rand.Uint32()%5) * time.Millisecond)
			blk, err := remote.Block(i)
			require.NoError(t, err)
			var cert agreement.Certificate
			cert.Proposal.BlockDigest = blk.Digest()
			err = local.AddBlock(blk, cert)
			require.NoError(t, err)
		}
	}()

	// Start the service ( dummy )
	s.testStart()

	s.sync()
	require.Equal(t, remote.LastRound(), local.LastRound())
}

func TestServiceFetchBlocksMultiBlocks(t *testing.T) {
	// Make Ledger
	numberOfBlocks := basics.Round(100)
	if testing.Short() {
		numberOfBlocks = basics.Round(10)
	}
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	lastRoundAtStart := local.LastRound()

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, int(numberOfBlocks)-1)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: -1}, nil)
	fetcher := makeUniversalBlockFetcher(logging.Base(), net, defaultConfig)

	// Start the service ( dummy )
	syncer.testStart()

	// Fetch blocks
	syncer.sync()

	// Asserts that the last block is the one we expect
	require.Equal(t, lastRoundAtStart+numberOfBlocks, local.LastRound())

	for i := basics.Round(1); i <= numberOfBlocks; i++ {
		// Get the same block we wrote
		blk, _, _, err2 := fetcher.fetchBlock(context.Background(), i, net.GetPeers()[0])
		require.NoError(t, err2)

		// Check we wrote the correct block
		localBlock, err := local.Block(i)
		require.NoError(t, err)
		require.Equal(t, *blk, localBlock)
		return
	}
}

func TestServiceFetchBlocksMalformed(t *testing.T) {
	// Make Ledger
	numBlocks := 10
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})

	lastRoundAtStart := local.LastRound()

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, numBlocks-1)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: int(lastRoundAtStart + 1)}, nil)

	// Start the service ( dummy )
	s.testStart()

	s.sync()
	require.Equal(t, lastRoundAtStart, local.LastRound())
	// maybe check all peers/clients are closed here?
	//require.True(t, s.fetcherFactory.(*MockedFetcherFactory).fetcher.client.closed)
}

func TestOnSwitchToUnSupportedProtocol(t *testing.T) {
	// Test the interruption in the initial loop
	// This cannot happen in practice, but is used to test the code.
	{
		lastRoundRemote := 5
		lastRoundLocal := 0
		roundWithSwitchOn := 0
		local, remote := helperTestOnSwitchToUnSupportedProtocol(t, lastRoundRemote, lastRoundLocal, roundWithSwitchOn, 0)

		// Last supported round is 0, but is guaranteed
		// to stop after 2 rounds.

		// SeedLookback is 2, which allows two parallel fetches.
		// i.e. rounds 1 and 2 may be simultaneously fetched.
		require.Less(t, int(local.LastRound()), 3)
		require.Equal(t, lastRoundRemote, int(remote.LastRound()))
		remote.Ledger.Close()
	}

	// Test the interruption in "the rest" loop
	{
		lastRoundRemote := 10
		lastRoundLocal := 7
		roundWithSwitchOn := 5
		local, remote := helperTestOnSwitchToUnSupportedProtocol(t, lastRoundRemote, lastRoundLocal, roundWithSwitchOn, 0)
		for r := 1; r <= lastRoundLocal; r++ {
			blk, err := local.Block(basics.Round(r))
			require.NoError(t, err)
			require.Equal(t, r, int(blk.Round()))
		}
		require.Equal(t, lastRoundLocal, int(local.LastRound()))
		require.Equal(t, lastRoundRemote, int(remote.LastRound()))
		remote.Ledger.Close()
	}

	// Test the interruption with short notice (less than
	// SeedLookback or the number of parallel fetches which in the
	// test is the same: 2)

	// This can not happen in practice, because there will be
	// enough rounds for the protocol upgrade notice.
	{
		lastRoundRemote := 14
		lastRoundLocal := 7
		roundWithSwitchOn := 7
		local, remote := helperTestOnSwitchToUnSupportedProtocol(t, lastRoundRemote, lastRoundLocal, roundWithSwitchOn, 0)
		for r := 1; r <= lastRoundLocal; r = r + 1 {
			blk, err := local.Block(basics.Round(r))
			require.NoError(t, err)
			require.Equal(t, r, int(blk.Round()))
		}
		// Since round with switch on (7) can be fetched
		// Simultaneously with round 8, round 8 might also be
		// fetched.
		require.Less(t, int(local.LastRound()), lastRoundLocal+2)
		require.Equal(t, lastRoundRemote, int(remote.LastRound()))
		remote.Ledger.Close()
	}

	// Test the interruption with short notice (less than
	// SeedLookback or the number of parallel fetches which in the
	// test is the same: 2)

	// This case is a variation of the previous case. This may
	// happen when the catchup service restart at the round when
	// an upgrade happens.
	{
		lastRoundRemote := 14
		lastRoundLocal := 7
		roundWithSwitchOn := 7
		roundsAlreadyInLocal := 8 // round 0 -> 7

		local, remote := helperTestOnSwitchToUnSupportedProtocol(
			t,
			lastRoundRemote,
			lastRoundLocal,
			roundWithSwitchOn,
			roundsAlreadyInLocal)

		for r := 1; r <= lastRoundLocal; r = r + 1 {
			blk, err := local.Block(basics.Round(r))
			require.NoError(t, err)
			require.Equal(t, r, int(blk.Round()))
		}
		// Since round with switch on (7) is already in the
		// ledger, round 8 will not be fetched.
		require.Equal(t, int(local.LastRound()), lastRoundLocal)
		require.Equal(t, lastRoundRemote, int(remote.LastRound()))
		remote.Ledger.Close()
	}
}

func helperTestOnSwitchToUnSupportedProtocol(
	t *testing.T,
	lastRoundRemote,
	lastRoundLocal,
	roundWithSwitchOn,
	roundsToCopy int) (Ledger, *data.Ledger) {

	// Make Ledger
	mRemote, mLocal := testingenvWithUpgrade(t, lastRoundRemote, roundWithSwitchOn, lastRoundLocal+1)

	// Copy rounds to local
	for r := 1; r < roundsToCopy; r++ {
		mLocal.blocks = append(mLocal.blocks, mRemote.blocks[r])
	}

	local := mLocal

	config := defaultConfig
	config.CatchupParallelBlocks = 2

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{}) //mRemote.blocks[0])
	if err != nil {
		t.Fatal(err)
		return local, remote
	}
	for i := 1; i < lastRoundRemote; i++ {
		blk.NextProtocolSwitchOn = mRemote.blocks[i].NextProtocolSwitchOn
		blk.NextProtocol = mRemote.blocks[i].NextProtocol
		addBlocks(t, remote, blk, 1)
		blk.BlockHeader.Round++
	}

	// Create a network and block service
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), config, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	s := MakeService(logging.Base(), config, net, local, &mockedAuthenticator{errorRound: -1}, nil)
	s.deadlineTimeout = 2 * time.Second
	s.Start()
	defer s.Stop()

	<-s.done
	return local, remote
}

const defaultRewardUnit = 1e6

type mockedLedger struct {
	mu     deadlock.Mutex
	blocks []bookkeeping.Block
	chans  map[basics.Round]chan struct{}
}

func (m *mockedLedger) NextRound() basics.Round {
	return m.LastRound() + 1
}

func (m *mockedLedger) LastRound() basics.Round {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRound()
}

func (m *mockedLedger) lastRound() basics.Round {
	return m.blocks[len(m.blocks)-1].Round()
}

func (m *mockedLedger) AddBlock(blk bookkeeping.Block, cert agreement.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lastRound := m.lastRound()

	if blk.Round() > lastRound+1 {
		return errors.New("mockedLedger.AddBlock: bad block round provided")
	}

	if blk.Round() < lastRound+1 {
		return nil
	}

	m.blocks = append(m.blocks, blk)
	for r, ch := range m.chans {
		if r <= blk.Round() {
			close(ch)
			delete(m.chans, r)
		}
	}
	return nil
}

func (m *mockedLedger) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return config.Consensus[protocol.ConsensusCurrentVersion], nil
}

func (m *mockedLedger) Wait(r basics.Round) chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()

	lastRound := m.lastRound()
	if lastRound >= r {
		ch := make(chan struct{})
		close(ch)
		return ch
	}

	if m.chans == nil {
		m.chans = make(map[basics.Round]chan struct{})
	}
	if _, ok := m.chans[r]; !ok {
		ch := make(chan struct{})
		m.chans[r] = ch
	}
	return m.chans[r]
}

func (m *mockedLedger) Block(r basics.Round) (bookkeeping.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r > m.lastRound() {
		return bookkeeping.Block{}, errors.New("mockedLedger.Block: round too high")
	}
	return m.blocks[r], nil
}

func (m *mockedLedger) Lookup(basics.Round, basics.Address) (basics.AccountData, error) {
	return basics.AccountData{}, errors.New("not needed for mockedLedger")
}
func (m *mockedLedger) Circulation(basics.Round) (basics.MicroAlgos, error) {
	return basics.MicroAlgos{}, errors.New("not needed for mockedLedger")
}
func (m *mockedLedger) ConsensusVersion(basics.Round) (protocol.ConsensusVersion, error) {
	return protocol.ConsensusCurrentVersion, nil
}
func (m *mockedLedger) EnsureBlock(block *bookkeeping.Block, c agreement.Certificate) {
	m.AddBlock(*block, c)
}
func (m *mockedLedger) Seed(basics.Round) (committee.Seed, error) {
	return committee.Seed{}, errors.New("not needed for mockedLedger")
}

func (m *mockedLedger) LookupDigest(basics.Round) (crypto.Digest, error) {
	return crypto.Digest{}, errors.New("not needed for mockedLedger")
}

func (m *mockedLedger) IsWritingCatchpointFile() bool {
	return false
}

func testingenvWithUpgrade(
	t testing.TB,
	numBlocks,
	roundWithSwitchOn,
	upgradeRound int) (ledger, emptyLedger *mockedLedger) {

	mLedger := new(mockedLedger)
	mEmptyLedger := new(mockedLedger)

	var blk bookkeeping.Block
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion
	mLedger.blocks = append(mLedger.blocks, blk)
	mEmptyLedger.blocks = append(mEmptyLedger.blocks, blk)

	for i := 1; i <= numBlocks; i++ {
		blk = bookkeeping.MakeBlock(blk.BlockHeader)
		if roundWithSwitchOn <= i {
			modifierBlk := blk
			blkh := &modifierBlk.BlockHeader
			blkh.NextProtocolSwitchOn = basics.Round(upgradeRound)
			blkh.NextProtocol = protocol.ConsensusVersion("some-unsupported-protocol")

			mLedger.blocks = append(mLedger.blocks, modifierBlk)
			continue
		}

		mLedger.blocks = append(mLedger.blocks, blk)
	}

	return mLedger, mEmptyLedger
}

type MockVoteVerifier struct{}

func (avv *MockVoteVerifier) Quit() {
}
func (avv *MockVoteVerifier) Parallelism() int {
	return 1
}

// Start the catchup service, without starting the periodic sync.
func (s *Service) testStart() {
	s.done = make(chan struct{})
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.InitialSyncDone = make(chan struct{})
}

func TestCatchupUnmatchedCertificate(t *testing.T) {
	// Make Ledger
	numBlocks := 10
	local := new(mockedLedger)
	local.blocks = append(local.blocks, bookkeeping.Block{})
	lastRoundAtStart := local.LastRound()

	remote, _, blk, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	addBlocks(t, remote, blk, numBlocks-1)

	// Create a network and block service
	blockServiceConfig := config.GetDefaultLocal()
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, remote, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()
	net.addPeer(rootURL)

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, &mockedAuthenticator{errorRound: int(lastRoundAtStart + 1)}, nil)
	s.testStart()
	for roundNumber := 2; roundNumber < 10; roundNumber += 3 {
		pc := &PendingUnmatchedCertificate{
			Cert: agreement.Certificate{
				Round: basics.Round(roundNumber),
			},
			VoteVerifier: agreement.MakeAsyncVoteVerifier(nil),
		}
		block, _ := remote.Block(basics.Round(roundNumber))
		pc.Cert.Proposal.BlockDigest = block.Digest()
		s.syncCert(pc)
	}
}

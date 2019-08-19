// Copyright (C) 2019 Algorand, Inc.
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
	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

var defaultConfig = config.Local{
	Archival:                 false,
	GossipFanout:             4,
	NetAddress:               "",
	BaseLoggerDebugLevel:     1,
	IncomingConnectionsLimit: -1,
}

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

type MockedFetcherFactory struct {
	fetcher *MockedFetcher
	mu      deadlock.Mutex
}

// a lock just to sync swapping internal fetchers
func makeMockFactory(fetcher *MockedFetcher) *MockedFetcherFactory {
	var factory MockedFetcherFactory
	factory.fetcher = fetcher
	return &factory
}

func (factory *MockedFetcherFactory) New() rpcs.Fetcher {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.fetcher
}

func (factory *MockedFetcherFactory) NewOverGossip(tag protocol.Tag) rpcs.Fetcher {
	return factory.New()
}

func (factory *MockedFetcherFactory) changeFetcher(fetcher *MockedFetcher) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	factory.fetcher = fetcher
}

type MockClient struct {
	once   sync.Once
	closed bool
}

func (*MockClient) Address() string {
	return "mock.address."
}
func (c *MockClient) Close() error {
	c.once.Do(func() {
		c.closed = true
	})
	return nil
}
func (c *MockClient) GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	return nil, nil
}

// Mocked Fetcher
type MockedFetcher struct {
	ledger      Ledger
	timeout     bool
	tries       map[basics.Round]int
	client      MockClient
	latency     time.Duration
	predictable bool
	mu          deadlock.Mutex
}

func (m *MockedFetcher) FetchBlock(ctx context.Context, round basics.Round) (*bookkeeping.Block, *agreement.Certificate, rpcs.FetcherClient, error) {
	if m.timeout {
		time.Sleep(rpcs.DefaultFetchTimeout + time.Second)
	}
	time.Sleep(m.latency)

	if !m.predictable {
		// Add random delay to get it out of sync
		time.Sleep(time.Duration(rand.Int()%50) * time.Millisecond)
	}

	block, cert, err := m.ledger.BlockCert(round)
	if round > m.ledger.LastRound() {
		return nil, nil, nil, errors.New("no block")
	} else if err != nil {
		panic(err)
	}

	return &block, &cert, &m.client, nil
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
	// Make Ledger
	remote, local := testingenv(t, 10)

	require.NotNil(t, remote)
	require.NotNil(t, local)

	net := &mocks.MockNetwork{}

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, net, local, nil, &mockedAuthenticator{errorRound: -1})
	syncer.fetcherFactory = makeMockFactory(&MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)})

	syncer.sync()
	require.Equal(t, remote.LastRound(), local.LastRound())
}

func TestPeriodicSync(t *testing.T) {
	// Make Ledger
	remote, local := testingenv(t, 10)

	auth := &mockedAuthenticator{fail: true}
	initialLocalRound := local.LastRound()

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, auth)
	s.deadlineTimeout = 2 * time.Second

	factory := MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)}}
	s.fetcherFactory = &factory
	require.True(t, initialLocalRound < remote.LastRound())

	s.Start()
	defer s.Stop()
	time.Sleep(s.deadlineTimeout*2 - 200*time.Millisecond)
	require.Equal(t, local.LastRound(), initialLocalRound)
	auth.alter(-1, false)
	s.fetcherFactory.(*MockedFetcherFactory).changeFetcher(&MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)})
	time.Sleep(2 * time.Second)

	// Asserts that the last block is the one we expect
	require.Equal(t, remote.LastRound(), local.LastRound())
	for r := basics.Round(0); r < remote.LastRound(); r++ {
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
	remote, local := testingenv(t, numBlocks)
	lastRoundAtStart := local.LastRound()

	net := &mocks.MockNetwork{}

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, nil, &mockedAuthenticator{errorRound: -1})
	factory := MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)}}
	s.fetcherFactory = &factory

	// Get last round
	require.False(t, factory.fetcher.client.closed)

	// Fetch blocks
	s.sync()

	// Asserts that the last block is the one we expect
	require.Equal(t, lastRoundAtStart+basics.Round(numBlocks), local.LastRound())
	require.False(t, factory.fetcher.client.closed)

	// Get the same block we wrote
	block, _, client, err := factory.New().FetchBlock(context.Background(), lastRoundAtStart+1)
	require.NoError(t, err)
	require.False(t, client.(*MockClient).closed)

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
	remote, local := testingenv(t, numberOfBlocks)

	lastRound := local.LastRound()

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, &mockedAuthenticator{errorRound: -1})
	factory := MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)}}
	s.fetcherFactory = &factory

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		for i := basics.Round(lastRound + 1); i <= basics.Round(numberOfBlocks); i++ {
			time.Sleep(time.Duration(rand.Uint32()%5) * time.Millisecond)
			blk, cert, err := remote.BlockCert(i)
			require.NoError(t, err)
			err = local.AddBlock(blk, cert)
			require.NoError(t, err)
		}
	}()

	s.sync()
	require.Equal(t, remote.LastRound(), local.LastRound())
}

func TestServiceFetchBlocksMultiBlocks(t *testing.T) {
	// Make Ledger
	numberOfBlocks := basics.Round(100)
	if testing.Short() {
		numberOfBlocks = basics.Round(10)
	}
	remote, local := testingenv(t, int(numberOfBlocks))
	lastRoundAtStart := local.LastRound()

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, &mockedAuthenticator{errorRound: -1})
	syncer.fetcherFactory = &MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)}}

	// Fetch blocks
	syncer.sync()

	// Asserts that the last block is the one we expect
	require.Equal(t, lastRoundAtStart+numberOfBlocks, local.LastRound())

	for i := basics.Round(1); i <= numberOfBlocks; i++ {
		// Get the same block we wrote
		blk, _, client, err2 := syncer.fetcherFactory.New().FetchBlock(context.Background(), i)
		require.NoError(t, err2)
		require.False(t, client.(*MockClient).closed)

		// Check we wrote the correct block
		localBlock, err := local.Block(i)
		require.NoError(t, err)
		require.Equal(t, *blk, localBlock)
		return
	}
}

func TestServiceFetchBlocksMalformed(t *testing.T) {
	// Make Ledger
	remote, local := testingenv(t, 10)

	lastRoundAtStart := local.LastRound()
	// Make Service
	s := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, &mockedAuthenticator{errorRound: int(lastRoundAtStart + 1)})
	s.fetcherFactory = &MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int)}}

	s.sync()
	require.Equal(t, lastRoundAtStart, local.LastRound())
	require.True(t, s.fetcherFactory.(*MockedFetcherFactory).fetcher.client.closed)
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

func (m *mockedLedger) BlockCert(r basics.Round) (bookkeeping.Block, agreement.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r > m.lastRound() {
		return bookkeeping.Block{}, agreement.Certificate{}, errors.New("mockedLedger.BlockCert: round too high")
	}
	return m.blocks[r], agreement.Certificate{}, nil
}

func (m *mockedLedger) Block(r basics.Round) (bookkeeping.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r > m.lastRound() {
		return bookkeeping.Block{}, errors.New("mockedLedger.Block: round too high")
	}
	return m.blocks[r], nil
}

func testingenv(t testing.TB, numBlocks int) (ledger, emptyLedger Ledger) {
	mLedger := new(mockedLedger)
	mEmptyLedger := new(mockedLedger)

	var blk bookkeeping.Block
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion
	mLedger.blocks = append(mLedger.blocks, blk)
	mEmptyLedger.blocks = append(mEmptyLedger.blocks, blk)

	for i := 1; i <= numBlocks; i++ {
		blk = bookkeeping.MakeBlock(blk.BlockHeader)
		mLedger.blocks = append(mLedger.blocks, blk)
	}

	return mLedger, mEmptyLedger
}

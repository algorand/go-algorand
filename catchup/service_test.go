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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/datatest"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/db"
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
	ledger      *data.Ledger
	timeout     bool
	errorRound  int
	fail        uint32
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

	if (m.errorRound >= 0 && basics.Round(m.errorRound) == round) || atomic.LoadUint32(&m.fail) == 1 {
		// change reply so that block is malformed
		block.BlockHeader.Seed[0]++
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

func TestServiceFetchBlocksSameRange(t *testing.T) {
	// Make Ledger
	remote, local, release, _ := testingenv(t, 10, 10)
	defer release()

	require.NotNil(t, remote)
	require.NotNil(t, local)

	net := &mocks.MockNetwork{}

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, net, local, nil, nil)
	syncer.fetcherFactory = makeMockFactory(&MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 0, tries: make(map[basics.Round]int)})

	syncer.sync()
	require.Equal(t, remote.LastRound(), local.LastRound())
}

func TestPeriodicSync(t *testing.T) {
	// Make Ledger
	remote, local, release, _ := testingenv(t, 10, 10)
	defer release()

	initialLocalRound := local.LastRound()

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, nil)
	s.deadlineTimeout = 2 * time.Second

	factory := MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 1, tries: make(map[basics.Round]int)}}
	s.fetcherFactory = &factory
	require.True(t, initialLocalRound < remote.LastRound())

	s.Start()
	defer s.Stop()
	time.Sleep(s.deadlineTimeout*2 - 200*time.Millisecond)
	require.Equal(t, local.LastRound(), initialLocalRound)
	s.fetcherFactory.(*MockedFetcherFactory).changeFetcher(&MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 0, tries: make(map[basics.Round]int)})
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
	remote, local, release, _ := testingenv(t, 10, numBlocks)
	defer release()
	lastRoundAtStart := local.LastRound()

	net := &mocks.MockNetwork{}

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, net, local, nil, nil)
	factory := MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 0, tries: make(map[basics.Round]int)}}
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
	remote, local, release, _ := testingenv(t, 10, numberOfBlocks)
	defer release()

	lastRound := local.LastRound()

	// Make Service
	s := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, nil)
	factory := MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 0, tries: make(map[basics.Round]int)}}
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
	remote, local, release, _ := testingenv(t, 10, int(numberOfBlocks))
	defer release()
	lastRoundAtStart := local.LastRound()

	// Make Service
	syncer := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, nil)
	syncer.fetcherFactory = &MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 0, tries: make(map[basics.Round]int)}}

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
	remote, local, release, _ := testingenv(t, 10, 10)
	defer release()

	lastRoundAtStart := local.LastRound()
	// Make Service
	s := MakeService(logging.Base(), defaultConfig, &mocks.MockNetwork{}, local, nil, nil)
	s.fetcherFactory = &MockedFetcherFactory{fetcher: &MockedFetcher{ledger: remote, timeout: false, errorRound: int(lastRoundAtStart + 1), fail: 0, tries: make(map[basics.Round]int)}}

	s.sync()
	require.Equal(t, lastRoundAtStart, local.LastRound())
	require.True(t, s.fetcherFactory.(*MockedFetcherFactory).fetcher.client.closed)
}

const defaultRewardUnit = 1e6

// one service
func testingenv(t testing.TB, numAccounts, numBlocks int) (ledger, emptyLedger *data.Ledger, release func(), genesisBalances data.GenesisBalances) {
	P := numAccounts                                  // n accounts
	maxMoneyAtStart := uint64(10 * defaultRewardUnit) // max money start
	minMoneyAtStart := uint64(defaultRewardUnit)      // min money start

	accesssors := make([]db.Accessor, 0)
	release = func() {
		ledger.Close()
		emptyLedger.Close()
		for _, acc := range accesssors {
			acc.Close()
		}
	}
	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	parts := make([]account.Participation, P)
	for i := 0; i < P; i++ {
		access, err := db.MakeAccessor(t.Name()+"_root_testingenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accesssors = append(accesssors, access)
		root, err := account.GenerateRoot(access)
		if err != nil {
			panic(err)
		}

		access, err = db.MakeAccessor(t.Name()+"_part_testingenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accesssors = append(accesssors, access)
		part, err := account.FillDBWithParticipationKeys(access, root.Address(), 0, basics.Round(numBlocks),
			config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		if err != nil {
			panic(err)
		}

		startamt := basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Uint64() % (maxMoneyAtStart - minMoneyAtStart)))},
			SelectionID: part.VRFSecrets().PK,
			VoteID:      part.VotingSecrets().OneTimeSignatureVerifier,
		}
		short := root.Address()

		parts[i] = part
		genesis[short] = startamt
	}

	genesis[basics.Address(sinkAddr)] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: uint64(1e3 * minMoneyAtStart)},
	}
	genesis[basics.Address(poolAddr)] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: uint64(1e3 * minMoneyAtStart)},
	}

	var err error
	genesisBalances = data.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	emptyLedger, err = data.LoadLedger(logging.Base(), t.Name()+"empty", true, protocol.ConsensusCurrentVersion, genesisBalances, "", crypto.Digest{}, nil)
	require.NoError(t, err)

	ledger, err = datatest.FabricateLedger(logging.Base(), t.Name(), parts, genesisBalances, emptyLedger.LastRound()+basics.Round(numBlocks))
	require.NoError(t, err)
	require.Equal(t, ledger.LastRound(), emptyLedger.LastRound()+basics.Round(numBlocks))
	return ledger, emptyLedger, release, genesisBalances
}

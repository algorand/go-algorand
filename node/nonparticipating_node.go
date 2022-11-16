// Copyright (C) 2019-2022 Algorand, Inc.
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

package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	// v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/messagetracer"
	"github.com/algorand/go-algorand/node/indexer"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/execpool"
)

// AlgorandNonParticipatingNode specifies and implements an Algorand node w/o participation.
type AlgorandNonParticipatingNode struct {
	mu        deadlock.Mutex
	ctx       context.Context
	cancelCtx context.CancelFunc
	config    config.Local

	ledger *data.Ledger
	net    network.GossipNode

	accountManager *data.AccountManager

	catchupService           *catchup.Service
	catchpointCatchupService *catchup.CatchpointCatchupService
	blockService             *rpcs.BlockService
	ledgerService            *rpcs.LedgerService

	// Can I remove this?
	indexer *indexer.Indexer

	rootDir     string
	genesisID   string
	genesisHash crypto.Digest
	devMode     bool // is this node operates in a developer mode ? ( benign agreement, broadcasting transaction generates a new block )

	log logging.Logger

	// syncStatusMu used for locking lastRoundTimestamp and hasSyncedSinceStartup
	syncStatusMu          deadlock.Mutex
	lastRoundTimestamp    time.Time
	hasSyncedSinceStartup bool

	cryptoPool                         execpool.ExecutionPool
	lowPriorityCryptoVerificationPool  execpool.BacklogPool
	highPriorityCryptoVerificationPool execpool.BacklogPool
	catchupBlockAuth                   blockAuthenticatorImpl

	tracer messagetracer.MessageTracer
}

// MakeNonParticipating sets up an Algorand partial node
// (i.e., it returns a node that does not participate in consensus)
func MakeNonParticipating(log logging.Logger, rootDir string, cfg config.Local, phonebookAddresses []string, genesis bookkeeping.Genesis) (*AlgorandNonParticipatingNode, error) {
	node := new(AlgorandNonParticipatingNode)
	node.rootDir = rootDir
	node.log = log.With("name", cfg.NetAddress)
	node.genesisID = genesis.ID()
	node.genesisHash = genesis.Hash()
	node.devMode = genesis.DevMode

	if node.devMode {
		cfg.DisableNetworking = true
	}
	node.config = cfg

	// tie network, block fetcher, and agreement services together
	p2pNode, err := network.NewWebsocketNetwork(node.log, node.config, phonebookAddresses, genesis.ID(), genesis.Network, node)
	if err != nil {
		log.Errorf("could not create websocket node: %v", err)
		return nil, err
	}

	// @EricW it seems like not initializing a prio scheme will not prevent us from using the p2p network in way required for partial nodes
	// p2pNode.SetPrioScheme(node)
	node.net = p2pNode

	accountListener := makeTopAccountListener(log)

	// load stored data
	genesisDir := filepath.Join(rootDir, genesis.ID())
	ledgerPathnamePrefix := filepath.Join(genesisDir, config.LedgerFilenamePrefix)

	// create initial ledger, if it doesn't exist
	err = os.Mkdir(genesisDir, 0700)
	if err != nil && !os.IsExist(err) {
		log.Errorf("Unable to create genesis directory: %v", err)
		return nil, err
	}
	genalloc, err := genesis.Balances()
	if err != nil {
		log.Errorf("Cannot load genesis allocation: %v", err)
		return nil, err
	}

	node.cryptoPool = execpool.MakePool(node)
	node.lowPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.LowPriority, node)
	node.highPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.HighPriority, node)
	node.ledger, err = data.LoadLedger(node.log, ledgerPathnamePrefix, false, genesis.Proto, genalloc, node.genesisID, node.genesisHash, []ledger.BlockListener{}, cfg)
	if err != nil {
		log.Errorf("Cannot initialize ledger (%s): %v", ledgerPathnamePrefix, err)
		return nil, err
	}

	blockListeners := []ledger.BlockListener{node}
	if node.config.EnableTopAccountsReporting {
		blockListeners = append(blockListeners, &accountListener)
	}
	node.ledger.RegisterBlockListeners(blockListeners)

	// Indexer setup
	if cfg.IsIndexerActive && cfg.Archival {
		node.indexer, err = indexer.MakeIndexer(genesisDir, node.ledger, false)
		if err != nil {
			logging.Base().Errorf("failed to make indexer -  %v", err)
			return nil, err
		}
	}

	node.blockService = rpcs.MakeBlockService(node.log, cfg, node.ledger, p2pNode, node.genesisID)
	node.ledgerService = rpcs.MakeLedgerService(cfg, node.ledger, p2pNode, node.genesisID)

	node.catchupBlockAuth = blockAuthenticatorImpl{Ledger: node.ledger, AsyncVoteVerifier: agreement.MakeAsyncVoteVerifier(node.lowPriorityCryptoVerificationPool)}

	// The catchup service receives on the PendingUnmatchedCertificate chan in order to catchup using the agreement service.
	// Since we aren't participating in consensus, and are not running the agreement service, an empty chan will always default
	// to catchup via network sync after the configured timeout.
	node.catchupService = catchup.MakeService(node.log, node.config, p2pNode, node.ledger, node.catchupBlockAuth, make(chan catchup.PendingUnmatchedCertificate), node.lowPriorityCryptoVerificationPool)

	registry, err := ensureParticipationDB(genesisDir, node.log)
	if err != nil {
		log.Errorf("unable to initialize the participation registry database: %v", err)
		return nil, err
	}
	node.accountManager = data.MakeAccountManager(log, registry)

	catchpointCatchupState, err := node.ledger.GetCatchpointCatchupState(context.Background())
	if err != nil {
		log.Errorf("unable to determine catchpoint catchup state: %v", err)
		return nil, err
	}
	if catchpointCatchupState != ledger.CatchpointCatchupStateInactive {
		accessor := ledger.MakeCatchpointCatchupAccessor(node.ledger.Ledger, node.log)
		node.catchpointCatchupService, err = catchup.MakeResumedCatchpointCatchupService(context.Background(), node, node.log, node.net, accessor, node.config)
		if err != nil {
			log.Errorf("unable to create catchpoint catchup service: %v", err)
			return nil, err
		}
		node.log.Infof("resuming catchpoint catchup from state %d", catchpointCatchupState)
	}

	node.tracer = messagetracer.NewTracer(log).Init(cfg)

	return node, err
}

// OnNewBlock implements the BlockListener interface so we're notified after each block is written to the ledger
func (node *AlgorandNonParticipatingNode) OnNewBlock(block bookkeeping.Block, _ ledgercore.StateDelta) {
	if node.ledger.Latest() > block.Round() {
		return
	}
	node.syncStatusMu.Lock()
	node.lastRoundTimestamp = time.Now()
	node.hasSyncedSinceStartup = true
	node.syncStatusMu.Unlock()
}

// IsParticipating will always return false for Partial nodes since they never participate in consensus
func (node *AlgorandNonParticipatingNode) IsParticipating() bool {
	return false
}

// Start the node.
func (node *AlgorandNonParticipatingNode) Start() {
	node.mu.Lock()
	defer node.mu.Unlock()

	// Set up a context we can use to cancel goroutines on Stop()
	node.ctx, node.cancelCtx = context.WithCancel(context.Background())

	// The start network is being called only after the various services start up.
	// We want to do so in order to let the services register their callbacks with the
	// network package before any connections are being made.
	startNetwork := func() {
		if !node.config.DisableNetworking {
			// start accepting connections
			node.net.Start()
			node.config.NetAddress, _ = node.net.Address()
		}
	}

	if node.catchpointCatchupService != nil {
		startNetwork()
		node.catchpointCatchupService.Start(node.ctx)
	} else {
		node.catchupService.Start()
		node.blockService.Start()
		node.ledgerService.Start()
		startNetwork()
	}

}

// Stop stops running the node. Once a node is closed, it can never start again.
func (node *AlgorandNonParticipatingNode) Stop() {
	node.mu.Lock()
	node.net.ClearHandlers()
	if !node.config.DisableNetworking {
		node.net.Stop()
	}
	if node.catchpointCatchupService != nil {
		node.catchpointCatchupService.Stop()
	} else {
		node.catchupService.Stop()
		node.blockService.Stop()
		node.ledgerService.Stop()
	}
	node.catchupBlockAuth.Quit()
	node.highPriorityCryptoVerificationPool.Shutdown()
	node.lowPriorityCryptoVerificationPool.Shutdown()
	node.cryptoPool.Shutdown()
	node.cancelCtx()
	if node.indexer != nil {
		node.indexer.Shutdown()
	}
}

// StartCatchup starts the catchpoint mode and attempt to get to the provided catchpoint
// this function is intended to be called externally via the REST api interface.
func (node *AlgorandNonParticipatingNode) StartCatchup(catchpoint string) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.indexer != nil {
		return fmt.Errorf("catching up using a catchpoint is not supported on indexer-enabled nodes")
	}
	if node.catchpointCatchupService != nil {
		stats := node.catchpointCatchupService.GetStatistics()
		// No need to return an error
		if catchpoint == stats.CatchpointLabel {
			return MakeCatchpointAlreadyInProgressError(catchpoint)
		}
		return MakeCatchpointUnableToStartError(stats.CatchpointLabel, catchpoint)
	}
	var err error
	accessor := ledger.MakeCatchpointCatchupAccessor(node.ledger.Ledger, node.log)
	node.catchpointCatchupService, err = catchup.MakeNewCatchpointCatchupService(catchpoint, node, node.log, node.net, accessor, node.config)
	if err != nil {
		node.log.Warnf("unable to create catchpoint catchup service : %v", err)
		return err
	}
	node.catchpointCatchupService.Start(node.ctx)
	node.log.Infof("starting catching up toward catchpoint %s", catchpoint)
	return nil
}

// AbortCatchup aborts the given catchpoint
// this function is intended to be called externally via the REST api interface.
func (node *AlgorandNonParticipatingNode) AbortCatchup(catchpoint string) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.catchpointCatchupService == nil {
		return nil
	}
	stats := node.catchpointCatchupService.GetStatistics()
	if stats.CatchpointLabel != catchpoint {
		return fmt.Errorf("unable to abort catchpoint catchup for '%s' - already catching up '%s'", catchpoint, stats.CatchpointLabel)
	}
	node.catchpointCatchupService.Abort()
	return nil
}

// SetCatchpointCatchupMode change the node's operational mode from catchpoint catchup mode and back, it returns a
// channel which contains the updated node context. This function need to work asynchronously so that the caller could
// detect and handle the use case where the node is being shut down while we're switching to/from catchup mode without
// deadlocking on the shared node mutex.
func (node *AlgorandNonParticipatingNode) SetCatchpointCatchupMode(catchpointCatchupMode bool) (outCtxCh <-chan context.Context) {
	// create a non-buffered channel to return the newly created context. The fact that it's non-buffered here
	// is important, as it allows us to synchronize the "receiving" of the new context before canceling of the previous
	// one.
	ctxCh := make(chan context.Context)
	outCtxCh = ctxCh
	go func() {
		node.mu.Lock()
		// check that the node wasn't canceled. If it have been canceled, it means that the node.Stop() was called, in which case
		// we should close the channel.
		if node.ctx.Err() == context.Canceled {
			close(ctxCh)
			node.mu.Unlock()
			return
		}
		if catchpointCatchupMode {
			// stop..
			node.net.ClearHandlers()
			node.catchupService.Stop()
			node.blockService.Stop()
			node.ledgerService.Stop()

			prevNodeCancelFunc := node.cancelCtx

			// Set up a context we can use to cancel goroutines on Stop()
			node.ctx, node.cancelCtx = context.WithCancel(context.Background())
			ctxCh <- node.ctx

			prevNodeCancelFunc()
			return
		}
		defer node.mu.Unlock()
		// start
		node.catchupService.Start()
		node.blockService.Start()
		node.ledgerService.Start()

		// Set up a context we can use to cancel goroutines on Stop()
		node.ctx, node.cancelCtx = context.WithCancel(context.Background())

		// at this point, the catchpoint catchup is done ( either successfully or not.. )
		node.catchpointCatchupService = nil

		ctxCh <- node.ctx
	}()
	return

}

// GenesisID returns the ID of the genesis node.
func (node *AlgorandNonParticipatingNode) GenesisID() string {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.genesisID
}

// GenesisHash returns the hash of the genesis configuration.
func (node *AlgorandNonParticipatingNode) GenesisHash() crypto.Digest {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.genesisHash
}

// Indexer returns a pointer to nodes indexer
func (node *AlgorandNonParticipatingNode) Indexer() (*indexer.Indexer, error) {
	if node.indexer != nil && node.config.IsIndexerActive {
		return node.indexer, nil
	}
	return nil, fmt.Errorf("indexer is not active")
}

// GetTransactionByID gets transaction by ID
// this function is intended to be called externally via the REST api interface.
func (node *AlgorandNonParticipatingNode) GetTransactionByID(txid transactions.Txid, rnd basics.Round) (TxnWithStatus, error) {
	stx, _, err := node.ledger.LookupTxid(txid, rnd)
	if err != nil {
		return TxnWithStatus{}, err
	}
	return TxnWithStatus{
		Txn:            stx.SignedTxn,
		ConfirmedRound: rnd,
		ApplyData:      stx.ApplyData,
	}, nil
}

// ListTxns returns SignedTxns associated with a specific account in a range of Rounds (inclusive).
// TxnWithStatus returns the round in which a particular transaction appeared,
// since that information is not part of the SignedTxn itself.
func (node *AlgorandNonParticipatingNode) ListTxns(addr basics.Address, minRound basics.Round, maxRound basics.Round) ([]TxnWithStatus, error) {
	result := make([]TxnWithStatus, 0)
	for r := minRound; r <= maxRound; r++ {
		h, err := node.ledger.AddressTxns(addr, r)
		if err != nil {
			return nil, err
		}
		for _, tx := range h {
			result = append(result, TxnWithStatus{
				Txn:            tx.SignedTxn,
				ConfirmedRound: r,
				ApplyData:      tx.ApplyData,
			})
		}
	}
	return result, nil
}

// GetTransaction looks for the required txID within with a specific account within a range of rounds (inclusive) and
// returns the SignedTxn and true iff it finds the transaction.
func (node *AlgorandNonParticipatingNode) GetTransaction(addr basics.Address, txID transactions.Txid, minRound basics.Round, maxRound basics.Round) (TxnWithStatus, bool) {
	// start with the most recent round, and work backwards:
	// this will abort early if it hits pruned rounds
	if maxRound < minRound {
		return TxnWithStatus{}, false
	}
	r := maxRound
	for {
		h, err := node.ledger.AddressTxns(addr, r)
		if err != nil {
			return TxnWithStatus{}, false
		}
		for _, tx := range h {
			if tx.ID() == txID {
				return TxnWithStatus{
					Txn:            tx.SignedTxn,
					ConfirmedRound: r,
					ApplyData:      tx.ApplyData,
				}, true
			}
		}
		if r == minRound {
			break
		}
		r--
	}
	return TxnWithStatus{}, false
}

// IsArchival returns true the node is an archival node, false otherwise
func (node *AlgorandNonParticipatingNode) IsArchival() bool {
	return node.config.Archival
}

// Status returns a StatusReport structure reporting our status as Active and with our ledger's LastRound
func (node *AlgorandNonParticipatingNode) Status() (s StatusReport, err error) {
	node.syncStatusMu.Lock()
	s.LastRoundTimestamp = node.lastRoundTimestamp
	s.HasSyncedSinceStartup = node.hasSyncedSinceStartup
	node.syncStatusMu.Unlock()

	node.mu.Lock()
	defer node.mu.Unlock()
	if node.catchpointCatchupService != nil {
		// we're in catchpoint catchup mode.
		lastBlockHeader := node.catchpointCatchupService.GetLatestBlockHeader()
		s.LastRound = lastBlockHeader.Round
		s.LastVersion = lastBlockHeader.CurrentProtocol
		s.NextVersion, s.NextVersionRound, s.NextVersionSupported = lastBlockHeader.NextVersionInfo()
		s.StoppedAtUnsupportedRound = s.LastRound+1 == s.NextVersionRound && !s.NextVersionSupported

		// for now, I'm leaving this commented out. Once we refactor some of the ledger locking mechanisms, we
		// should be able to make this call work.
		//s.LastCatchpoint = node.ledger.GetLastCatchpointLabel()

		// report back the catchpoint catchup progress statistics
		stats := node.catchpointCatchupService.GetStatistics()
		s.Catchpoint = stats.CatchpointLabel
		s.CatchpointCatchupTotalAccounts = stats.TotalAccounts
		s.CatchpointCatchupProcessedAccounts = stats.ProcessedAccounts
		s.CatchpointCatchupVerifiedAccounts = stats.VerifiedAccounts
		s.CatchpointCatchupTotalBlocks = stats.TotalBlocks
		s.CatchpointCatchupAcquiredBlocks = stats.AcquiredBlocks
		s.CatchupTime = time.Since(stats.StartTime)
	} else {
		// we're not in catchpoint catchup mode
		var b bookkeeping.BlockHeader
		s.LastRound = node.ledger.Latest()
		b, err = node.ledger.BlockHdr(s.LastRound)
		if err != nil {
			return
		}
		s.LastVersion = b.CurrentProtocol
		s.NextVersion, s.NextVersionRound, s.NextVersionSupported = b.NextVersionInfo()

		s.StoppedAtUnsupportedRound = s.LastRound+1 == s.NextVersionRound && !s.NextVersionSupported
		s.LastCatchpoint = node.ledger.GetLastCatchpointLabel()
		s.SynchronizingTime = node.catchupService.SynchronizingTime()
		s.CatchupTime = node.catchupService.SynchronizingTime()
	}

	return
}

// ListeningAddress retrieves the node's current listening address, if any.
// Returns true if currently listening, false otherwise.
func (node *AlgorandNonParticipatingNode) ListeningAddress() (string, bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.net.Address()
}

// LedgerForAPI exposes the node's ledger handle to the algod API code
func (node *AlgorandNonParticipatingNode) LedgerForAPI() ledger.LedgerForAPI {
	return node.ledger
}

// Config returns a copy of the node's Local configuration
func (node *AlgorandNonParticipatingNode) Config() config.Local {
	return node.config
}

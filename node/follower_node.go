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

// Package node is the Algorand node itself, with functions exposed to the frontend
package node

import (
	"context"
	"fmt"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/execpool"
)

// AlgorandFollowerNode implements follower mode/ledger delta APIs and disables participation-related methods
type AlgorandFollowerNode struct {
	mu        deadlock.Mutex
	ctx       context.Context
	cancelCtx context.CancelFunc
	config    config.Local

	ledger *data.Ledger
	net    network.GossipNode

	catchupService           *catchup.Service
	catchpointCatchupService *catchup.CatchpointCatchupService
	blockService             *rpcs.BlockService

	genesisDirs config.ResolvedGenesisDirs
	genesisID   string
	genesisHash crypto.Digest
	devMode     bool // is this node operates in a developer mode ? ( benign agreement, broadcasting transaction generates a new block )

	log logging.Logger

	// syncStatusMu used for locking lastRoundTimestamp and hasSyncedSinceStartup
	// syncStatusMu added so OnNewBlock wouldn't be blocked by oldKeyDeletionThread during catchup
	syncStatusMu          deadlock.Mutex
	lastRoundTimestamp    time.Time
	hasSyncedSinceStartup bool

	cryptoPool                        execpool.ExecutionPool
	lowPriorityCryptoVerificationPool execpool.BacklogPool
	catchupBlockAuth                  blockAuthenticatorImpl
}

// MakeFollower sets up an Algorand data node
func MakeFollower(log logging.Logger, rootDir string, cfg config.Local, phonebookAddresses []string, genesis bookkeeping.Genesis) (*AlgorandFollowerNode, error) {
	node := new(AlgorandFollowerNode)
	node.log = log.With("name", cfg.NetAddress)
	node.genesisID = genesis.ID()
	node.genesisHash = genesis.Hash()
	node.devMode = genesis.DevMode
	var err error
	node.genesisDirs, err = cfg.EnsureAndResolveGenesisDirs(rootDir, genesis.ID(), log)
	if err != nil {
		return nil, err
	}

	if node.devMode {
		log.Warn("Follower running on a devMode network. Must submit txns to a different node.")
	}
	node.config = cfg

	var genesisInfo = network.GenesisInfo{
		GenesisID: genesis.ID(),
		NetworkID: genesis.Network,
	}
	// tie network, block fetcher, and agreement services together
	p2pNode, err := network.NewWebsocketNetwork(node.log, node.config, phonebookAddresses, genesisInfo, nil, nil, nil)
	if err != nil {
		log.Errorf("could not create websocket node: %v", err)
		return nil, err
	}
	p2pNode.DeregisterMessageInterest(protocol.AgreementVoteTag)
	p2pNode.DeregisterMessageInterest(protocol.ProposalPayloadTag)
	p2pNode.DeregisterMessageInterest(protocol.VoteBundleTag)
	node.net = p2pNode

	genalloc, err := genesis.Balances()
	if err != nil {
		log.Errorf("Cannot load genesis allocation: %v", err)
		return nil, err
	}

	node.cryptoPool = execpool.MakePool(node)
	node.lowPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.LowPriority, node)
	ledgerPaths := ledger.DirsAndPrefix{
		DBFilePrefix:        config.LedgerFilenamePrefix,
		ResolvedGenesisDirs: node.genesisDirs,
	}
	node.ledger, err = data.LoadLedger(node.log, ledgerPaths, false, genesis.Proto, genalloc, node.genesisID, node.genesisHash, cfg)
	if err != nil {
		log.Errorf("Cannot initialize ledger (%v): %v", ledgerPaths, err)
		return nil, err
	}

	node.ledger.RegisterBlockListeners([]ledgercore.BlockListener{node})

	if cfg.IsGossipServer() {
		rpcs.MakeHealthService(node.net)
	}

	node.blockService = rpcs.MakeBlockService(node.log, cfg, node.ledger, p2pNode, node.genesisID)
	node.catchupBlockAuth = blockAuthenticatorImpl{Ledger: node.ledger, AsyncVoteVerifier: agreement.MakeAsyncVoteVerifier(node.lowPriorityCryptoVerificationPool)}
	node.catchupService = catchup.MakeService(node.log, node.config, p2pNode, node.ledger, node.catchupBlockAuth, make(chan catchup.PendingUnmatchedCertificate), node.lowPriorityCryptoVerificationPool)

	// Initialize sync round to the latest db round + 1 so that nothing falls out of the cache on Start
	err = node.SetSyncRound(node.Ledger().LatestTrackerCommitted() + 1)
	if err != nil {
		log.Errorf("unable to set sync round to Ledger.DBRound %v", err)
		return nil, err
	}

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

	return node, err
}

// Config returns a copy of the node's Local configuration
func (node *AlgorandFollowerNode) Config() config.Local {
	return node.config
}

// Start the node: connect to peers while obtaining a lock. Doesn't wait for initial sync.
func (node *AlgorandFollowerNode) Start() error {
	node.mu.Lock()
	defer node.mu.Unlock()

	// Set up a context we can use to cancel goroutines on Stop()
	node.ctx, node.cancelCtx = context.WithCancel(context.Background())

	// The start network is being called only after the various services start up.
	// We want to do so in order to let the services register their callbacks with the
	// network package before any connections are being made.
	startNetwork := func() error {
		if !node.config.DisableNetworking {
			// start accepting connections
			err := node.net.Start()
			if err != nil {
				return err
			}
			node.config.NetAddress, _ = node.net.Address()
		}
		return nil
	}

	var err error
	if node.catchpointCatchupService != nil {
		err = startNetwork()
		if err == nil {
			err = node.catchpointCatchupService.Start(node.ctx)
		}
	} else {
		node.catchupService.Start()
		node.blockService.Start()
		err = startNetwork()
	}
	return err
}

// ListeningAddress retrieves the node's current listening address, if any.
// Returns true if currently listening, false otherwise.
func (node *AlgorandFollowerNode) ListeningAddress() (string, bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.net.Address()
}

// Stop stops running the node. Once a node is closed, it can never start again.
func (node *AlgorandFollowerNode) Stop() {
	node.mu.Lock()
	defer node.mu.Unlock()

	node.net.ClearHandlers()
	if !node.config.DisableNetworking {
		node.net.Stop()
	}
	if node.catchpointCatchupService != nil {
		node.catchpointCatchupService.Stop()
	} else {
		node.catchupService.Stop()
		node.blockService.Stop()
	}
	node.catchupBlockAuth.Quit()
	node.lowPriorityCryptoVerificationPool.Shutdown()
	node.cryptoPool.Shutdown()
	node.cancelCtx()
}

// Ledger exposes the node's ledger handle to the algod API code
func (node *AlgorandFollowerNode) Ledger() *data.Ledger {
	return node.ledger
}

// BroadcastSignedTxGroup errors in follower mode
func (node *AlgorandFollowerNode) BroadcastSignedTxGroup(_ []transactions.SignedTxn) (err error) {
	return fmt.Errorf("cannot broadcast txns in follower mode")
}

// AsyncBroadcastSignedTxGroup errors in follower mode
func (node *AlgorandFollowerNode) AsyncBroadcastSignedTxGroup(_ []transactions.SignedTxn) (err error) {
	return fmt.Errorf("cannot broadcast txns in follower mode")
}

// BroadcastInternalSignedTxGroup errors in follower mode
func (node *AlgorandFollowerNode) BroadcastInternalSignedTxGroup(_ []transactions.SignedTxn) (err error) {
	return fmt.Errorf("cannot broadcast internal signed txn group in follower mode")
}

// Simulate speculatively runs a transaction group against the current
// blockchain state and returns the effects and/or errors that would result.
func (node *AlgorandFollowerNode) Simulate(request simulation.Request) (result simulation.Result, err error) {
	simulator := simulation.MakeSimulator(node.ledger, node.config.EnableDeveloperAPI)
	return simulator.Simulate(request)
}

// GetPendingTransaction no-ops in follower mode
func (node *AlgorandFollowerNode) GetPendingTransaction(_ transactions.Txid) (res TxnWithStatus, found bool) {
	return
}

// GetPeers returns the node's peers
func (node *AlgorandFollowerNode) GetPeers() (inboundPeers []network.Peer, outboundPeers []network.Peer, err error) {
	return node.net.GetPeers(network.PeersConnectedIn), node.net.GetPeers(network.PeersConnectedOut), nil
}

// Status returns a StatusReport structure reporting our status as Active and with our ledger's LastRound
func (node *AlgorandFollowerNode) Status() (StatusReport, error) {
	node.syncStatusMu.Lock()
	lastRoundTimestamp := node.lastRoundTimestamp
	hasSyncedSinceStartup := node.hasSyncedSinceStartup
	node.syncStatusMu.Unlock()

	node.mu.Lock()
	defer node.mu.Unlock()
	var s StatusReport
	var err error
	if node.catchpointCatchupService != nil {
		s = catchpointCatchupStatus(node.catchpointCatchupService.GetLatestBlockHeader(), node.catchpointCatchupService.GetStatistics())
	} else {
		s, err = latestBlockStatus(node.ledger, node.catchupService)
	}

	s.LastRoundTimestamp = lastRoundTimestamp
	s.HasSyncedSinceStartup = hasSyncedSinceStartup

	return s, err
}

// GenesisID returns the ID of the genesis node.
func (node *AlgorandFollowerNode) GenesisID() string {
	return node.genesisID
}

// GenesisHash returns the hash of the genesis configuration.
func (node *AlgorandFollowerNode) GenesisHash() crypto.Digest {
	return node.genesisHash
}

// SuggestedFee no-ops in follower mode
func (node *AlgorandFollowerNode) SuggestedFee() basics.MicroAlgos {
	return basics.MicroAlgos{}
}

// GetPendingTxnsFromPool returns an empty array in follower mode.
func (node *AlgorandFollowerNode) GetPendingTxnsFromPool() ([]transactions.SignedTxn, error) {
	return []transactions.SignedTxn{}, nil
}

// ListParticipationKeys returns an empty list in follower mode
func (node *AlgorandFollowerNode) ListParticipationKeys() (partKeys []account.ParticipationRecord, err error) {
	return []account.ParticipationRecord{}, nil
}

// GetParticipationKey returns an error in follower mode
func (node *AlgorandFollowerNode) GetParticipationKey(_ account.ParticipationID) (account.ParticipationRecord, error) {
	return account.ParticipationRecord{}, fmt.Errorf("cannot get participation key in follower mode")
}

// RemoveParticipationKey returns an error in follower mode
func (node *AlgorandFollowerNode) RemoveParticipationKey(_ account.ParticipationID) error {
	return fmt.Errorf("cannot remove participation key in follower mode")
}

// AppendParticipationKeys returns an error in follower mode
func (node *AlgorandFollowerNode) AppendParticipationKeys(_ account.ParticipationID, _ account.StateProofKeys) error {
	return fmt.Errorf("cannot append participation keys in follower mode")
}

// InstallParticipationKey returns an error in follower mode
func (node *AlgorandFollowerNode) InstallParticipationKey(_ []byte) (account.ParticipationID, error) {
	return account.ParticipationID{}, fmt.Errorf("cannot install participation key in follower mode")
}

// OnNewBlock implements the BlockListener interface so we're notified after each block is written to the ledger
func (node *AlgorandFollowerNode) OnNewBlock(block bookkeeping.Block, _ ledgercore.StateDelta) {
	if node.ledger.Latest() > block.Round() {
		return
	}
	node.syncStatusMu.Lock()
	node.lastRoundTimestamp = time.Now()
	node.hasSyncedSinceStartup = true
	node.syncStatusMu.Unlock()
}

// StartCatchup starts the catchpoint mode and attempt to get to the provided catchpoint
// this function is intended to be called externally via the REST api interface.
func (node *AlgorandFollowerNode) StartCatchup(catchpoint string) error {
	node.mu.Lock()
	defer node.mu.Unlock()
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
	err = node.catchpointCatchupService.Start(node.ctx)
	if err != nil {
		node.log.Warn(err.Error())
		return MakeStartCatchpointError(catchpoint, err)
	}
	node.log.Infof("starting catching up toward catchpoint %s", catchpoint)
	return nil
}

// AbortCatchup aborts the given catchpoint
// this function is intended to be called externally via the REST api interface.
func (node *AlgorandFollowerNode) AbortCatchup(catchpoint string) error {
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
func (node *AlgorandFollowerNode) SetCatchpointCatchupMode(catchpointCatchupMode bool) (outCtxCh <-chan context.Context) {
	// create a non-buffered channel to return the newly created context. The fact that it's non-buffered here
	// is important, as it allows us to synchronize the "receiving" of the new context before canceling of the previous
	// one.
	ctxCh := make(chan context.Context)
	outCtxCh = ctxCh
	go func() {
		node.mu.Lock()
		// check that the node wasn't canceled. If it has been canceled, it means that the node.Stop() was called, in which case
		// we should close the channel.
		if node.ctx.Err() == context.Canceled {
			close(ctxCh)
			node.mu.Unlock()
			return
		}
		if catchpointCatchupMode {
			// stop..
			defer func() {
				node.mu.Unlock()
			}()
			node.net.ClearHandlers()
			node.catchupService.Stop()
			node.blockService.Stop()

			prevNodeCancelFunc := node.cancelCtx

			// Set up a context we can use to cancel goroutines on Stop()
			node.ctx, node.cancelCtx = context.WithCancel(context.Background())
			ctxCh <- node.ctx

			prevNodeCancelFunc()
			return
		}

		// Catchup finished, resume.
		defer node.mu.Unlock()

		// update sync round before starting services
		if err := node.SetSyncRound(node.ledger.LastRound()); err != nil {
			node.log.Warnf("unable to set sync round while resuming fast catchup: %v", err)
		}

		// start
		node.catchupService.Start()
		node.blockService.Start()

		// Set up a context we can use to cancel goroutines on Stop()
		node.ctx, node.cancelCtx = context.WithCancel(context.Background())

		// at this point, the catchpoint catchup is done ( either successfully or not.. )
		node.catchpointCatchupService = nil

		ctxCh <- node.ctx
	}()
	return
}

// SetSyncRound sets the minimum sync round on the catchup service
func (node *AlgorandFollowerNode) SetSyncRound(rnd basics.Round) error {
	// Calculate the first round for which we want to disable catchup from the network.
	// This is based on the size of the cache used in the ledger.
	disableSyncRound := rnd + basics.Round(node.Config().MaxAcctLookback)
	return node.catchupService.SetDisableSyncRound(disableSyncRound)
}

// GetSyncRound retrieves the sync round, removes cache offset used during SetSyncRound
func (node *AlgorandFollowerNode) GetSyncRound() basics.Round {
	return basics.SubSaturate(node.catchupService.GetDisableSyncRound(), basics.Round(node.Config().MaxAcctLookback))
}

// UnsetSyncRound removes the sync round constraint on the catchup service
func (node *AlgorandFollowerNode) UnsetSyncRound() {
	node.catchupService.UnsetDisableSyncRound()
}

// SetBlockTimeStampOffset sets a timestamp offset in the block header.
// This is only available in dev mode.
func (node *AlgorandFollowerNode) SetBlockTimeStampOffset(offset int64) error {
	return fmt.Errorf("cannot set block timestamp offset in follower mode")
}

// GetBlockTimeStampOffset gets a timestamp offset.
// This is only available in dev mode.
func (node *AlgorandFollowerNode) GetBlockTimeStampOffset() (*int64, error) {
	return nil, fmt.Errorf("cannot get block timestamp offset in follower mode")
}

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
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	// v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/messagetracer"
	"github.com/algorand/go-algorand/node/indexer"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/execpool"
)

// AlgorandDataNode specifies and implements an Algorand node w/ data-specific APIs.
type AlgorandDataNode struct {
	AlgorandNonParticipatingNode
}

// MakeData sets up an Algorand data node
func MakeData(log logging.Logger, rootDir string, cfg config.Local, phonebookAddresses []string, genesis bookkeeping.Genesis) (*AlgorandDataNode, error) {
	node := new(AlgorandDataNode)
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

	// Set sync round in the catchup service to ledger.NextRound() so data falls out of the cache(s) until we let it
	err = node.catchupService.SetSyncRound(uint64(node.ledger.NextRound()))
	if err != nil {
		log.Errorf("Unable to set sync round on catchup service %v", err)
		return nil, err
	}

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

// Start the node.
func (node *AlgorandDataNode) Start() {
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
func (node *AlgorandDataNode) Stop() {
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

// SetSyncRound sets the minimum sync round on the catchup service
func (node *AlgorandDataNode) SetSyncRound(rnd uint64) error {
	return node.catchupService.SetSyncRound(rnd)
}

// GetSyncRound retrieves the sync round, and any error
func (node *AlgorandDataNode) GetSyncRound() (uint64, error) {
	return node.catchupService.GetSyncRound()
}

// UnsetSyncRound removes the sync round constraint on the ledger
func (node *AlgorandDataNode) UnsetSyncRound() error {
	return node.catchupService.UnsetSyncRound()
}

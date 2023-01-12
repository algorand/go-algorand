// Copyright (C) 2019-2023 Algorand, Inc.
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
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/messagetracer"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/stateproof"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
)

type AlgorandDataNode struct {
	AlgorandFullNode
}

// TODO how will we no-op the methods we don't want called?

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
	p2pNode.SetPrioScheme(node)
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
	node.ledger, err = data.LoadLedger(node.log, ledgerPathnamePrefix, false, genesis.Proto, genalloc, node.genesisID, node.genesisHash, []ledgercore.BlockListener{}, cfg)
	if err != nil {
		log.Errorf("Cannot initialize ledger (%s): %v", ledgerPathnamePrefix, err)
		return nil, err
	}

	node.transactionPool = pools.MakeTransactionPool(node.ledger.Ledger, cfg, node.log)

	blockListeners := []ledgercore.BlockListener{
		node.transactionPool,
		node,
	}

	if node.config.EnableTopAccountsReporting {
		blockListeners = append(blockListeners, &accountListener)
	}
	node.ledger.RegisterBlockListeners(blockListeners)

	node.blockService = rpcs.MakeBlockService(node.log, cfg, node.ledger, p2pNode, node.genesisID)
	node.ledgerService = rpcs.MakeLedgerService(cfg, node.ledger, p2pNode, node.genesisID)
	rpcs.RegisterTxService(node.transactionPool, p2pNode, node.genesisID, cfg.TxPoolSize, cfg.TxSyncServeResponseSize)

	node.catchupBlockAuth = blockAuthenticatorImpl{Ledger: node.ledger, AsyncVoteVerifier: agreement.MakeAsyncVoteVerifier(node.lowPriorityCryptoVerificationPool)}
	node.catchupService = catchup.MakeService(node.log, node.config, p2pNode, node.ledger, node.catchupBlockAuth, make(chan catchup.PendingUnmatchedCertificate), node.lowPriorityCryptoVerificationPool)

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

	stateProofPathname := filepath.Join(genesisDir, config.StateProofFileName)
	stateProofAccess, err := db.MakeAccessor(stateProofPathname, false, false)
	if err != nil {
		log.Errorf("Cannot load state proof data: %v", err)
		return nil, err
	}
	node.stateProofWorker = stateproof.NewWorker(stateProofAccess, node.log, node.accountManager, node.ledger.Ledger, node.net, node)

	return node, err
}

// Start the node: connect to peers while obtaining a lock. Doesn't wait for initial sync.
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
		node.stateProofWorker.Start()
		startNetwork()

		node.startMonitoringRoutines()
	}

}

// startMonitoringRoutines starts the internal monitoring routines used by the node.
func (node *AlgorandDataNode) startMonitoringRoutines() {
	if node.config.EnableUsageLog {
		node.monitoringRoutinesWaitGroup.Add(1)
		go logging.UsageLogThread(node.ctx, node.log, 100*time.Millisecond, nil)
	}
}

// waitMonitoringRoutines waits for all the monitoring routines to exit. Note that
// the node.mu must not be taken, and that the node's context should have been canceled.
func (node *AlgorandDataNode) waitMonitoringRoutines() {
	node.monitoringRoutinesWaitGroup.Wait()
}

// Stop stops running the node. Once a node is closed, it can never start again.
func (node *AlgorandDataNode) Stop() {
	node.mu.Lock()
	defer func() {
		node.mu.Unlock()
		node.waitMonitoringRoutines()
		node.stateProofWorker.Shutdown()
		node.stateProofWorker = nil
	}()

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
}

// BroadcastSignedTxGroup errors in sync mode
func (node *AlgorandDataNode) BroadcastSignedTxGroup(_ []transactions.SignedTxn) (err error) {
	return fmt.Errorf("cannot broadcast txns in sync mode")
}

// BroadcastInternalSignedTxGroup errors in sync mode
func (node *AlgorandDataNode) BroadcastInternalSignedTxGroup(_ []transactions.SignedTxn) (err error) {
	return fmt.Errorf("cannot broadcast internal signed txn group in sync mode")
}

// Simulate speculatively runs a transaction group against the current
// blockchain state and returns the effects and/or errors that would result.
func (node *AlgorandDataNode) Simulate(_ []transactions.SignedTxn) (vb *ledgercore.ValidatedBlock, missingSignatures bool, err error) {
	err = fmt.Errorf("cannot simulate in data mode")
	return
}

// GetPendingTransaction no-ops in sync mode
func (node *AlgorandDataNode) GetPendingTransaction(_ transactions.Txid) (res TxnWithStatus, found bool) {
	return
}

// SuggestedFee no-ops in sync mode
func (node *AlgorandDataNode) SuggestedFee() basics.MicroAlgos {
	return basics.MicroAlgos{}
}

// GetPendingTxnsFromPool returns an empty array in sync mode.
func (node *AlgorandDataNode) GetPendingTxnsFromPool() ([]transactions.SignedTxn, error) {
	return []transactions.SignedTxn{}, nil
}

// ListParticipationKeys returns an empty list in sync mode
func (node *AlgorandDataNode) ListParticipationKeys() (partKeys []account.ParticipationRecord, err error) {
	return []account.ParticipationRecord{}, nil
}

// GetParticipationKey returns an error in sync mode
func (node *AlgorandDataNode) GetParticipationKey(_ account.ParticipationID) (account.ParticipationRecord, error) {
	return account.ParticipationRecord{}, fmt.Errorf("cannot get participation key in sync mode")
}

// RemoveParticipationKey returns an error in sync mode
func (node *AlgorandDataNode) RemoveParticipationKey(_ account.ParticipationID) error {
	return fmt.Errorf("cannot remove participation key in sync mode")
}

// AppendParticipationKeys returns an error in sync mode
func (node *AlgorandDataNode) AppendParticipationKeys(_ account.ParticipationID, keys account.StateProofKeys) error {
	return fmt.Errorf("cannot append participation keys in sync mode")
}

// InstallParticipationKey Given a participation key binary stream install the participation key.
func (node *AlgorandDataNode) InstallParticipationKey(_ []byte) (account.ParticipationID, error) {
	return account.ParticipationID{}, fmt.Errorf("cannot install participation key in sync mode")
}

// OnNewBlock implements the BlockListener interface so we're notified after each block is written to the ledger
//TODO
func (node *AlgorandDataNode) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	if node.ledger.Latest() > block.Round() {
		return
	}
	node.syncStatusMu.Lock()
	node.lastRoundTimestamp = time.Now()
	node.hasSyncedSinceStartup = true
	node.syncStatusMu.Unlock()

	// Wake up oldKeyDeletionThread(), non-blocking.
	select {
	case node.oldKeyDeletionNotify <- struct{}{}:
	default:
	}
}

func (node *AlgorandDataNode) oldKeyDeletionThread(_ <-chan struct{}) {
	node.monitoringRoutinesWaitGroup.Done()
}

// AssembleBlock returns an error in sync mode
func (node *AlgorandDataNode) AssembleBlock(_ basics.Round) (agreement.ValidatedBlock, error) {
	return validatedBlock{}, fmt.Errorf("cannot run AssembleBlock in sync mode")
}

// VotingKeys no-ops in sync mode
func (node *AlgorandDataNode) VotingKeys(_, _ basics.Round) []account.ParticipationRecordForRound {
	return []account.ParticipationRecordForRound{}
}

// Record no-ops in sync mode.
func (node *AlgorandDataNode) Record(_ basics.Address, _ basics.Round, _ account.ParticipationAction) {
}

// IsParticipating implements network.NodeInfo
func (node *AlgorandDataNode) IsParticipating() bool {
	return false
}

// SetSyncRound sets the minimum sync round on the catchup service
func (node *AlgorandDataNode) SetSyncRound(rnd uint64) error {
	// Calculate the first round for which we want to disable catchup from the network.
	// This is based on the size of the cache used in the ledger.
	disableSyncRound := rnd + node.Config().MaxAcctLookback
	return node.catchupService.SetDisableSyncRound(disableSyncRound)
}

// GetSyncRound retrieves the sync round, removes cache offset used during SetSyncRound
func (node *AlgorandDataNode) GetSyncRound() uint64 {
	return basics.SubSaturate(node.catchupService.GetDisableSyncRound(), node.Config().MaxAcctLookback)
}

// UnsetSyncRound removes the sync round constraint on the catchup service
func (node *AlgorandDataNode) UnsetSyncRound() {
	node.catchupService.UnsetDisableSyncRound()
}

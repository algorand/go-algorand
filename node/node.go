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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/agreement/gossip"
	"github.com/algorand/go-algorand/catchup"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/heartbeat"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/messagetracer"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/stateproof"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-algorand/util/timers"
)

const (
	participationRegistryFlushMaxWaitDuration = 30 * time.Second
)

const (
	bitMismatchingVotingKey = 1 << iota
	bitMismatchingSelectionKey
	bitAccountOffline
	bitAccountIsClosed
)

// StatusReport represents the current basic status of the node
type StatusReport struct {
	LastRound                          basics.Round
	LastVersion                        protocol.ConsensusVersion
	NextVersion                        protocol.ConsensusVersion
	NextVersionRound                   basics.Round
	NextVersionSupported               bool
	LastRoundTimestamp                 time.Time
	SynchronizingTime                  time.Duration
	CatchupTime                        time.Duration
	HasSyncedSinceStartup              bool
	StoppedAtUnsupportedRound          bool
	LastCatchpoint                     string // the last catchpoint hit by the node. This would get updated regardless of whether the node is catching up using catchpoints or not.
	Catchpoint                         string // the catchpoint where we're currently catching up to. If the node isn't in fast catchup mode, it will be empty.
	CatchpointCatchupTotalAccounts     uint64
	CatchpointCatchupProcessedAccounts uint64
	CatchpointCatchupVerifiedAccounts  uint64
	CatchpointCatchupTotalKVs          uint64
	CatchpointCatchupProcessedKVs      uint64
	CatchpointCatchupVerifiedKVs       uint64
	CatchpointCatchupTotalBlocks       uint64
	CatchpointCatchupAcquiredBlocks    uint64
	UpgradePropose                     protocol.ConsensusVersion
	UpgradeApprove                     bool
	UpgradeDelay                       basics.Round
	NextProtocolVoteBefore             basics.Round
	NextProtocolApprovals              basics.Round
}

// TimeSinceLastRound returns the time since the last block was approved (locally), or 0 if no blocks seen
func (status StatusReport) TimeSinceLastRound() time.Duration {
	if status.LastRoundTimestamp.IsZero() {
		return time.Duration(0)
	}

	return time.Since(status.LastRoundTimestamp)
}

// AlgorandFullNode specifies and implements a full Algorand node.
type AlgorandFullNode struct {
	mu        deadlock.Mutex
	ctx       context.Context
	cancelCtx context.CancelFunc
	config    config.Local

	ledger *data.Ledger
	net    network.GossipNode

	transactionPool *pools.TransactionPool
	txHandler       *data.TxHandler
	accountManager  *data.AccountManager

	agreementService         *agreement.Service
	catchupService           *catchup.Service
	catchpointCatchupService *catchup.CatchpointCatchupService
	blockService             *rpcs.BlockService
	ledgerService            *rpcs.LedgerService
	txPoolSyncerService      *rpcs.TxSyncer

	genesisDirs     config.ResolvedGenesisDirs
	genesisID       string
	genesisHash     crypto.Digest
	devMode         bool // is this node operating in a developer mode ? ( benign agreement, broadcasting transaction generates a new block )
	timestampOffset *int64

	log logging.Logger

	// syncStatusMu used for locking lastRoundTimestamp and hasSyncedSinceStartup
	// syncStatusMu added so OnNewBlock wouldn't be blocked by oldKeyDeletionThread during catchup
	syncStatusMu          deadlock.Mutex
	lastRoundTimestamp    time.Time
	hasSyncedSinceStartup bool

	cryptoPool                         execpool.ExecutionPool
	lowPriorityCryptoVerificationPool  execpool.BacklogPool
	highPriorityCryptoVerificationPool execpool.BacklogPool
	catchupBlockAuth                   blockAuthenticatorImpl

	oldKeyDeletionNotify        chan struct{}
	monitoringRoutinesWaitGroup sync.WaitGroup

	hybridError                 string // whether the MakeFull switched to non-hybrid mode due to a P2PHybridConfigError and needs to be logged periodically
	hybridErrorRoutineWaitGroup sync.WaitGroup

	tracer messagetracer.MessageTracer

	stateProofWorker *stateproof.Worker
	partHandles      []db.Accessor

	heartbeatService *heartbeat.Service
}

// TxnWithStatus represents information about a single transaction,
// in particular, whether it has appeared in some block yet or not,
// and whether it was kicked out of the txpool due to some error.
type TxnWithStatus struct {
	Txn transactions.SignedTxn

	// Zero indicates no confirmation
	ConfirmedRound basics.Round

	// PoolError indicates that the transaction was kicked out of this
	// node's transaction pool (and specifies why that happened).  An
	// empty string indicates the transaction wasn't kicked out of this
	// node's txpool due to an error.
	PoolError string

	// ApplyData is the transaction.ApplyData, if committed.
	ApplyData transactions.ApplyData
}

// MakeFull sets up an Algorand full node
// (i.e., it returns a node that participates in consensus)
func MakeFull(log logging.Logger, rootDir string, cfg config.Local, phonebookAddresses []string, genesis bookkeeping.Genesis) (*AlgorandFullNode, error) {
	node := new(AlgorandFullNode)
	node.log = log.With("name", cfg.NetAddress)
	node.genesisID = genesis.ID()
	node.genesisHash = genesis.Hash()
	node.devMode = genesis.DevMode
	node.config = cfg
	var err error
	node.genesisDirs, err = cfg.EnsureAndResolveGenesisDirs(rootDir, genesis.ID(), log)
	if err != nil {
		return nil, err
	}

	genalloc, err := genesis.Balances()
	if err != nil {
		log.Errorf("Cannot load genesis allocation: %v", err)
		return nil, err
	}

	// tie network, block fetcher, and agreement services together
	var p2pNode network.GossipNode
	var genesisInfo = network.GenesisInfo{
		GenesisID: genesis.ID(),
		NetworkID: genesis.Network,
	}
recreateNetwork:
	if cfg.EnableP2PHybridMode {
		p2pNode, err = network.NewHybridP2PNetwork(node.log, node.config, rootDir, phonebookAddresses, genesisInfo, node, nil)
		if err != nil {
			if _, ok := err.(config.P2PHybridConfigError); !ok {
				log.Errorf("could not create hybrid p2p node: %v", err)
				return nil, err
			}
			// it was P2PHybridConfigError error so fallback to non-hybrid mode (either P2P or WS)
			cfg.EnableP2PHybridMode = false

			// indicate we need to start logging the error into the log periodically
			fallbackNetName := "WS"
			if cfg.EnableP2P {
				fallbackNetName = "P2P"
			}
			node.hybridError = fmt.Sprintf("could not create hybrid p2p node: %v. Falling back to %s network", err, fallbackNetName)
			log.Error(node.hybridError)

			goto recreateNetwork
		}
	} else if cfg.EnableP2P {
		p2pNode, err = network.NewP2PNetwork(node.log, node.config, rootDir, phonebookAddresses, genesisInfo, node, nil, nil)
		if err != nil {
			log.Errorf("could not create p2p node: %v", err)
			return nil, err
		}
	} else {
		var wsNode *network.WebsocketNetwork
		wsNode, err = network.NewWebsocketNetwork(node.log, node.config, phonebookAddresses, genesisInfo, node, nil, nil)
		if err != nil {
			log.Errorf("could not create websocket node: %v", err)
			return nil, err
		}
		wsNode.SetPrioScheme(node)
		p2pNode = wsNode
	}
	node.net = p2pNode

	node.cryptoPool = execpool.MakePool(node, "worker", "cryptoPool")
	node.lowPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.LowPriority, node, "worker", "lowPriorityCryptoVerificationPool")
	node.highPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.HighPriority, node, "worker", "highPriorityCryptoVerificationPool")
	ledgerPaths := ledger.DirsAndPrefix{
		DBFilePrefix:        config.LedgerFilenamePrefix,
		ResolvedGenesisDirs: node.genesisDirs,
	}
	node.ledger, err = data.LoadLedger(node.log, ledgerPaths, false, genesis.Proto, genalloc, node.genesisID, node.genesisHash, cfg)
	if err != nil {
		log.Errorf("Cannot initialize ledger (%v): %v", ledgerPaths, err)
		return nil, err
	}

	registry, err := ensureParticipationDB(node.genesisDirs.ColdGenesisDir, node.log)
	if err != nil {
		log.Errorf("unable to initialize the participation registry database: %v", err)
		return nil, err
	}
	node.accountManager = data.MakeAccountManager(log, registry)

	err = node.loadParticipationKeys()
	if err != nil {
		log.Errorf("Cannot load participation keys: %v", err)
		return nil, err
	}

	node.oldKeyDeletionNotify = make(chan struct{}, 1)

	node.transactionPool = pools.MakeTransactionPool(node.ledger.Ledger, cfg, node.log, node)

	node.ledger.RegisterBlockListeners([]ledgercore.BlockListener{node.transactionPool, node})
	txHandlerOpts := data.TxHandlerOpts{
		TxPool:        node.transactionPool,
		ExecutionPool: node.lowPriorityCryptoVerificationPool,
		Ledger:        node.ledger,
		Net:           node.net,
		Config:        cfg,
	}
	node.txHandler, err = data.MakeTxHandler(txHandlerOpts)
	if err != nil {
		log.Errorf("Cannot initialize TxHandler: %v", err)
		return nil, err
	}

	// The health service registers itself with the network
	if cfg.IsGossipServer() {
		rpcs.MakeHealthService(node.net)
	}

	node.blockService = rpcs.MakeBlockService(node.log, cfg, node.ledger, p2pNode, node.genesisID)
	node.ledgerService = rpcs.MakeLedgerService(cfg, node.ledger, p2pNode, node.genesisID)
	rpcs.RegisterTxService(node.transactionPool, p2pNode, node.genesisID, cfg.TxPoolSize, cfg.TxSyncServeResponseSize)

	// crash data is stored in the cold data directory unless otherwise specified
	crashPathname := filepath.Join(node.genesisDirs.CrashGenesisDir, config.CrashFilename)
	crashAccess, err := db.MakeAccessor(crashPathname, false, false)
	if err != nil {
		log.Errorf("Cannot load crash data: %v", err)
		return nil, err
	}

	blockValidator := blockValidatorImpl{l: node.ledger, verificationPool: node.highPriorityCryptoVerificationPool}
	agreementLedger := makeAgreementLedger(node.ledger, node.net)
	var agreementClock timers.Clock[agreement.TimeoutType]
	if node.devMode {
		agreementClock = timers.MakeFrozenClock[agreement.TimeoutType]()
	} else {
		agreementClock = timers.MakeMonotonicClock[agreement.TimeoutType](time.Now())
	}

	agreementParameters := agreement.Parameters{
		Logger:         log,
		Accessor:       crashAccess,
		Clock:          agreementClock,
		Local:          node.config,
		Network:        gossip.WrapNetwork(node.net, log, cfg),
		Ledger:         agreementLedger,
		BlockFactory:   node,
		BlockValidator: blockValidator,
		KeyManager:     node,
		RandomSource:   node,
		BacklogPool:    node.highPriorityCryptoVerificationPool,
	}
	node.agreementService, err = agreement.MakeService(agreementParameters)
	if err != nil {
		log.Errorf("unable to initialize agreement: %v", err)
		return nil, err
	}

	node.catchupBlockAuth = blockAuthenticatorImpl{Ledger: node.ledger, AsyncVoteVerifier: agreement.MakeAsyncVoteVerifier(node.lowPriorityCryptoVerificationPool)}
	node.catchupService = catchup.MakeService(node.log, node.config, p2pNode, node.ledger, node.catchupBlockAuth, agreementLedger.UnmatchedPendingCertificates, node.lowPriorityCryptoVerificationPool)
	node.txPoolSyncerService = rpcs.MakeTxSyncer(node.transactionPool, node.net, node.txHandler.SolicitedTxHandler(), time.Duration(cfg.TxSyncIntervalSeconds)*time.Second, time.Duration(cfg.TxSyncTimeoutSeconds)*time.Second, cfg.TxSyncServeResponseSize)

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
	gossip.SetTrace(agreementParameters.Network, node.tracer)

	node.stateProofWorker = stateproof.NewWorker(node.genesisDirs.StateproofGenesisDir, node.log, node.accountManager, node.ledger.Ledger, node.net, node)

	node.heartbeatService = heartbeat.NewService(node.accountManager, node.ledger, node, node.log)

	return node, err
}

// Config returns a copy of the node's Local configuration
func (node *AlgorandFullNode) Config() config.Local {
	return node.config
}

// Start the node: connect to peers and run the agreement service while obtaining a lock. Doesn't wait for initial sync.
func (node *AlgorandFullNode) Start() error {
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

	if node.hybridError != "" {
		node.hybridErrorRoutineWaitGroup.Add(1)
		go func() {
			defer node.hybridErrorRoutineWaitGroup.Done()
			ticker := time.NewTicker(6 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-node.ctx.Done():
					return
				case <-ticker.C:
					// continue logging the error periodically
					node.log.Error(node.hybridError)
				}
			}
		}()
	}

	if node.catchpointCatchupService != nil {
		startNetwork()
		node.catchpointCatchupService.Start(node.ctx)
	} else {
		node.catchupService.Start()
		node.agreementService.Start()
		node.txPoolSyncerService.Start(node.catchupService.InitialSyncDone)
		node.blockService.Start()
		node.ledgerService.Start()
		node.txHandler.Start()
		node.stateProofWorker.Start()
		node.heartbeatService.Start()
		err := startNetwork()
		if err != nil {
			return err
		}

		node.startMonitoringRoutines()
	}
	return nil
}

// Capabilities returns the node's capabilities for advertising to other nodes.
func (node *AlgorandFullNode) Capabilities() []p2p.Capability {
	var caps []p2p.Capability
	if node.config.Archival && node.config.IsGossipServer() {
		caps = append(caps, p2p.Archival)
	}
	if node.config.StoresCatchpoints() && node.config.IsGossipServer() {
		caps = append(caps, p2p.Catchpoints)
	}
	if node.config.EnableGossipService && node.config.IsGossipServer() {
		caps = append(caps, p2p.Gossip)
	}
	return caps
}

// startMonitoringRoutines starts the internal monitoring routines used by the node.
func (node *AlgorandFullNode) startMonitoringRoutines() {
	node.monitoringRoutinesWaitGroup.Add(2)
	go node.txPoolGaugeThread(node.ctx.Done())
	// Delete old participation keys
	go node.oldKeyDeletionThread(node.ctx.Done())

	if node.config.EnableUsageLog {
		node.monitoringRoutinesWaitGroup.Add(1)
		go logging.UsageLogThread(node.ctx, node.log, 100*time.Millisecond, &node.monitoringRoutinesWaitGroup)
	}
}

// waitMonitoringRoutines waits for all the monitoring routines to exit. Note that
// the node.mu must not be taken, and that the node's context should have been canceled.
func (node *AlgorandFullNode) waitMonitoringRoutines() {
	node.log.Debug("waiting on node monitoring routines to exit")
	defer node.log.Debug("done waiting on node monitoring routines to exit")
	node.monitoringRoutinesWaitGroup.Wait()
}

// ListeningAddress retrieves the node's current listening address, if any.
// Returns true if currently listening, false otherwise.
func (node *AlgorandFullNode) ListeningAddress() (string, bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.net.Address()
}

// Stop stops running the node. Once a node is closed, it can never start again.
func (node *AlgorandFullNode) Stop() {
	node.log.Debug("algorand node is stopping")
	defer node.log.Debug("algorand node has stopped")

	node.mu.Lock()
	defer func() {
		node.mu.Unlock()
		node.waitMonitoringRoutines()
		node.hybridErrorRoutineWaitGroup.Wait()

		// oldKeyDeletionThread uses accountManager registry so must be stopped before accountManager is closed
		node.accountManager.Registry().Close()
		for h := range node.partHandles {
			node.partHandles[h].Close()
		}
	}()

	node.net.ClearHandlers()
	node.net.ClearValidatorHandlers()
	if !node.config.DisableNetworking {
		node.net.Stop()
	}
	if node.catchpointCatchupService != nil {
		node.catchpointCatchupService.Stop()
	} else {
		node.heartbeatService.Stop()
		node.stateProofWorker.Stop()
		node.txHandler.Stop()
		node.agreementService.Shutdown()
		node.agreementService.Accessor.Close()
		node.catchupService.Stop()
		node.txPoolSyncerService.Stop()
		node.blockService.Stop()
		node.ledgerService.Stop()
	}
	node.catchupBlockAuth.Quit()
	node.log.Debug("crypto worker pools are stopping")
	node.highPriorityCryptoVerificationPool.Shutdown()
	node.lowPriorityCryptoVerificationPool.Shutdown()
	node.cryptoPool.Shutdown()
	node.log.Debug("crypto worker pools have stopped")
	node.transactionPool.Shutdown()
	node.cancelCtx()
	node.ledger.Close()
}

// note: unlike the other two functions, this accepts a whole filename
func (node *AlgorandFullNode) getExistingPartHandle(filename string) (db.Accessor, error) {
	filename = filepath.Join(node.genesisDirs.RootGenesisDir, filename)

	_, err := os.Stat(filename)
	if err == nil {
		return db.MakeErasableAccessor(filename)
	}
	return db.Accessor{}, err
}

// Ledger exposes the node's ledger handle to the algod API code
func (node *AlgorandFullNode) Ledger() *data.Ledger {
	return node.ledger
}

// writeDevmodeBlock generates a new block for a devmode, and write it to the ledger.
func (node *AlgorandFullNode) writeDevmodeBlock() (err error) {
	var vb *ledgercore.UnfinishedBlock
	vb, err = node.transactionPool.AssembleDevModeBlock()
	if err != nil || vb == nil {
		return
	}

	// Make a new validated block from this UnfinishedBlock.
	prevRound := vb.Round() - 1
	prev, err := node.ledger.BlockHdr(prevRound)
	if err != nil {
		return err
	}

	blk := vb.UnfinishedBlock()

	// Set block timestamp based on offset, if set.
	// Make sure block timestamp is not greater than MaxInt64.
	if node.timestampOffset != nil && *node.timestampOffset < math.MaxInt64-prev.TimeStamp {
		blk.TimeStamp = prev.TimeStamp + *node.timestampOffset
	}
	blk.BlockHeader.Seed = committee.Seed(prev.Hash())
	// Zero out payouts if Proposer not set
	if (blk.BlockHeader.Proposer == basics.Address{}) {
		blk.BlockHeader.ProposerPayout = basics.MicroAlgos{}
	}
	vb2 := ledgercore.MakeValidatedBlock(blk, vb.UnfinishedDeltas())

	// add the newly generated block to the ledger
	err = node.ledger.AddValidatedBlock(vb2, agreement.Certificate{Round: vb2.Block().Round()})
	return err
}

// BroadcastSignedTxGroup broadcasts a transaction group that has already been signed.
func (node *AlgorandFullNode) BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) (err error) {
	// in developer mode, we need to take a lock, so that each new transaction group would truly
	// render into a unique block.
	if node.devMode {
		node.mu.Lock()
		defer func() {
			// if we added the transaction successfully to the transaction pool, then
			// attempt to generate a block and write it to the ledger.
			if err == nil {
				err = node.writeDevmodeBlock()
			}
			node.mu.Unlock()
		}()
	}
	return node.broadcastSignedTxGroup(txgroup)
}

// AsyncBroadcastSignedTxGroup feeds a raw transaction group directly to the transaction pool.
// This method is intended to be used for performance testing and debugging purposes only.
func (node *AlgorandFullNode) AsyncBroadcastSignedTxGroup(txgroup []transactions.SignedTxn) (err error) {
	return node.txHandler.LocalTransaction(txgroup)
}

// BroadcastInternalSignedTxGroup broadcasts a transaction group that has already been signed.
// It is originated internally, and in DevMode, it will not advance the round.
func (node *AlgorandFullNode) BroadcastInternalSignedTxGroup(txgroup []transactions.SignedTxn) (err error) {
	return node.broadcastSignedTxGroup(txgroup)
}

var broadcastTxSucceeded = metrics.MakeCounter(metrics.BroadcastSignedTxGroupSucceeded)
var broadcastTxFailed = metrics.MakeCounter(metrics.BroadcastSignedTxGroupFailed)

// broadcastSignedTxGroup broadcasts a transaction group that has already been signed.
func (node *AlgorandFullNode) broadcastSignedTxGroup(txgroup []transactions.SignedTxn) (err error) {
	defer func() {
		if err != nil {
			broadcastTxFailed.Inc(nil)
		} else {
			broadcastTxSucceeded.Inc(nil)
		}
	}()

	lastRound := node.ledger.Latest()
	var b bookkeeping.BlockHeader
	b, err = node.ledger.BlockHdr(lastRound)
	if err != nil {
		node.log.Errorf("could not get block header from last round %v: %v", lastRound, err)
		return err
	}

	_, err = verify.TxnGroup(txgroup, &b, node.ledger.VerifiedTransactionCache(), node.ledger)
	if err != nil {
		node.log.Warnf("malformed transaction: %v", err)
		return err
	}

	err = node.transactionPool.Remember(txgroup)
	if err != nil {
		node.log.Infof("rejected by local pool: %v - transaction group was %+v", err, txgroup)
		return err
	}

	err = node.ledger.VerifiedTransactionCache().Pin(txgroup)
	if err != nil {
		logging.Base().Infof("unable to pin transaction: %v", err)
	}
	// DevMode nodes do not broadcast txns to the network
	if node.devMode {
		return nil
	}
	var enc []byte
	var txids []transactions.Txid
	for _, tx := range txgroup {
		enc = append(enc, protocol.Encode(&tx)...)
		txids = append(txids, tx.ID())
	}
	err = node.net.Broadcast(context.TODO(), protocol.TxnTag, enc, false, nil)
	if err != nil {
		node.log.Infof("failure broadcasting transaction to network: %v - transaction group was %+v", err, txgroup)
		return err
	}
	node.log.Infof("Sent signed tx group with IDs %v", txids)
	return nil
}

// Simulate speculatively runs a transaction group against the current
// blockchain state and returns the effects and/or errors that would result.
func (node *AlgorandFullNode) Simulate(request simulation.Request) (result simulation.Result, err error) {
	simulator := simulation.MakeSimulator(node.ledger, node.config.EnableDeveloperAPI)
	return simulator.Simulate(request)
}

// GetPendingTransaction looks for the required txID in the recent ledger
// blocks, in the txpool, and in the txpool's status cache.  It returns
// the SignedTxn (with status information), and a bool to indicate if the
// transaction was found.
func (node *AlgorandFullNode) GetPendingTransaction(txID transactions.Txid) (res TxnWithStatus, found bool) {
	// We need to check both the pool and the ledger's blocks.
	// If the transaction is found in a committed block, that
	// takes precedence.  But we check the pool first, because
	// otherwise there could be a race between the pool and the
	// ledger, where the block wasn't in the ledger at first,
	// but by the time we check the pool, it's not there either
	// because it committed.

	// The default return value is found=false, which is
	// appropriate if the transaction isn't found anywhere.

	// Check if it's in the pool or evicted from the pool.
	tx, txErr, found := node.transactionPool.Lookup(txID)
	if found {
		res = TxnWithStatus{
			Txn:            tx,
			ConfirmedRound: 0,
			PoolError:      txErr,
		}
		found = true

		// Keep looking in the ledger.
	}

	// quick check for confirmed transactions with LastValid in future
	// this supposed to cover most of the cases where REST checks for the most recent txns
	if r, confirmed := node.ledger.CheckConfirmedTail(txID); confirmed {
		tx, foundBlk, err := node.ledger.LookupTxid(txID, r)
		if err == nil && foundBlk {
			return TxnWithStatus{
				Txn:            tx.SignedTxn,
				ConfirmedRound: r,
				ApplyData:      tx.ApplyData,
			}, true
		}
	}
	// if found in the pool and not in the tail then return without looking into blocks
	// because the check appears to be too early
	if found {
		return res, found
	}

	// fallback to blocks lookup
	var maxLife basics.Round
	latest := node.ledger.Latest()
	proto, err := node.ledger.ConsensusParams(latest)
	if err == nil {
		maxLife = basics.Round(proto.MaxTxnLife)
	} else {
		node.log.Errorf("node.GetPendingTransaction: cannot get consensus params for latest round %v", latest)
	}

	// Search from newest to oldest round up to the max life of a transaction.
	maxRound := latest
	minRound := maxRound.SubSaturate(maxLife)

	// Since we're using uint64, if the minRound is 0, we need to check for an underflow.
	if minRound == 0 {
		minRound++
	}

	// If we did find the transaction, we know there is no point
	// checking rounds earlier or later than validity rounds
	if found {
		if tx.Txn.FirstValid > minRound {
			minRound = tx.Txn.FirstValid
		}

		if tx.Txn.LastValid < maxRound {
			maxRound = tx.Txn.LastValid
		}
	}

	for r := maxRound; r >= minRound; r-- {
		tx, found, err := node.ledger.LookupTxid(txID, r)
		if err != nil || !found {
			continue
		}

		return TxnWithStatus{
			Txn:            tx.SignedTxn,
			ConfirmedRound: r,
			ApplyData:      tx.ApplyData,
		}, true
	}

	// Return whatever we found in the pool (if anything).
	return res, found
}

// GetPeers returns the node's peers
func (node *AlgorandFullNode) GetPeers() (inboundPeers []network.Peer, outboundPeers []network.Peer, err error) {
	return node.net.GetPeers(network.PeersConnectedIn), node.net.GetPeers(network.PeersConnectedOut), nil
}

// Status returns a StatusReport structure reporting our status as Active and with our ledger's LastRound
func (node *AlgorandFullNode) Status() (StatusReport, error) {
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

func catchpointCatchupStatus(lastBlockHeader bookkeeping.BlockHeader, stats catchup.CatchpointCatchupStats) (s StatusReport) {
	// we're in catchpoint catchup mode.
	s.LastRound = lastBlockHeader.Round
	s.LastVersion = lastBlockHeader.CurrentProtocol
	s.NextVersion, s.NextVersionRound, s.NextVersionSupported = lastBlockHeader.NextVersionInfo()
	s.StoppedAtUnsupportedRound = s.LastRound+1 == s.NextVersionRound && !s.NextVersionSupported

	// for now, I'm leaving this commented out. Once we refactor some of the ledger locking mechanisms, we
	// should be able to make this call work.
	//s.LastCatchpoint = node.ledger.GetLastCatchpointLabel()

	// report back the catchpoint catchup progress statistics
	s.Catchpoint = stats.CatchpointLabel
	s.CatchpointCatchupTotalAccounts = stats.TotalAccounts
	s.CatchpointCatchupProcessedAccounts = stats.ProcessedAccounts
	s.CatchpointCatchupVerifiedAccounts = stats.VerifiedAccounts
	s.CatchpointCatchupTotalKVs = stats.TotalKVs
	s.CatchpointCatchupProcessedKVs = stats.ProcessedKVs
	s.CatchpointCatchupVerifiedKVs = stats.VerifiedKVs
	s.CatchpointCatchupTotalBlocks = stats.TotalBlocks
	s.CatchpointCatchupAcquiredBlocks = stats.AcquiredBlocks
	s.CatchupTime = time.Since(stats.StartTime)
	return
}

func latestBlockStatus(ledger *data.Ledger, catchupService *catchup.Service) (s StatusReport, err error) {
	// we're not in catchpoint catchup mode
	var b bookkeeping.BlockHeader
	s.LastRound = ledger.Latest()
	b, err = ledger.BlockHdr(s.LastRound)
	if err != nil {
		return
	}
	s.LastVersion = b.CurrentProtocol
	s.NextVersion, s.NextVersionRound, s.NextVersionSupported = b.NextVersionInfo()

	s.StoppedAtUnsupportedRound = s.LastRound+1 == s.NextVersionRound && !s.NextVersionSupported
	s.LastCatchpoint = ledger.GetLastCatchpointLabel()
	s.SynchronizingTime = catchupService.SynchronizingTime()
	s.CatchupTime = catchupService.SynchronizingTime()

	s.UpgradePropose = b.UpgradeVote.UpgradePropose
	s.UpgradeApprove = b.UpgradeApprove
	s.UpgradeDelay = b.UpgradeVote.UpgradeDelay
	s.NextProtocolVoteBefore = b.NextProtocolVoteBefore
	s.NextProtocolApprovals = b.UpgradeState.NextProtocolApprovals

	return
}

// GenesisID returns the ID of the genesis node.
func (node *AlgorandFullNode) GenesisID() string {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.genesisID
}

// GenesisHash returns the hash of the genesis configuration.
func (node *AlgorandFullNode) GenesisHash() crypto.Digest {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.genesisHash
}

// SuggestedFee returns the suggested fee per byte recommended to ensure a new transaction is processed in a timely fashion.
// Caller should set fee to max(MinTxnFee, SuggestedFee() * len(encoded SignedTxn))
func (node *AlgorandFullNode) SuggestedFee() basics.MicroAlgos {
	return basics.MicroAlgos{Raw: node.transactionPool.FeePerByte()}
}

// GetPendingTxnsFromPool returns a snapshot of every pending transactions from the node's transaction pool in a slice.
// Transactions are sorted in decreasing order. If no transactions, returns an empty slice.
func (node *AlgorandFullNode) GetPendingTxnsFromPool() ([]transactions.SignedTxn, error) {
	return bookkeeping.SignedTxnGroupsFlatten(node.transactionPool.PendingTxGroups()), nil
}

// ensureParticipationDB opens or creates a participation DB.
func ensureParticipationDB(genesisDir string, log logging.Logger) (account.ParticipationRegistry, error) {
	accessorFile := filepath.Join(genesisDir, config.ParticipationRegistryFilename)
	accessor, err := db.OpenErasablePair(accessorFile)
	if err != nil {
		return nil, err
	}
	return account.MakeParticipationRegistry(accessor, log)
}

// ListParticipationKeys returns all participation keys currently installed on the node
func (node *AlgorandFullNode) ListParticipationKeys() (partKeys []account.ParticipationRecord, err error) {
	return node.accountManager.Registry().GetAll(), nil
}

// GetParticipationKey retries the information of a participation id from the node
func (node *AlgorandFullNode) GetParticipationKey(partKeyID account.ParticipationID) (account.ParticipationRecord, error) {
	rval := node.accountManager.Registry().Get(partKeyID)

	if rval.IsZero() {
		return account.ParticipationRecord{}, account.ErrParticipationIDNotFound
	}

	return rval, nil
}

// RemoveParticipationKey given a participation id, remove the records from the node
func (node *AlgorandFullNode) RemoveParticipationKey(partKeyID account.ParticipationID) error {

	// Need to remove the file and then remove the entry in the registry
	// Let's first get the recorded information from the registry so we can lookup the file

	partRecord := node.accountManager.Registry().Get(partKeyID)

	if partRecord.IsZero() {
		return account.ErrParticipationIDNotFound
	}

	outDir := node.genesisDirs.RootGenesisDir

	filename := config.PartKeyFilename(partRecord.ParticipationID.String(), uint64(partRecord.FirstValid), uint64(partRecord.LastValid))
	fullyQualifiedFilename := filepath.Join(outDir, filepath.Base(filename))

	err := node.accountManager.Registry().Delete(partKeyID)
	if err != nil {
		return err
	}

	err = node.accountManager.Registry().Flush(participationRegistryFlushMaxWaitDuration)
	if err != nil {
		return err
	}

	// Only after deleting and flushing do we want to remove the file
	_ = os.Remove(fullyQualifiedFilename)

	return nil
}

// AppendParticipationKeys given a participation id, remove the records from the node
func (node *AlgorandFullNode) AppendParticipationKeys(partKeyID account.ParticipationID, keys account.StateProofKeys) error {
	err := node.accountManager.Registry().AppendKeys(partKeyID, keys)
	if err != nil {
		return err
	}

	return node.accountManager.Registry().Flush(participationRegistryFlushMaxWaitDuration)
}

func createTemporaryParticipationKey(outDir string, partKeyBinary []byte) (string, error) {
	var sb strings.Builder

	// Create a temporary filename with a UUID so that we can call this function twice
	// in a row without worrying about collisions
	sb.WriteString("tempPartKeyBinary.")
	sb.WriteString(fmt.Sprintf("%d", crypto.RandUint64()))
	sb.WriteString(".bin")

	tempFile := filepath.Join(outDir, filepath.Base(sb.String()))

	file, err := os.Create(tempFile)

	if err != nil {
		return "", err
	}

	_, err = file.Write(partKeyBinary)

	file.Close()

	if err != nil {
		os.Remove(tempFile)
		return "", err
	}

	return tempFile, nil
}

// InstallParticipationKey Given a participation key binary stream install the participation key.
func (node *AlgorandFullNode) InstallParticipationKey(partKeyBinary []byte) (account.ParticipationID, error) {
	outDir := node.genesisDirs.RootGenesisDir

	fullyQualifiedTempFile, err := createTemporaryParticipationKey(outDir, partKeyBinary)
	// We need to make sure no tempfile is created/remains if there is an error
	// However, we will eventually rename this file but if we fail in-between
	// this point and the rename we want to ensure that we remove the temporary file
	// After we rename, this will fail anyway since the file will not exist

	// Explicitly ignore the error with a closure
	defer func(name string) {
		_ = os.Remove(name)
	}(fullyQualifiedTempFile)

	if err != nil {
		return account.ParticipationID{}, err
	}

	inputdb, err := db.MakeErasableAccessor(fullyQualifiedTempFile)
	if err != nil {
		return account.ParticipationID{}, err
	}
	defer inputdb.Close()

	partkey, err := account.RestoreParticipationWithSecrets(inputdb)
	if err != nil {
		return account.ParticipationID{}, err
	}
	defer partkey.Close()

	if partkey.Parent == (basics.Address{}) {
		return account.ParticipationID{}, fmt.Errorf("cannot install partkey with missing (zero) parent address")
	}

	// Tell the AccountManager about the Participation (dupes don't matter) so we ignore the return value
	// This is ephemeral since we are deleting the file after this function is done
	added := node.accountManager.AddParticipation(partkey, true)
	if !added {
		return account.ParticipationID{}, fmt.Errorf("ParticipationRegistry: cannot register duplicate participation key")
	}

	err = insertStateProofToRegistry(partkey, node)
	if err != nil {
		return account.ParticipationID{}, err
	}

	err = node.accountManager.Registry().Flush(participationRegistryFlushMaxWaitDuration)
	if err != nil {
		return account.ParticipationID{}, err
	}

	return partkey.ID(), nil
}

func (node *AlgorandFullNode) loadParticipationKeys() error {
	// Generate a list of all potential participation key files
	genesisDir := node.genesisDirs.RootGenesisDir
	files, err := os.ReadDir(genesisDir)
	if err != nil {
		return fmt.Errorf("AlgorandFullNode.loadPartitipationKeys: could not read directory %v: %v", genesisDir, err)
	}

	// For each of these files
	for _, info := range files {
		// If it can't be a participation key database, skip it
		if !config.IsPartKeyFilename(info.Name()) {
			continue
		}
		filename := info.Name()

		// Fetch a handle to this database
		handle, err := node.getExistingPartHandle(filename)
		if err != nil {
			if db.IsErrBusy(err) {
				// this is a special case:
				// we might get "database is locked" when we attempt to access a database that is concurrently updating its participation keys.
				// that database is clearly already on the account manager, and doesn't need to be processed through this logic, and therefore
				// we can safely ignore that fail case.
				continue
			}
			return fmt.Errorf("AlgorandFullNode.loadParticipationKeys: cannot load db %v: %v", filename, err)
		}

		// Fetch an account.Participation from the database
		// currently, we load all stateproof secrets to memory which is not ideal .
		// as part of the participation interface changes , secrets will no longer
		// be loaded like this.
		part, err := account.RestoreParticipationWithSecrets(handle)
		if err != nil {
			handle.Close()
			if err == account.ErrUnsupportedSchema {
				node.log.Infof("Loaded participation keys from storage: %s %s", part.Address(), info.Name())
				node.log.Warnf("loadParticipationKeys: not loading unsupported participation key: %s; renaming to *.old", info.Name())
				fullname := filepath.Join(genesisDir, info.Name())
				renamedFileName := filepath.Join(fullname, ".old")
				err = os.Rename(fullname, renamedFileName)
				if err != nil {
					node.log.Warnf("loadParticipationKeys: failed to rename unsupported participation key file '%s' to '%s': %v", fullname, renamedFileName, err)
				}
			} else {
				return fmt.Errorf("AlgorandFullNode.loadParticipationKeys: cannot load account at %v: %v", info.Name(), err)
			}
		} else {
			// Tell the AccountManager about the Participation (dupes don't matter)
			// make sure that all stateproof data (with are not the keys per round)
			// are being store to the registry in that point
			// These files are not ephemeral and must be deleted eventually since
			// this function is called to load files located in the node on startup
			added := node.accountManager.AddParticipation(part, false)
			if !added {
				part.Close()
				continue
			}
			node.log.Infof("Loaded participation keys from storage: %s %s", part.Address(), info.Name())
			node.partHandles = append(node.partHandles, handle)
			err = insertStateProofToRegistry(part, node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func insertStateProofToRegistry(part account.PersistedParticipation, node *AlgorandFullNode) error {
	partID := part.ID()
	// in case there are no state proof keys for that participant
	if part.StateProofSecrets == nil {
		return nil
	}
	keys := part.StateProofSecrets.GetAllKeys()
	keysSigner := make(account.StateProofKeys, len(keys))
	for i := uint64(0); i < uint64(len(keys)); i++ {
		keysSigner[i] = keys[i]
	}
	return node.accountManager.Registry().AppendKeys(partID, keysSigner)

}

var txPoolGauge = metrics.MakeGauge(metrics.MetricName{Name: "algod_tx_pool_count", Description: "current number of available transactions in pool"})

func (node *AlgorandFullNode) txPoolGaugeThread(done <-chan struct{}) {
	defer node.monitoringRoutinesWaitGroup.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			txPoolGauge.Set(uint64(node.transactionPool.PendingCount()))
		case <-done:
			return
		}
	}
}

// OnNewBlock implements the BlockListener interface so we're notified after each block is written to the ledger
func (node *AlgorandFullNode) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
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

// oldKeyDeletionThread keeps deleting old participation keys.
// It runs in a separate thread so that, during catchup, we
// don't have to delete key for each block we received.
func (node *AlgorandFullNode) oldKeyDeletionThread(done <-chan struct{}) {
	defer node.monitoringRoutinesWaitGroup.Done()

	for {
		select {
		case <-done:
			return
		case <-node.oldKeyDeletionNotify:
		}

		r := node.ledger.Latest()

		latestHdr, err := node.ledger.BlockHdr(r)
		if err != nil {
			switch err.(type) {
			case ledgercore.ErrNoEntry:
				// No need to warn; expected during catchup.
			default:
				node.log.Warnf("Cannot look up latest block %d for deleting ephemeral keys: %v", r, err)
			}
			continue
		}

		// We need to find the consensus protocol used to agree on block r,
		// since that determines the params used for ephemeral keys in block
		// r.  The params come from agreement.ParamsRound(r), which is r-2.
		hdr, err := node.ledger.BlockHdr(agreement.ParamsRound(r))
		if err != nil {
			switch err.(type) {
			case ledgercore.ErrNoEntry:
				// No need to warn; expected during catchup.
			default:
				node.log.Warnf("Cannot look up params block %d for deleting ephemeral keys: %v", agreement.ParamsRound(r), err)
			}
			continue
		}

		agreementProto := config.Consensus[hdr.CurrentProtocol]

		node.mu.Lock()
		node.accountManager.DeleteOldKeys(latestHdr, agreementProto)
		node.mu.Unlock()

		// Persist participation registry updates to last-used round and voting key changes.
		err = node.accountManager.Registry().Flush(participationRegistryFlushMaxWaitDuration)
		if err != nil {
			node.log.Warnf("error while flushing the registry: %v", err)
		}
	}
}

// Uint64 implements the randomness by calling the crypto library.
func (node *AlgorandFullNode) Uint64() uint64 {
	return crypto.RandUint64()
}

// StartCatchup starts the catchpoint mode and attempt to get to the provided catchpoint
// this function is intended to be called externally via the REST api interface.
func (node *AlgorandFullNode) StartCatchup(catchpoint string) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.config.Archival {
		return fmt.Errorf("catching up using a catchpoint is not supported on archive nodes")
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
func (node *AlgorandFullNode) AbortCatchup(catchpoint string) error {
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
func (node *AlgorandFullNode) SetCatchpointCatchupMode(catchpointCatchupMode bool) (outCtxCh <-chan context.Context) {
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
			defer func() {
				node.mu.Unlock()
				node.waitMonitoringRoutines()
			}()
			node.net.ClearHandlers()
			node.net.ClearValidatorHandlers()
			node.heartbeatService.Stop()
			node.stateProofWorker.Stop()
			node.txHandler.Stop()
			node.agreementService.Shutdown()
			node.catchupService.Stop()
			node.txPoolSyncerService.Stop()
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
		node.transactionPool.Reset()
		node.catchupService.Start()
		node.agreementService.Start()
		node.txPoolSyncerService.Start(node.catchupService.InitialSyncDone)
		node.blockService.Start()
		node.ledgerService.Start()
		node.txHandler.Start()
		node.stateProofWorker.Start()
		node.heartbeatService.Start()

		// Set up a context we can use to cancel goroutines on Stop()
		node.ctx, node.cancelCtx = context.WithCancel(context.Background())

		node.startMonitoringRoutines()

		// at this point, the catchpoint catchup is done ( either successfully or not.. )
		node.catchpointCatchupService = nil

		ctxCh <- node.ctx
	}()
	return

}

// unfinishedBlock satisfies agreement.UnfinishedBlock
type unfinishedBlock struct {
	blk *ledgercore.UnfinishedBlock
}

// Round satisfies the agreement.UnfinishedBlock interface.
func (ub unfinishedBlock) Round() basics.Round { return ub.blk.Round() }

// FinishBlock satisfies the agreement.UnfinishedBlock interface.
func (ub unfinishedBlock) FinishBlock(s committee.Seed, proposer basics.Address, eligible bool) agreement.Block {
	return agreement.Block(ub.blk.FinishBlock(s, proposer, eligible))
}

// AssembleBlock implements Ledger.AssembleBlock.
func (node *AlgorandFullNode) AssembleBlock(round basics.Round, addrs []basics.Address) (agreement.UnfinishedBlock, error) {
	deadline := time.Now().Add(node.config.ProposalAssemblyTime)
	ub, err := node.transactionPool.AssembleBlock(round, deadline)
	if err != nil {
		if errors.Is(err, pools.ErrStaleBlockAssemblyRequest) {
			// convert specific error to one that would have special handling in the agreement code.
			err = agreement.ErrAssembleBlockRoundStale

			ledgerNextRound := node.ledger.NextRound()
			if ledgerNextRound == round {
				// we've asked for the right round.. and the ledger doesn't think it's stale.
				node.log.Errorf("AlgorandFullNode.AssembleBlock: could not generate a proposal for round %d, ledger and proposal generation are synced: %v", round, err)
			} else if ledgerNextRound < round {
				// from some reason, the ledger is behind the round that we're asking. That shouldn't happen, but error if it does.
				node.log.Errorf("AlgorandFullNode.AssembleBlock: could not generate a proposal for round %d, ledger next round is %d: %v", round, ledgerNextRound, err)
			}
			// the case where ledgerNextRound > round was not implemented here on purpose. This is the "normal case" where the
			// ledger was advancing faster then the agreement by the catchup.
		}
		return nil, err
	}

	// ensure UnfinishedBlock contains provided addresses
	for _, addr := range addrs {
		if !ub.ContainsAddress(addr) {
			// this should not happen: VotingKeys() and VotingAccountsForRound() should be in sync
			node.log.Errorf("AlgorandFullNode.AssembleBlock: could not generate a proposal for round %d, proposer %s not in UnfinishedBlock", round, addr)
			return nil, agreement.ErrAssembleBlockRoundStale
		}
	}

	return unfinishedBlock{blk: ub}, nil
}

// getOfflineClosedStatus will return an int with the appropriate bit(s) set if it is offline and/or online
func getOfflineClosedStatus(acctData basics.OnlineAccountData) int {
	rval := 0
	isOffline := acctData.VoteFirstValid == 0 && acctData.VoteLastValid == 0

	if isOffline {
		rval = rval | bitAccountOffline
	}

	isClosed := isOffline && acctData.MicroAlgosWithRewards.Raw == 0
	if isClosed {
		rval = rval | bitAccountIsClosed
	}

	return rval
}

// VotingAccountsForRound provides a list of addresses that have participation keys valid for the given round.
// These accounts may not all be eligible to propose, but they are a superset of eligible proposers.
func (node *AlgorandFullNode) VotingAccountsForRound(round basics.Round) []basics.Address {
	if node.devMode {
		return []basics.Address{}
	}
	parts := node.accountManager.Keys(round)
	accounts := make([]basics.Address, len(parts))
	for i, p := range parts {
		accounts[i] = p.Account
	}
	return accounts
}

// VotingKeys implements the key manager's VotingKeys method, and provides additional validation with the ledger.
// that allows us to load multiple overlapping keys for the same account, and filter these per-round basis.
func (node *AlgorandFullNode) VotingKeys(votingRound, keysRound basics.Round) []account.ParticipationRecordForRound {
	// on devmode, we don't need any voting keys for the agreement, since the agreement doesn't vote.
	if node.devMode {
		return []account.ParticipationRecordForRound{}
	}

	parts := node.accountManager.Keys(votingRound)
	participations := make([]account.ParticipationRecordForRound, 0, len(parts))
	accountsData := make(map[basics.Address]basics.OnlineAccountData, len(parts))
	matchingAccountsKeys := make(map[basics.Address]bool)
	mismatchingAccountsKeys := make(map[basics.Address]int)

	for _, p := range parts {
		acctData, hasAccountData := accountsData[p.Account]
		if !hasAccountData {
			var err error
			// LookupAgreement is used to look at the past ~320 rounds of account state
			// It provides a fast lookup method for online account information
			acctData, err = node.ledger.LookupAgreement(keysRound, p.Account)
			if err != nil {
				node.log.Warnf("node.VotingKeys: Account %v not participating: cannot locate account for round %d : %v", p.Account, keysRound, err)
				continue
			}
			accountsData[p.Account] = acctData
		}

		mismatchingAccountsKeys[p.Account] = mismatchingAccountsKeys[p.Account] | getOfflineClosedStatus(acctData)

		if acctData.VoteID != p.Voting.OneTimeSignatureVerifier {
			mismatchingAccountsKeys[p.Account] = mismatchingAccountsKeys[p.Account] | bitMismatchingVotingKey
			continue
		}
		if acctData.SelectionID != p.VRF.PK {
			mismatchingAccountsKeys[p.Account] = mismatchingAccountsKeys[p.Account] | bitMismatchingSelectionKey
			continue
		}
		participations = append(participations, p)
		matchingAccountsKeys[p.Account] = true

		// Make sure the key is registered.
		err := node.accountManager.Registry().Register(p.ParticipationID, votingRound)
		if err != nil {
			node.log.Warnf("Failed to register participation key (%s) with participation registry: %v\n", p.ParticipationID, err)
		}
	}
	// write the warnings per account only if we couldn't find a single valid key for that account.
	for mismatchingAddr, warningFlags := range mismatchingAccountsKeys {
		if matchingAccountsKeys[mismatchingAddr] {
			continue
		}
		if warningFlags&bitMismatchingVotingKey != 0 || warningFlags&bitMismatchingSelectionKey != 0 {
			// If we are closed, upgrade this to info so we don't spam telemetry reporting
			if warningFlags&bitAccountIsClosed != 0 {
				node.log.Infof("node.VotingKeys: Address: %v - Account was closed but still has a participation key active.", mismatchingAddr)
			} else if warningFlags&bitAccountOffline != 0 {
				// If account is offline, then warn that no registration transaction has been issued or that previous registration transaction is expired.
				node.log.Warnf("node.VotingKeys: Address: %v - Account is offline.  No registration transaction has been issued or a previous registration transaction has expired", mismatchingAddr)
			} else {
				// If the account isn't closed/offline and has a valid participation key, then this key may have been generated
				// on a different node.
				node.log.Warnf("node.VotingKeys: Account %v not participating on round %d: on chain voting key differ from participation voting key for round %d. Consider regenerating the participation key for this node.", mismatchingAddr, votingRound, keysRound)
			}

			continue
		}

	}
	return participations
}

// Record forwards participation record calls to the participation registry.
func (node *AlgorandFullNode) Record(account basics.Address, round basics.Round, participationType account.ParticipationAction) {
	node.accountManager.Record(account, round, participationType)
}

// IsParticipating implements network.NodeInfo
//
// This function is not fully precise. node.ledger and
// node.accountManager might move relative to each other and there is
// no synchronization. This is good-enough for current uses of
// IsParticipating() which is used in networking code to determine if
// the node should ask for transaction gossip (or skip it to save
// bandwidth). The current transaction pool size is about 3
// rounds. Starting to receive transaction gossip 10 rounds in the
// future when we might propose or vote on blocks in that future is a
// little extra buffer but seems reasonable at this time. -- bolson
// 2022-05-18
func (node *AlgorandFullNode) IsParticipating() bool {
	round := node.ledger.Latest() + 1
	return node.accountManager.HasLiveKeys(round, round+10)
}

// SetSyncRound no-ops
func (node *AlgorandFullNode) SetSyncRound(_ basics.Round) error {
	return nil
}

// GetSyncRound returns 0 (not set) in the base node implementation
func (node *AlgorandFullNode) GetSyncRound() basics.Round {
	return 0
}

// UnsetSyncRound no-ops
func (node *AlgorandFullNode) UnsetSyncRound() {
}

// SetBlockTimeStampOffset sets a timestamp offset in the block header.
// This is only available in dev mode.
func (node *AlgorandFullNode) SetBlockTimeStampOffset(offset int64) error {
	if node.devMode {
		node.timestampOffset = &offset
		return nil
	}
	return fmt.Errorf("cannot set block timestamp offset when not in dev mode")
}

// GetBlockTimeStampOffset gets a timestamp offset.
// This is only available in dev mode.
func (node *AlgorandFullNode) GetBlockTimeStampOffset() (*int64, error) {
	if node.devMode {
		return node.timestampOffset, nil
	}
	return nil, fmt.Errorf("cannot get block timestamp offset when not in dev mode")
}

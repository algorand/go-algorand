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

package catchup

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/stateproof"
)

const (
	// noPeersAvailableSleepInterval is the sleep interval that the node would wait if no peers are available to download the next block from.
	// this delay is intended to ensure to give the network package some time to download the list of relays.
	noPeersAvailableSleepInterval = 50 * time.Millisecond
)

// CatchpointCatchupNodeServices defines the external node support needed
// for the catchpoint service to switch the node between "regular" operational mode and catchup mode.
type CatchpointCatchupNodeServices interface {
	SetCatchpointCatchupMode(bool) (newContextCh <-chan context.Context)
}

// CatchpointCatchupStats is used for querying and reporting the current state of the catchpoint catchup process
type CatchpointCatchupStats struct {
	CatchpointLabel    string
	TotalAccounts      uint64
	ProcessedAccounts  uint64
	VerifiedAccounts   uint64
	TotalKVs           uint64
	ProcessedKVs       uint64
	VerifiedKVs        uint64
	TotalBlocks        uint64
	AcquiredBlocks     uint64
	VerifiedBlocks     uint64
	ProcessedBytes     uint64
	TotalAccountHashes uint64
	TotalKVHashes      uint64
	StartTime          time.Time
}

// CatchpointCatchupService represents the catchpoint catchup service.
type CatchpointCatchupService struct {
	// stats is the statistics object, updated async while downloading the ledger
	stats CatchpointCatchupStats
	// statsMu synchronizes access to stats, as we could attempt to update it while querying for its current state
	statsMu deadlock.Mutex
	node    CatchpointCatchupNodeServices
	// ctx is the node cancellation context, used when the node is being stopped.
	ctx           context.Context
	cancelCtxFunc context.CancelFunc
	// running is a waitgroup counting the running goroutine(1), and allow us to exit cleanly.
	running sync.WaitGroup
	// ledgerAccessor is the ledger accessor used to perform ledger-level operation on the database
	ledgerAccessor ledger.CatchpointCatchupAccessor
	// stage is the current stage of the catchpoint catchup process
	stage ledger.CatchpointCatchupState
	// log is the logger object
	log logging.Logger
	// newService indicates whether this service was created after the node was running ( i.e. true ) or the node just started to find that it was previously performing catchup
	newService bool
	// net is the underlying network module
	net network.GossipNode
	// ledger points to the ledger object
	ledger ledger.CatchupAccessorClientLedger
	// lastBlockHeader is the latest block we have before going into catchpoint catchup mode. We use it to serve the node status requests instead of going to the ledger.
	lastBlockHeader bookkeeping.BlockHeader
	// config is a copy of the node configuration
	config config.Local
	// abortCtx used as a synchronized flag to let us know when the user asked us to abort the catchpoint catchup process. note that it's not being used when we decided to abort
	// the catchup due to an internal issue ( such as exceeding number of retries )
	abortCtx     context.Context
	abortCtxFunc context.CancelFunc
	// blocksDownloadPeerSelector is the peer selector used for downloading blocks.
	blocksDownloadPeerSelector peerSelector
}

// MakeResumedCatchpointCatchupService creates a catchpoint catchup service for a node that is already in catchpoint catchup mode
func MakeResumedCatchpointCatchupService(ctx context.Context, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode, accessor ledger.CatchpointCatchupAccessor, cfg config.Local) (service *CatchpointCatchupService, err error) {
	service = &CatchpointCatchupService{
		stats: CatchpointCatchupStats{
			StartTime: time.Now(),
		},
		node:           node,
		ledgerAccessor: accessor,
		log:            log,
		newService:     false,
		net:            net,
		ledger:         accessor.Ledger(),
		config:         cfg,
	}
	l := accessor.Ledger()
	service.lastBlockHeader, err = l.BlockHdr(l.Latest())
	if err != nil {
		return nil, err
	}
	err = service.loadStateVariables(ctx)
	if err != nil {
		return nil, err
	}
	service.initDownloadPeerSelector()
	return service, nil
}

// MakeNewCatchpointCatchupService creates a new catchpoint catchup service for a node that is not in catchpoint catchup mode
func MakeNewCatchpointCatchupService(catchpoint string, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode, accessor ledger.CatchpointCatchupAccessor, cfg config.Local) (service *CatchpointCatchupService, err error) {
	if catchpoint == "" {
		return nil, fmt.Errorf("MakeNewCatchpointCatchupService: catchpoint is invalid")
	}
	service = &CatchpointCatchupService{
		stats: CatchpointCatchupStats{
			CatchpointLabel: catchpoint,
			StartTime:       time.Now(),
		},
		node:           node,
		ledgerAccessor: accessor,
		stage:          ledger.CatchpointCatchupStateInactive,
		log:            log,
		newService:     true,
		net:            net,
		ledger:         accessor.Ledger(),
		config:         cfg,
	}
	l := accessor.Ledger()
	service.lastBlockHeader, err = l.BlockHdr(l.Latest())
	if err != nil {
		return nil, err
	}
	service.initDownloadPeerSelector()
	return service, nil
}

// Start starts the catchpoint catchup service ( continue in the process )
func (cs *CatchpointCatchupService) Start(ctx context.Context) error {
	// Only check catchpoint ledger validity if we're starting new
	if cs.stage == ledger.CatchpointCatchupStateInactive {
		err := cs.checkLedgerDownload()
		if err != nil {
			return fmt.Errorf("aborting catchup Start(): %s", err)
		}
	}
	cs.ctx, cs.cancelCtxFunc = context.WithCancel(ctx)
	cs.abortCtx, cs.abortCtxFunc = context.WithCancel(context.Background())
	cs.running.Add(1)
	go cs.run()
	return nil
}

// Abort aborts the catchpoint catchup process
func (cs *CatchpointCatchupService) Abort() {
	// In order to abort the catchpoint catchup process, we need to first set the flag of abortCtxFunc, and follow that by canceling the main context.
	// The order of these calls is crucial : The various stages are blocked on the main context. When that one expires, it uses the abort context to determine
	// if the cancellation meaning that we want to shut down the process, or aborting the catchpoint catchup completely.
	cs.abortCtxFunc()
	cs.cancelCtxFunc()
}

// Stop stops the catchpoint catchup service - unlike Abort, this is not intended to abort the process but rather to allow
// cleanup of in-memory resources for the purpose of clean shutdown.
func (cs *CatchpointCatchupService) Stop() {
	cs.log.Debug("catchpoint service is stopping")
	defer cs.log.Debug("catchpoint service has stopped")

	// signal the running goroutine that we want to stop
	cs.cancelCtxFunc()
	// wait for the running goroutine to terminate.
	cs.running.Wait()
	// call the abort context canceling, just to release it's goroutine.
	cs.abortCtxFunc()
}

// GetLatestBlockHeader returns the last block header that was available at the time the catchpoint catchup service started
func (cs *CatchpointCatchupService) GetLatestBlockHeader() bookkeeping.BlockHeader {
	return cs.lastBlockHeader
}

// run is the main stage-switching background service function. It switches the current stage into the correct stage handler.
func (cs *CatchpointCatchupService) run() {
	defer cs.running.Done()
	var err error
	for {
		// check if we need to abort.
		select {
		case <-cs.ctx.Done():
			return
		default:
		}

		switch cs.stage {
		case ledger.CatchpointCatchupStateInactive:
			err = cs.processStageInactive()
		case ledger.CatchpointCatchupStateLedgerDownload:
			err = cs.processStageLedgerDownload()
		case ledger.CatchpointCatchupStateLatestBlockDownload:
			err = cs.processStageLatestBlockDownload()
		case ledger.CatchpointCatchupStateBlocksDownload:
			err = cs.processStageBlocksDownload()
		case ledger.CatchpointCatchupStateSwitch:
			err = cs.processStageSwitch()
		default:
			err = cs.abort(fmt.Errorf("unexpected catchpoint catchup stage encountered : %v", cs.stage))
		}

		if cs.ctx.Err() != nil {
			if err != nil {
				cs.log.Warnf("catchpoint catchup stage error : %v", err)
			}
			continue
		}

		if err != nil {
			cs.log.Warnf("catchpoint catchup stage error : %v", err)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// loadStateVariables loads the current stage and catchpoint label from disk. It's used only in the case of catchpoint catchup recovery.
// ( i.e. the node never completed the catchup, and the node was shutdown )
func (cs *CatchpointCatchupService) loadStateVariables(ctx context.Context) (err error) {
	var label string
	label, err = cs.ledgerAccessor.GetLabel(ctx)
	if err != nil {
		return err
	}
	cs.statsMu.Lock()
	cs.stats.CatchpointLabel = label
	cs.statsMu.Unlock()

	cs.stage, err = cs.ledgerAccessor.GetState(ctx)
	if err != nil {
		return err
	}
	return nil
}

// processStageInactive is the first catchpoint stage. It stores the desired label for catching up, so that if the catchpoint catchup is interrupted
// it could be resumed from that point.
func (cs *CatchpointCatchupService) processStageInactive() (err error) {
	cs.statsMu.Lock()
	label := cs.stats.CatchpointLabel
	cs.statsMu.Unlock()
	err = cs.ledgerAccessor.SetLabel(cs.ctx, label)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageInactive failed to set a catchpoint label : %v", err))
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateLedgerDownload)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageInactive failed to update stage : %v", err))
	}
	if cs.newService {
		// we need to let the node know that it should shut down all the unneeded services to avoid clashes.
		cs.updateNodeCatchupMode(true)
	}
	return nil
}

// processStageLedgerDownload is the second catchpoint catchup stage. It downloads the ledger.
func (cs *CatchpointCatchupService) processStageLedgerDownload() error {
	cs.statsMu.Lock()
	label := cs.stats.CatchpointLabel
	cs.statsMu.Unlock()
	round, _, err := ledgercore.ParseCatchpointLabel(label)

	if err != nil {
		return cs.abort(fmt.Errorf("processStageLedgerDownload failed to parse label : %v", err))
	}

	// download balances file.
	lf := makeLedgerFetcher(cs.net, cs.ledgerAccessor, cs.log, cs, cs.config)
	attemptsCount := 0

	for {
		attemptsCount++

		err0 := cs.ledgerAccessor.ResetStagingBalances(cs.ctx, true)
		if err0 != nil {
			if cs.ctx.Err() != nil {
				return cs.stopOrAbort()
			}
			return cs.abort(fmt.Errorf("processStageLedgerDownload failed to reset staging balances : %v", err0))
		}
		psp, err0 := cs.blocksDownloadPeerSelector.getNextPeer()
		if err0 != nil {
			err0 = fmt.Errorf("processStageLedgerDownload: catchpoint catchup was unable to obtain a list of peers to retrieve the catchpoint file from")
			return cs.abort(err0)
		}
		peer := psp.Peer
		start := time.Now()
		err0 = lf.downloadLedger(cs.ctx, peer, round)
		if err0 == nil {
			cs.log.Infof("ledger downloaded from %s in %d seconds", peerAddress(peer), time.Since(start)/time.Second)
			start = time.Now()
			err0 = cs.ledgerAccessor.BuildMerkleTrie(cs.ctx, cs.updateVerifiedCounts)
			if err0 == nil {
				cs.log.Infof("built merkle trie in %d seconds", time.Since(start)/time.Second)
				break
			}
			// failed to build the merkle trie for the above catchpoint file.
			cs.log.Infof("failed to build merkle trie for catchpoint file from %s: %v", peerAddress(peer), err0)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
		} else {
			cs.log.Infof("failed to download catchpoint ledger from peer %s: %v", peerAddress(peer), err0)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankDownloadFailed)
		}

		// instead of testing for err == cs.ctx.Err() , we'll check on the context itself.
		// this is more robust, as the http client library sometimes wrap the context canceled
		// error with other errors.
		if cs.ctx.Err() != nil {
			return cs.stopOrAbort()
		}

		if attemptsCount >= cs.config.CatchupLedgerDownloadRetryAttempts {
			err0 = fmt.Errorf("processStageLedgerDownload: catchpoint catchup exceeded number of attempts to retrieve ledger")
			return cs.abort(err0)
		}
		cs.log.Warnf("unable to download ledger : %v", err0)
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateLatestBlockDownload)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageLedgerDownload failed to update stage to CatchpointCatchupStateLatestBlockDownload : %v", err))
	}
	return nil
}

// updateVerifiedCounts update the user's statistics for the given verified hashes
func (cs *CatchpointCatchupService) updateVerifiedCounts(accountCount, kvCount uint64) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()

	if cs.stats.TotalAccountHashes > 0 {
		cs.stats.VerifiedAccounts = cs.stats.TotalAccounts * accountCount / cs.stats.TotalAccountHashes
	}

	if cs.stats.TotalKVs > 0 {
		cs.stats.VerifiedKVs = kvCount
	}
}

// processStageLatestBlockDownload is the third catchpoint catchup stage. It downloads the latest block and verify that against the previously downloaded ledger.
func (cs *CatchpointCatchupService) processStageLatestBlockDownload() (err error) {
	blockRound, err := cs.ledgerAccessor.GetCatchupBlockRound(cs.ctx)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageLatestBlockDownload failed to retrieve catchup block round : %v", err))
	}

	attemptsCount := 0
	var blk *bookkeeping.Block
	var cert *agreement.Certificate
	// check to see if the current ledger might have this block. If so, we should try this first instead of downloading anything.
	if ledgerBlock, ledgerCert, err0 := cs.ledger.BlockCert(blockRound); err0 == nil {
		blk = &ledgerBlock
		cert = &ledgerCert
	}
	var protoParams config.ConsensusParams
	var ok bool

	for {
		attemptsCount++

		var psp *peerSelectorPeer
		blockDownloadDuration := time.Duration(0)
		if blk == nil {
			var stop bool
			blk, cert, blockDownloadDuration, psp, stop, err = cs.fetchBlock(blockRound, uint64(attemptsCount))
			if stop {
				return err
			} else if blk == nil {
				continue
			}
		}

		// check block protocol version support.
		if protoParams, ok = config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
			cs.log.Warnf("processStageLatestBlockDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol)

			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol))
		}

		// We need to compare explicitly the genesis hash since we're not doing any block validation. This would ensure the genesis.json file matches the block that we've received.
		if protoParams.SupportGenesisHash && blk.GenesisHash() != cs.ledger.GenesisHash() {
			cs.log.Warnf("processStageLatestBlockDownload: genesis hash mismatches : genesis hash on genesis.json file is %v while genesis hash of downloaded block is %v", cs.ledger.GenesisHash(), blk.GenesisHash())
			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload: genesis hash mismatches : genesis hash on genesis.json file is %v while genesis hash of downloaded block is %v", cs.ledger.GenesisHash(), blk.GenesisHash()))
		}

		// check to see that the block header and the block payset aligns
		if !blk.ContentsMatchHeader() {
			cs.log.Warnf("processStageLatestBlockDownload: downloaded block content does not match downloaded block header")

			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload: downloaded block content does not match downloaded block header"))
		}

		// verify that the catchpoint is valid.
		err = cs.ledgerAccessor.VerifyCatchpoint(cs.ctx, blk)
		if err != nil {
			if cs.ctx.Err() != nil {
				return cs.stopOrAbort()
			}
			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				cs.log.Infof("processStageLatestBlockDownload: block %d verification against catchpoint failed, another attempt will be made; err = %v", blockRound, err)
				cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload failed when calling VerifyCatchpoint : %v", err))
		}
		if psp != nil {
			// give a rank to the download, as the download was successful.
			// if the block might have been retrieved from the local ledger, nothing to rank
			peerRank := cs.blocksDownloadPeerSelector.peerDownloadDurationToRank(psp, blockDownloadDuration)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRank)
		}

		err = cs.ledgerAccessor.StoreBalancesRound(cs.ctx, blk)
		if err != nil {
			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload failed when calling StoreBalancesRound : %v", err))
		}

		err = cs.ledgerAccessor.StoreFirstBlock(cs.ctx, blk, cert)
		if err != nil {
			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload failed when calling StoreFirstBlock : %v", err))
		}

		err = cs.updateStage(ledger.CatchpointCatchupStateBlocksDownload)
		if err != nil {
			if attemptsCount <= cs.config.CatchupBlockDownloadRetryAttempts {
				// try again.
				blk = nil
				continue
			}
			return cs.abort(fmt.Errorf("processStageLatestBlockDownload failed to update stage : %v", err))
		}

		// great ! everything is ready for next stage.
		break
	}
	return nil
}

// lookbackForStateproofsSupport calculates the lookback (from topBlock round) needed to be downloaded
// in order to support state proofs verification.
func lookbackForStateproofsSupport(topBlock *bookkeeping.Block) uint64 {
	proto := config.Consensus[topBlock.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		return 0
	}
	lowestStateProofRound := stateproof.GetOldestExpectedStateProof(&topBlock.BlockHeader)
	// in order to be able to confirm/build lowestStateProofRound we would need to reconstruct
	// the corresponding voterForRound which is (lowestStateProofRound - stateproofInterval - VotersLookback)
	lowestStateProofRound = lowestStateProofRound.SubSaturate(basics.Round(proto.StateProofInterval))
	lowestStateProofRound = lowestStateProofRound.SubSaturate(basics.Round(proto.StateProofVotersLookback))
	return uint64(topBlock.Round().SubSaturate(lowestStateProofRound))
}

// processStageBlocksDownload is the fourth catchpoint catchup stage. It downloads all the reminder of the blocks, verifying each one of them against its predecessor.
func (cs *CatchpointCatchupService) processStageBlocksDownload() (err error) {
	topBlock, err := cs.ledgerAccessor.EnsureFirstBlock(cs.ctx)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageBlocksDownload failed, unable to ensure first block : %v", err))
	}

	// pick the lookback with the greatest of
	// either (MaxTxnLife+DeeperBlockHeaderHistory+CatchpointLookback) or MaxBalLookback
	// Explanation:
	// 1. catchpoint snapshots accounts at round X-CatchpointLookback
	// 2. replay starts from X-CatchpointLookback+1
	// 3. transaction evaluation at Y requires block up to MaxTxnLife+DeeperBlockHeaderHistory back from Y
	proto := config.Consensus[topBlock.CurrentProtocol]
	lookback := max(proto.MaxTxnLife+proto.DeeperBlockHeaderHistory+proto.CatchpointLookback, proto.MaxBalLookback)

	lookbackForStateProofSupport := lookbackForStateproofsSupport(&topBlock)
	if lookback < lookbackForStateProofSupport {
		lookback = lookbackForStateProofSupport
	}

	// in case the effective lookback is going before our rounds count, trim it there.
	// ( a catchpoint is generated starting round MaxBalLookback, and this is a possible in any round in the range of MaxBalLookback...MaxTxnLife)
	if lookback >= uint64(topBlock.Round()) {
		lookback = uint64(topBlock.Round() - 1)
	}

	cs.statsMu.Lock()
	cs.stats.TotalBlocks = lookback
	cs.stats.AcquiredBlocks = 0
	cs.stats.VerifiedBlocks = 0
	cs.statsMu.Unlock()

	prevBlock := &topBlock
	blocksFetched := uint64(1) // we already got the first block in the previous step.
	var blk *bookkeeping.Block
	var cert *agreement.Certificate
	for retryCount := uint64(1); blocksFetched <= lookback; {
		if err1 := cs.ctx.Err(); err1 != nil {
			return cs.stopOrAbort()
		}

		blk = nil
		cert = nil
		// check to see if the current ledger might have this block. If so, we should try this first instead of downloading anything.
		if ledgerBlock, ledgerCert, err0 := cs.ledger.BlockCert(topBlock.Round() - basics.Round(blocksFetched)); err0 == nil {
			blk = &ledgerBlock
			cert = &ledgerCert
		} else {
			var errNoEntry ledgercore.ErrNoEntry
			switch {
			case errors.As(err0, &errNoEntry):
				// this is expected, ignore this one.
			default:
				cs.log.Warnf("processStageBlocksDownload encountered the following error when attempting to retrieve the block for round %d : %v", topBlock.Round()-basics.Round(blocksFetched), err0)
			}
		}

		var psp *peerSelectorPeer
		blockDownloadDuration := time.Duration(0)
		if blk == nil {
			var stop bool
			blk, cert, blockDownloadDuration, psp, stop, err = cs.fetchBlock(topBlock.Round()-basics.Round(blocksFetched), retryCount)
			if stop {
				return err
			} else if blk == nil {
				retryCount++
				continue
			}
		}

		cs.updateBlockRetrievalStatistics(1, 0)

		// validate :
		if prevBlock.BlockHeader.Branch != blk.Hash() {
			// not identical, retry download.
			cs.log.Warnf("processStageBlocksDownload downloaded block(%d) did not match it's successor(%d) block hash %v != %v", blk.Round(), prevBlock.Round(), blk.Hash(), prevBlock.BlockHeader.Branch)
			cs.updateBlockRetrievalStatistics(-1, 0)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
			if retryCount <= uint64(cs.config.CatchupBlockDownloadRetryAttempts) {
				// try again.
				retryCount++
				continue
			}
			return cs.abort(fmt.Errorf("processStageBlocksDownload downloaded block(%d) did not match it's successor(%d) block hash %v != %v", blk.Round(), prevBlock.Round(), blk.Hash(), prevBlock.BlockHeader.Branch))
		}

		// check block protocol version support.
		if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
			cs.log.Warnf("processStageBlocksDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol)
			cs.updateBlockRetrievalStatistics(-1, 0)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
			if retryCount <= uint64(cs.config.CatchupBlockDownloadRetryAttempts) {
				// try again.
				retryCount++
				continue
			}
			return cs.abort(fmt.Errorf("processStageBlocksDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol))
		}

		// check to see that the block header and the block payset aligns
		if !blk.ContentsMatchHeader() {
			cs.log.Warnf("processStageBlocksDownload: downloaded block content does not match downloaded block header")
			// try again.
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
			cs.updateBlockRetrievalStatistics(-1, 0)
			if retryCount <= uint64(cs.config.CatchupBlockDownloadRetryAttempts) {
				// try again.
				retryCount++
				continue
			}
			return cs.abort(fmt.Errorf("processStageBlocksDownload: downloaded block content does not match downloaded block header"))
		}

		if psp != nil {
			// the block might have been retrieved from the local ledger, nothing to rank
			cs.updateBlockRetrievalStatistics(0, 1)
			peerRank := cs.blocksDownloadPeerSelector.peerDownloadDurationToRank(psp, blockDownloadDuration)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRank)
		}

		// all good, persist and move on.
		err = cs.ledgerAccessor.StoreBlock(cs.ctx, blk, cert)
		if err != nil {
			cs.log.Warnf("processStageBlocksDownload failed to store downloaded staging block for round %d", blk.Round())
			cs.updateBlockRetrievalStatistics(-1, -1)
			if retryCount <= uint64(cs.config.CatchupBlockDownloadRetryAttempts) {
				// try again.
				retryCount++
				continue
			}
			return cs.abort(fmt.Errorf("processStageBlocksDownload failed to store downloaded staging block for round %d", blk.Round()))
		}
		prevBlock = blk
		blocksFetched++
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateSwitch)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageBlocksDownload failed to update stage : %v", err))
	}
	return nil
}

// fetchBlock uses the internal peer selector blocksDownloadPeerSelector to pick a peer and then attempt to fetch the block requested from that peer.
// The method return stop=true if the caller should exit the current operation
// If the method return a nil block, the caller is expected to retry the operation, increasing the retry counter as needed.
func (cs *CatchpointCatchupService) fetchBlock(round basics.Round, retryCount uint64) (blk *bookkeeping.Block, cert *agreement.Certificate, downloadDuration time.Duration, psp *peerSelectorPeer, stop bool, err error) {
	psp, err = cs.blocksDownloadPeerSelector.getNextPeer()
	if err != nil {
		if errors.Is(err, errPeerSelectorNoPeerPoolsAvailable) {
			cs.log.Infof("fetchBlock: unable to obtain a list of peers to retrieve the latest block from; will retry shortly.")
			// this is a possible on startup, since the network package might have yet to retrieve the list of peers.
			time.Sleep(noPeersAvailableSleepInterval)
			return nil, nil, time.Duration(0), psp, false, nil
		}
		err = fmt.Errorf("fetchBlock: unable to obtain a list of peers to retrieve the latest block from : %w", err)
		return nil, nil, time.Duration(0), psp, true, cs.abort(err)
	}
	peer := psp.Peer

	httpPeer, validPeer := peer.(network.HTTPPeer)
	if !validPeer {
		cs.log.Warnf("fetchBlock: non-HTTP peer was provided by the peer selector")
		cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankInvalidDownload)
		if retryCount <= uint64(cs.config.CatchupBlockDownloadRetryAttempts) {
			// try again.
			return nil, nil, time.Duration(0), psp, false, nil
		}
		return nil, nil, time.Duration(0), psp, true, cs.abort(fmt.Errorf("fetchBlock: recurring non-HTTP peer was provided by the peer selector"))
	}
	fetcher := makeUniversalBlockFetcher(cs.log, cs.net, cs.config)
	blk, cert, downloadDuration, err = fetcher.fetchBlock(cs.ctx, round, httpPeer)
	if err != nil {
		if cs.ctx.Err() != nil {
			return nil, nil, time.Duration(0), psp, true, cs.stopOrAbort()
		}
		if retryCount <= uint64(cs.config.CatchupBlockDownloadRetryAttempts) {
			// try again.
			cs.log.Infof("Failed to download block %d on attempt %d out of %d. %v", round, retryCount, cs.config.CatchupBlockDownloadRetryAttempts, err)
			cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankDownloadFailed)
			return nil, nil, time.Duration(0), psp, false, nil
		}
		return nil, nil, time.Duration(0), psp, true, cs.abort(fmt.Errorf("fetchBlock failed after multiple blocks download attempts"))
	}
	// success
	return blk, cert, downloadDuration, psp, false, nil
}

// processStageSwitch is the fifth catchpoint catchup stage. It completes the catchup process, swap the new tables and restart the node functionality.
func (cs *CatchpointCatchupService) processStageSwitch() (err error) {
	err = cs.ledgerAccessor.CompleteCatchup(cs.ctx)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageSwitch failed to complete catchup : %v", err))
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateInactive)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageSwitch failed to update stage : %v", err))
	}
	cs.updateNodeCatchupMode(false)
	// we've completed the catchup, so we want to cancel the context so that the
	// run function would exit.
	cs.cancelCtxFunc()
	return nil
}

// stopOrAbort is called when any of the stage processing function sees that cs.ctx has been canceled. It can be
// due to the end user attempting to abort the current catchpoint catchup operation or due to a node shutdown.
func (cs *CatchpointCatchupService) stopOrAbort() error {
	if errors.Is(cs.abortCtx.Err(), context.Canceled) {
		return cs.abort(context.Canceled)
	}
	return nil
}

// abort aborts the current catchpoint catchup process, reverting to node to standard operation.
func (cs *CatchpointCatchupService) abort(originatingErr error) error {
	outError := originatingErr
	err0 := cs.ledgerAccessor.ResetStagingBalances(cs.ctx, false)
	if err0 != nil {
		outError = fmt.Errorf("unable to reset staging balances : %v; %v", err0, outError)
	}
	cs.updateNodeCatchupMode(false)
	// we want to abort the catchpoint catchup process, and the node already reverted to normal operation.
	// as part of the returning to normal operation, we've re-created our context. This context need to be
	// canceled so that when we go back to run(), we would exit from there right away.
	cs.cancelCtxFunc()
	return outError
}

// updateStage updates the current catchpoint catchup stage to the provided new stage.
func (cs *CatchpointCatchupService) updateStage(newStage ledger.CatchpointCatchupState) (err error) {
	err = cs.ledgerAccessor.SetState(cs.ctx, newStage)
	if err != nil {
		return err
	}
	cs.stage = newStage
	return nil
}

// updateNodeCatchupMode requests the node to change its operational mode from
// catchup mode to normal mode and vice versa.
func (cs *CatchpointCatchupService) updateNodeCatchupMode(catchupModeEnabled bool) {
	newCtxCh := cs.node.SetCatchpointCatchupMode(catchupModeEnabled)
	select {
	case newCtx, open := <-newCtxCh:
		if open {
			cs.ctx, cs.cancelCtxFunc = context.WithCancel(newCtx)
		}
		// if channel is closed, this means that the node is stopping
	case <-cs.ctx.Done():
		// the node context was canceled before the SetCatchpointCatchupMode goroutine had
		// the chance of completing. We At this point, the service is shutting down. However,
		// we don't know how long it would take for the node mutex until it's become available.
		// given that the SetCatchpointCatchupMode gave us a non-buffered channel, it might get blocked
		// if we won't be draining that channel. To resolve that, we will create another goroutine here
		// which would drain that channel.
		go func() {
			// We'll wait here for the above goroutine to complete :
			<-newCtxCh
		}()
	}
}

func (cs *CatchpointCatchupService) updateLedgerFetcherProgress(fetcherStats *ledger.CatchpointCatchupAccessorProgress) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()
	cs.stats.TotalAccounts = fetcherStats.TotalAccounts
	cs.stats.ProcessedAccounts = fetcherStats.ProcessedAccounts
	cs.stats.TotalKVs = fetcherStats.TotalKVs
	cs.stats.ProcessedKVs = fetcherStats.ProcessedKVs
	cs.stats.ProcessedBytes = fetcherStats.ProcessedBytes
	cs.stats.TotalAccountHashes = fetcherStats.TotalAccountHashes
}

// GetStatistics returns a copy of the current catchpoint catchup statistics
func (cs *CatchpointCatchupService) GetStatistics() (out CatchpointCatchupStats) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()
	out = cs.stats
	return
}

// updateBlockRetrievalStatistics updates the blocks retrieval statistics by applying the provided deltas
func (cs *CatchpointCatchupService) updateBlockRetrievalStatistics(acquiredBlocksDelta, verifiedBlocksDelta int64) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()
	cs.stats.AcquiredBlocks = uint64(int64(cs.stats.AcquiredBlocks) + acquiredBlocksDelta)
	cs.stats.VerifiedBlocks = uint64(int64(cs.stats.VerifiedBlocks) + verifiedBlocksDelta)
}

func (cs *CatchpointCatchupService) initDownloadPeerSelector() {
	cs.blocksDownloadPeerSelector = makeCatchpointPeerSelector(cs.net)
}

// checkLedgerDownload sends a HEAD request to the ledger endpoint of peers to validate the catchpoint's availability
// before actually starting the catchup process.
// The error returned is either from an unsuccessful request or a successful request that did not return a 200.
func (cs *CatchpointCatchupService) checkLedgerDownload() error {
	round, _, err := ledgercore.ParseCatchpointLabel(cs.stats.CatchpointLabel)
	if err != nil {
		return fmt.Errorf("failed to parse catchpoint label : %v", err)
	}
	ledgerFetcher := makeLedgerFetcher(cs.net, cs.ledgerAccessor, cs.log, cs, cs.config)
	for i := 0; i < cs.config.CatchupLedgerDownloadRetryAttempts; i++ {
		psp, peerError := cs.blocksDownloadPeerSelector.getNextPeer()
		if peerError != nil {
			cs.log.Debugf("checkLedgerDownload: error on getNextPeer: %s", peerError.Error())
			return peerError
		}
		err = ledgerFetcher.headLedger(context.Background(), psp.Peer, round)
		if err == nil {
			return nil
		}
		cs.log.Debugf("checkLedgerDownload: failed to headLedger from peer %s: %v", peerAddress(psp.Peer), err)
		// a non-nil error means that the catchpoint is not available, so we should rank it accordingly
		cs.blocksDownloadPeerSelector.rankPeer(psp, peerRankNoCatchpointForRound)
	}
	return fmt.Errorf("checkLedgerDownload(): catchpoint '%s' unavailable from peers: %s", cs.stats.CatchpointLabel, err)
}

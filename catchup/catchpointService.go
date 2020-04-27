// Copyright (C) 2019-2020 Algorand, Inc.
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
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// CatchpointCatchupNodeServices defines the extenal node support needed
// for the catchpoint service to switch the node between "regular" operational mode and catchup mode.
type CatchpointCatchupNodeServices interface {
	SetCatchpointCatchupMode(bool) (newCtx context.Context)
}

// CatchpointCatchupStats is used for querying and reporting the current state of the catchpoint catchup process
type CatchpointCatchupStats struct {
	CatchpointLabel   string
	TotalAccounts     uint64
	ProcessedAccounts uint64
	TotalBlocks       uint64
	DownloadedBlocks  uint64
	VerifiedBlocks    uint64
	ProcessedBytes    uint64
	StartTime         time.Time
}

// CatchpointCatchupService represents the catchpoint catchup service.
type CatchpointCatchupService struct {
	stats          CatchpointCatchupStats
	statsMu        deadlock.Mutex
	node           CatchpointCatchupNodeServices
	ctx            context.Context
	cancelCtxFunc  context.CancelFunc
	running        sync.WaitGroup
	ledgerAccessor *ledger.CatchpointCatchupAccessor
	stage          ledger.CatchpointCatchupState
	log            logging.Logger
	newService     bool // indicates whether this service was created after the node was running ( i.e. true ) or the node just started to find that it was previously perfoming catchup
	net            network.GossipNode
	ledger         *ledger.Ledger
}

const (
	// maxLedgerDownloadAttempts is the number of attempts the catchpoint file will be downloaded and verified. Once we pass that number of attempts
	// the catchpoint catchup is considered to be a failuire, and the node would resume to work as before.
	maxLedgerDownloadAttempts = 50
	// maxBlockDownloadAttempts is the number of block download attempts failuires allows while downloading the blocks. Once we pass that number of attempts
	// the catchpoint catchup is considered to be a failuire, and the node would resume to work as before.
	maxBlockDownloadAttempts = 50
)

// MakeCatchpointCatchupService creates a catchpoint catchup service for a node that is already in catchpoint catchup mode
func MakeCatchpointCatchupService(ctx context.Context, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode, l *ledger.Ledger) (*CatchpointCatchupService, error) {
	service := &CatchpointCatchupService{
		stats: CatchpointCatchupStats{
			StartTime: time.Now(),
		},
		node:           node,
		ledgerAccessor: ledger.MakeCatchpointCatchupAccessor(l, log),
		log:            log,
		newService:     false,
		net:            net,
		ledger:         l,
	}
	err := service.loadStateVariables(ctx)
	if err != nil {
		return nil, err
	}

	return service, nil
}

// MakeNewCatchpointCatchupService creates a new catchpoint catchup service for a node that is not in catchpoint catchup mode
func MakeNewCatchpointCatchupService(catchpoint string, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode, l *ledger.Ledger) (*CatchpointCatchupService, error) {
	service := &CatchpointCatchupService{
		stats: CatchpointCatchupStats{
			CatchpointLabel: catchpoint,
			StartTime:       time.Now(),
		},
		node:           node,
		ledgerAccessor: ledger.MakeCatchpointCatchupAccessor(l, log),
		stage:          ledger.CatchpointCatchupStateInactive,
		log:            log,
		newService:     true,
		net:            net,
		ledger:         l,
	}
	if catchpoint == "" {
		return nil, fmt.Errorf("MakeNewCatchpointCatchupService: catchpoint is invalid")
	}

	return service, nil
}

// Start starts the catchpoint catchup service ( continue in the process )
func (cs *CatchpointCatchupService) Start(ctx context.Context) {
	cs.ctx, cs.cancelCtxFunc = context.WithCancel(ctx)
	cs.running.Add(1)
	go cs.run()
}

// Abort aborts the catchpoint catchup process
func (cs *CatchpointCatchupService) Abort() {
	cs.cancelCtxFunc()
}

// Stop stops the catchpoint catchup service - unlike Abort, this is not intended to abort the process but rather to allow
// cleanup of in-memory resources for the purpose of clean shutdown.
func (cs *CatchpointCatchupService) Stop() {
	// signal the running goroutine that we want to stop
	cs.cancelCtxFunc()
	// wait for the running goroutine to terminate.
	cs.running.Wait()
}

// run is the main stage-swtiching background service function. It switches the current stage into the correct stage handler.
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
		case ledger.CatchpointCatchupStateLastestBlockDownload:
			err = cs.processStageLastestBlockDownload()
		case ledger.CatchpointCatchupStateBlocksDownload:
			err = cs.processStageBlocksDownload()
		case ledger.CatchpointCatchupStateSwitch:
			err = cs.processStageSwitch()
		default:
			err = cs.abort(fmt.Errorf("unexpected catchpoint catchup stage encountered : %v", cs.stage))
		}

		if err != nil {
			if err != cs.ctx.Err() {
				cs.log.Warnf("catchpoint catchup stage error : %v", err)
				time.Sleep(200 * time.Millisecond)
			}
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
		// we need to let the node know that it should shut down all the unneed services to avoid clashes.
		cs.updateNodeCatchupMode(true)
	}
	return nil
}

// processStageLedgerDownload is the second catchpoint catchup stage. It downloads the ledger.
func (cs *CatchpointCatchupService) processStageLedgerDownload() (err error) {
	cs.statsMu.Lock()
	label := cs.stats.CatchpointLabel
	cs.statsMu.Unlock()
	round, _, err0 := ledger.ParseCatchpointLabel(label)

	if err0 != nil {
		return cs.abort(fmt.Errorf("processStageLedgerDownload failed to patse label : %v", err0))
	}

	// download balances file.
	ledgerFetcher := makeLedgerFetcher(cs.net, cs.ledgerAccessor, cs.log, cs)
	attemptsCount := 0

	for {
		attemptsCount++

		err = cs.ledgerAccessor.ResetStagingBalances(cs.ctx, true)
		if err != nil {
			if err == cs.ctx.Err() {
				return cs.abort(err) // we want to keep it with the context error.
			}
			return cs.abort(fmt.Errorf("processStageLedgerDownload failed to reset staging balances : %v", err))
		}
		err = ledgerFetcher.getLedger(cs.ctx, round)
		if err == nil {
			break
		}
		if err == cs.ctx.Err() {
			return cs.abort(err) // we want to keep it with the context error.
		}

		if attemptsCount >= maxLedgerDownloadAttempts {
			err = fmt.Errorf("catchpoint catchup exceeded number of attempts to retrieve ledger")
			return cs.abort(err)
		}
		cs.log.Warnf("unable to download ledger : %v", err)
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateLastestBlockDownload)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageLedgerDownload failed to update stage to CatchpointCatchupStateLastestBlockDownload : %v", err))
	}
	return nil
}

// processStageLedgerDownload is the third catchpoint catchup stage. It downloads the latest block and verify that against the previously downloaded ledger.
func (cs *CatchpointCatchupService) processStageLastestBlockDownload() (err error) {
	blockRound, err := cs.ledgerAccessor.GetCatchupBlockRound(cs.ctx)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed to retrieve catchup block round : %v", err))
	}

	fetcherFactory := MakeNetworkFetcherFactory(cs.net, 10, nil)
	attemptsCount := 0
	var blk *bookkeeping.Block
	var client FetcherClient
	// check to see if the current ledger might have this block. If so, we should try this first instead of downloading anything.
	if ledgerBlock, err := cs.ledger.Block(blockRound); err == nil {
		blk = &ledgerBlock
	}
	for {
		attemptsCount++

		if blk == nil {
			fetcher := fetcherFactory.New()
			blk, _, client, err = fetcher.FetchBlock(cs.ctx, blockRound)
			if err != nil {
				if err == cs.ctx.Err() {
					return cs.abort(err)
				}
				if attemptsCount <= maxBlockDownloadAttempts {
					// try again.
					blk = nil
					continue
				}
				return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed to get block %d : %v", blockRound, err))
			}
			// success
			client.Close()
		}

		// check block protocol version support.
		if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
			cs.log.Warnf("processStageLastestBlockDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol)
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload detected unsupported protocol version in block %d : %v", blk.Round(), blk.BlockHeader.CurrentProtocol))
		}

		// verify that the catchpoint is valid.
		err = cs.ledgerAccessor.VerifyCatchpoint(cs.ctx, blk)
		if err != nil {
			if err == cs.ctx.Err() {
				return cs.abort(err)
			}
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				blk = nil
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed when calling VerifyCatchpoint : %v", err))
		}

		err = cs.ledgerAccessor.StoreFirstBlock(cs.ctx, blk)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				blk = nil
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed when calling StoreFirstBlock : %v", err))
		}

		err = cs.updateStage(ledger.CatchpointCatchupStateBlocksDownload)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				blk = nil
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed to update stage : %v", err))
		}

		// great ! everything is ready for next stage.
		break
	}
	return nil
}

// processStageLedgerDownload is the fourth catchpoint catchup stage. It downloads all the reminder of the blocks, verifying each one of them against it's predecessor.
func (cs *CatchpointCatchupService) processStageBlocksDownload() (err error) {
	topBlock, err := cs.ledgerAccessor.EnsureFirstBlock(cs.ctx)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageBlocksDownload failed, unable to ensure first block : %v", err))
	}

	// pick the lookback with the greater of either MaxTxnLife or MaxBalLookback
	lookback := int(config.Consensus[topBlock.CurrentProtocol].MaxTxnLife)
	if lookback < int(config.Consensus[topBlock.CurrentProtocol].MaxBalLookback) {
		lookback = int(config.Consensus[topBlock.CurrentProtocol].MaxBalLookback)
	}

	cs.statsMu.Lock()
	cs.stats.TotalBlocks = uint64(lookback)
	cs.stats.DownloadedBlocks = 0
	cs.stats.VerifiedBlocks = 0
	cs.statsMu.Unlock()

	prevBlock := &topBlock
	fetcherFactory := MakeNetworkFetcherFactory(cs.net, 10, nil)
	attemptsCount := 0
	blocksFetched := 1 // we already got the first block in the previous step.
	var blk *bookkeeping.Block
	var client FetcherClient
	for blocksFetched <= lookback {
		attemptsCount++

		if err := cs.ctx.Err(); err != nil {
			return cs.abort(err)
		}

		blk = nil
		// check to see if the current ledger might have this block. If so, we should try this first instead of downloading anything.
		if ledgerBlock, err := cs.ledger.Block(topBlock.Round() - basics.Round(blocksFetched)); err == nil {
			blk = &ledgerBlock
		}

		if blk == nil {
			fetcher := fetcherFactory.New()
			blk, _, client, err = fetcher.FetchBlock(cs.ctx, topBlock.Round()-basics.Round(blocksFetched))
			if err != nil {
				if err == cs.ctx.Err() {
					return cs.abort(err)
				}
				if attemptsCount <= maxBlockDownloadAttempts {
					// try again.
					continue
				}
				return cs.abort(fmt.Errorf("processStageBlocksDownload failed after multiple blocks download attempts"))
			}
			// success
			client.Close()
		}

		cs.statsMu.Lock()
		cs.stats.DownloadedBlocks++
		cs.statsMu.Unlock()

		// validate :
		if prevBlock.BlockHeader.Branch != blk.Hash() {
			// not identical, retry download.
			cs.log.Warnf("processStageBlocksDownload downloaded block(%d) did not match it's successor(%d) block hash %v != %v", blk.Round(), prevBlock.Round(), blk.Hash(), prevBlock.BlockHeader.Branch)
			cs.statsMu.Lock()
			cs.stats.DownloadedBlocks--
			cs.statsMu.Unlock()
			continue
		}

		// check block protocol version support.
		if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
			cs.log.Warnf("processStageBlocksDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol)
			return cs.abort(fmt.Errorf("processStageBlocksDownload detected unsupported protocol version in block %d : %v", blk.Round(), blk.BlockHeader.CurrentProtocol))
		}

		cs.statsMu.Lock()
		cs.stats.VerifiedBlocks++
		cs.statsMu.Unlock()

		// all good, persist and move on.
		err = cs.ledgerAccessor.StoreBlock(cs.ctx, blk)
		if err != nil {
			cs.log.Warnf("processStageBlocksDownload failed to store downloaded staging block for round %d", blk.Round())
			cs.statsMu.Lock()
			cs.stats.DownloadedBlocks--
			cs.stats.VerifiedBlocks--
			cs.statsMu.Unlock()
			continue
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

// processStageLedgerDownload is the fifth catchpoint catchup stage. It completes the catchup process, swap the new tables and restart the node functionality.
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

// abort aborts the current catchpoint catchup process, reverting to node to standard operation.
func (cs *CatchpointCatchupService) abort(originatingErr error) error {
	outError := originatingErr
	err0 := cs.ledgerAccessor.ResetStagingBalances(cs.ctx, false)
	if err0 != nil {
		outError = fmt.Errorf("unable to reset staging balances : %v; %v", err0, outError)
	}
	cs.updateNodeCatchupMode(false)
	// we want to abort the catchpoint catchup process, and the node already reverted to normal operation.
	// at this point, all we need to do is to abort the run function.
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

func (cs *CatchpointCatchupService) updateNodeCatchupMode(catchupModeEnabled bool) {
	newCtx := cs.node.SetCatchpointCatchupMode(catchupModeEnabled)
	cs.ctx, cs.cancelCtxFunc = context.WithCancel(newCtx)
}

func (cs *CatchpointCatchupService) updateLedgerFetcherProgress(fetcherStats *ledger.CatchpointCatchupAccessorProgress) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()
	cs.stats.TotalAccounts = fetcherStats.TotalAccounts
	cs.stats.ProcessedAccounts = fetcherStats.ProcessedAccounts
	cs.stats.ProcessedBytes = fetcherStats.ProcessedBytes
}

// GetStatistics returns a copy of the current catchpoint catchup statistics
func (cs *CatchpointCatchupService) GetStatistics() (out CatchpointCatchupStats) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()
	out = cs.stats
	return
}

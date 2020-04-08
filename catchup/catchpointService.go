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
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// CatchpointCatchupNodeServices defines set of functionalities required by the node to be supplied for the catchpoint catchup service.
type CatchpointCatchupNodeServices interface {
	Ledger() *data.Ledger
	SetCatchpointCatchupMode(bool) (newCtx context.Context)
}

// CatchpointCatchupStats is used for querying the current state of the catchpoint catchup process
type CatchpointCatchupStats struct {
	CatchpointLabel   string
	TotalAccounts     uint64
	ProcessedAccounts uint64
	PendingBlocks     uint64
	DownloadedBlocks  uint64
	VerifiedBlocks    uint64
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
}

const (
	maxLedgerDownloadAttempts = 50
	maxBlockDownloadAttempts  = 50
)

// MakeCatchpointCatchupService creates a catchpoint catchup service for a node that is already in catchpoint catchup mode
func MakeCatchpointCatchupService(ctx context.Context, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode) (*CatchpointCatchupService, error) {
	service := &CatchpointCatchupService{
		stats: CatchpointCatchupStats{
			StartTime: time.Now(),
		},
		node:           node,
		ledgerAccessor: ledger.MakeCatchpointCatchupAccessor(node.Ledger().Ledger, log),
		log:            log,
		newService:     false,
		net:            net,
	}
	err := service.loadStateVariables(ctx)
	if err != nil {
		return nil, err
	}

	return service, nil
}

// MakeNewCatchpointCatchupService creates a new catchpoint catchup service for a node that is not in catchpoint catchup mode
func MakeNewCatchpointCatchupService(catchpoint string, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode) (*CatchpointCatchupService, error) {
	service := &CatchpointCatchupService{
		stats: CatchpointCatchupStats{
			CatchpointLabel: catchpoint,
			StartTime:       time.Now(),
		},
		node:           node,
		ledgerAccessor: ledger.MakeCatchpointCatchupAccessor(node.Ledger().Ledger, log),
		stage:          ledger.CatchpointCatchupStateInactive,
		log:            log,
		newService:     true,
		net:            net,
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

}

// Stop stops the catchpoint catchup service - unlike Abort, this is not intended to abort the process but rather to allow
// cleanup of in-memory resources for the purpose of clean shutdown.
func (cs *CatchpointCatchupService) Stop() {
	// signal the running goroutine that we want to stop
	cs.cancelCtxFunc()
	// wait for the running goroutine to terminate.
	cs.running.Wait()
}

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
			return cs.abort(fmt.Errorf("processStageLedgerDownload failed to reset staging balances : %v", err))
		}
		err = ledgerFetcher.getLedger(cs.ctx, round)
		if err == nil {
			break
		}
		if err == cs.ctx.Err() {
			return err // we want to keep it with the context error.
		}

		if attemptsCount >= maxLedgerDownloadAttempts {
			err = fmt.Errorf("catchpoint catchup exceeded number of attempts to retrieve ledger")
			return cs.abort(err)
		}
		cs.log.Infof("unable to download ledger : %v", err)
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateLastestBlockDownload)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageLedgerDownload failed to update stage to CatchpointCatchupStateLastestBlockDownload : %v", err))
	}
	return nil
}

func (cs *CatchpointCatchupService) abort(originatingErr error) error {
	outError := originatingErr
	err0 := cs.ledgerAccessor.ResetStagingBalances(cs.ctx, false)
	if err0 != nil {
		outError = fmt.Errorf("unable to reset staging balances : %v; %v", err0, outError)
	}
	cs.updateNodeCatchupMode(false)
	cs.cancelCtxFunc()
	return outError
}

func (cs *CatchpointCatchupService) processStageLastestBlockDownload() (err error) {
	blockRound, err := cs.ledgerAccessor.GetCatchupBlockRound(cs.ctx)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed to retrieve catchup block round : %v", err))
	}

	fetcherFactory := MakeNetworkFetcherFactory(cs.net, 10, nil)
	attemptsCount := 0
	var blk *bookkeeping.Block
	var client FetcherClient
	for {
		attemptsCount++

		fetcher := fetcherFactory.New()
		blk, _, client, err = fetcher.FetchBlock(cs.ctx, blockRound)
		if err != nil {
			if err == cs.ctx.Err() {
				return err
			}
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed to get block %d : %v", blockRound, err))
		}
		// success
		client.Close()

		// check block protocol version support.
		if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
			cs.log.Warnf("processStageLastestBlockDownload: unsupported protocol version detected: '%v'", blk.BlockHeader.CurrentProtocol)
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload detected unsupported protocol version in block %d : %v", blk.Round(), blk.BlockHeader.CurrentProtocol))
		}

		// verify that the catchpoint is valid.
		err = cs.ledgerAccessor.VerifyCatchpoint(cs.ctx, blk)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed when calling VerifyCatchpoint : %v", err))
		}

		err = cs.ledgerAccessor.StoreFirstBlock(cs.ctx, blk)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed when calling StoreFirstBlock : %v", err))
		}

		err = cs.updateStage(ledger.CatchpointCatchupStateBlocksDownload)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("processStageLastestBlockDownload failed to update stage : %v", err))
		}
		break
	}
	return nil
}

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
	cs.stats.PendingBlocks = uint64(lookback)
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
		fetcher := fetcherFactory.New()
		blk, _, client, err = fetcher.FetchBlock(cs.ctx, topBlock.Round()-basics.Round(blocksFetched))
		if err != nil {
			if err == cs.ctx.Err() {
				return err
			}
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("processStageBlocksDownload failed after multiple blocks download attempts"))
		}
		// success
		client.Close()

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
		cs.statsMu.Lock()
		cs.stats.PendingBlocks--
		cs.statsMu.Unlock()
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateSwitch)
	if err != nil {
		return cs.abort(fmt.Errorf("processStageBlocksDownload failed to update stage : %v", err))
	}
	return nil
}

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
	cs.cancelCtxFunc()
	return nil
}

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
}

// GetStatistics returns a copy of the current statistics
func (cs *CatchpointCatchupService) GetStatistics() (out CatchpointCatchupStats) {
	cs.statsMu.Lock()
	defer cs.statsMu.Unlock()
	out = cs.stats
	return
}

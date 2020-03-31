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

// CatchpointCatchupService represents the catchpoint catchup service.
type CatchpointCatchupService struct {
	CatchpointLabel string
	node            CatchpointCatchupNodeServices
	ctx             context.Context
	cancelCtxFunc   context.CancelFunc
	running         sync.WaitGroup
	ledgerAccessor  *ledger.CatchpointCatchupAccessor
	stage           ledger.CatchpointCatchupState
	log             logging.Logger
	newService      bool // indicates whether this service was created after the node was running ( i.e. true ) or the node just started to find that it was previously perfoming catchup
	net             network.GossipNode
}

const (
	maxLedgerDownloadAttempts = 50
	maxBlockDownloadAttempts  = 50
)

// MakeCatchpointCatchupService creates a catchpoint catchup service for a node that is already in catchpoint catchup mode
func MakeCatchpointCatchupService(ctx context.Context, node CatchpointCatchupNodeServices, log logging.Logger, net network.GossipNode) (*CatchpointCatchupService, error) {
	service := &CatchpointCatchupService{
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
		CatchpointLabel: catchpoint,
		node:            node,
		ledgerAccessor:  ledger.MakeCatchpointCatchupAccessor(node.Ledger().Ledger, log),
		stage:           ledger.CatchpointCatchupStateInactive,
		log:             log,
		newService:      true,
		net:             net,
	}
	if catchpoint == "" {
		return nil, fmt.Errorf("MakeNewCatchpointCatchupService: catchpoint is invalid")
	}

	return service, nil
}

// Start starts the catchpoint catchup service ( continue in the process )
func (cs *CatchpointCatchupService) Start(ctx context.Context) {
	fmt.Printf("Starting catchpoint catchup %s\n", cs.CatchpointLabel)
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
	defer fmt.Printf("catchpoint catchup %s - aborted main run loop\n", cs.CatchpointLabel)
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
			cs.log.Warnf("unexpected catchpoint catchup stage encountered : %v", cs.stage)
			// todo - abort..
		}

		if err != nil {
			if err != cs.ctx.Err() {
				cs.log.Warnf("catchpoint catchup stage error : %v", err)
				fmt.Printf("CatchpointCatchupService::run error, stage = %d err = %v\n", cs.stage, err)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}

func (cs *CatchpointCatchupService) loadStateVariables(ctx context.Context) (err error) {
	cs.CatchpointLabel, err = cs.ledgerAccessor.GetLabel(ctx)
	if err != nil {
		return err
	}
	cs.stage, err = cs.ledgerAccessor.GetState(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("catchpoint label : %s\n", cs.CatchpointLabel)
	return nil
}

func (cs *CatchpointCatchupService) processStageInactive() (err error) {
	err = cs.ledgerAccessor.SetLabel(cs.ctx, cs.CatchpointLabel)
	if err != nil {
		return err
	}
	err = cs.updateStage(ledger.CatchpointCatchupStateLedgerDownload)
	if err != nil {
		return err
	}
	if cs.newService {
		// we need to let the node know that it should shut down all the unneed services to avoid clashes.
		cs.updateNodeCatchupMode(true)
	}
	return nil
}

func (cs *CatchpointCatchupService) processStageLedgerDownload() (err error) {
	fmt.Printf("processStageLedgerDownload\n")
	round, _, _ := ledger.ParseCatchpointLabel(cs.CatchpointLabel)

	// download balances file.
	ledgerFetcher := makeLedgerFetcher(cs.net, cs.ledgerAccessor, cs.log)
	attemptsCount := 0

	for {
		attemptsCount++

		err = cs.ledgerAccessor.ResetStagingBalances(cs.ctx, true)
		if err != nil {
			return err
		}
		err = ledgerFetcher.getLedger(cs.ctx, round)
		if err == nil {
			break
		}
		if err == cs.ctx.Err() {
			return err
		}

		if attemptsCount >= maxLedgerDownloadAttempts {
			err = fmt.Errorf("catchpoint catchup exceeded number of attempts to retrieve ledger")
			return cs.abort(err)
		}
		cs.log.Infof("unable to download ledger : %v", err)
		fmt.Printf("unable to download ledger : %v\n", err)
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateLastestBlockDownload)
	if err != nil {
		return err
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
		return fmt.Errorf("GetCatchupBlockRound failed : %v", err)
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

		err = cs.ledgerAccessor.VerifyCatchpoint(cs.ctx, blk)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("VerifyCatchpoint failed : %v", err))
		}

		err = cs.ledgerAccessor.StoreFirstBlock(cs.ctx, blk)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("StoreFirstBlock failed : %v", err))
		}

		err = cs.updateStage(ledger.CatchpointCatchupStateBlocksDownload)
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return cs.abort(fmt.Errorf("updateStage failed : %v", err))
		}
		break
	}
	return nil
}

func (cs *CatchpointCatchupService) processStageBlocksDownload() (err error) {
	topBlock, err := cs.ledgerAccessor.EnsureFirstBlock(cs.ctx)
	if err != nil {
		return err
	}

	lookback := int(config.Consensus[topBlock.CurrentProtocol].MaxBalLookback)
	prevBlock := &topBlock
	fetcherFactory := MakeNetworkFetcherFactory(cs.net, 10, nil)
	attemptsCount := 0
	blocksFetched := 1 // we already got the first block in the previous step.
	var blk *bookkeeping.Block
	var client FetcherClient
	for blocksFetched < lookback {
		attemptsCount++
		fetcher := fetcherFactory.New()
		blk, _, client, err = fetcher.FetchBlock(cs.ctx, topBlock.Round()-basics.Round(blocksFetched))
		if err != nil {
			if attemptsCount <= maxBlockDownloadAttempts {
				// try again.
				continue
			}
			return err
		}
		// success
		client.Close()

		// validate :
		if prevBlock.BlockHeader.Branch != blk.Hash() {
			// not identical, retry download.
			continue
		}
		// all good, persist and move on.
		err = cs.ledgerAccessor.StoreBlock(cs.ctx, blk)
		if err != nil {
			// todo log
			continue
		}
		prevBlock = blk
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateSwitch)
	if err != nil {
		return err
	}
	return nil
}

func (cs *CatchpointCatchupService) processStageSwitch() (err error) {
	err = cs.ledgerAccessor.CompleteCatchup(cs.ctx)
	if err != nil {
		return err
	}

	err = cs.updateStage(ledger.CatchpointCatchupStateInactive)
	if err != nil {
		return err
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

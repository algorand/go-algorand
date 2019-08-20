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
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

const catchupPeersForSync = 10

// Ledger represents the interface of a block database which the
// catchup server should interact with.
type Ledger interface {
	NextRound() basics.Round
	LastRound() basics.Round
	Wait(basics.Round) chan struct{}
	AddBlock(bookkeeping.Block, agreement.Certificate) error
	ConsensusParams(basics.Round) (config.ConsensusParams, error)

	// only needed to support tests
	Block(basics.Round) (bookkeeping.Block, error)
	BlockCert(basics.Round) (bookkeeping.Block, agreement.Certificate, error)
}

// Service represents the catchup service. Once started and until it is stopped, it ensures that the ledger is up to date with network.
type Service struct {
	syncStartNS     int64 // at top of struct to keep 64 bit aligned for atomic.* ops
	cfg             config.Local
	ledger          Ledger
	fetcherFactory  rpcs.FetcherFactory
	ctx             context.Context
	cancel          func()
	done            chan struct{}
	log             logging.Logger
	net             network.GossipNode
	auth            BlockAuthenticator
	parallelBlocks  uint64
	deadlineTimeout time.Duration

	// The channel gets closed when the initial sync is complete. This allows for other services to avoid
	// the overhead of starting prematurely (before this node is caught-up and can validate messages for example).
	InitialSyncDone     chan struct{}
	initialSyncNotified uint32
	protocolErrorLogged bool
}

// A BlockAuthenticator authenticates blocks given a certificate.
//
// Note that Authenticate does not check if the block contents match
// their header as it only checks the block header.  If the contents
// have not been checked yet, callers should also call
// block.ContentsMatchHeader and reject blocks that do not pass this
// check.
type BlockAuthenticator interface {
	Authenticate(*bookkeeping.Block, *agreement.Certificate) error
	Quit()
}

// MakeService creates a catchup service instance from its constituent components
// If wsf is nil, then fetch over gossip is disabled.
func MakeService(log logging.Logger, config config.Local, net network.GossipNode, ledger Ledger, wsf *rpcs.WsFetcherService, auth BlockAuthenticator) (s *Service) {
	s = &Service{}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.cfg = config
	s.fetcherFactory = rpcs.MakeNetworkFetcherFactory(net, catchupPeersForSync, wsf)
	s.ledger = ledger
	s.net = net
	s.auth = auth

	s.log = log.With("Context", "sync")
	s.InitialSyncDone = make(chan struct{})
	s.parallelBlocks = config.CatchupParallelBlocks
	s.deadlineTimeout = agreement.DeadlineTimeout()
	return s
}

// Start the catchup service
func (s *Service) Start() {
	s.done = make(chan struct{})
	go s.periodicSync()
}

// Stop informs the catchup service that it should stop, and waits for it to stop (when periodicSync() exits)
func (s *Service) Stop() {
	s.cancel()
	<-s.done
	if atomic.CompareAndSwapUint32(&s.initialSyncNotified, 0, 1) {
		close(s.InitialSyncDone)
	}
	s.auth.Quit()
}

// IsSynchronizing returns true if we're currently executing a sync() call - either initial catchup
// or attempting to catchup after too-long waiting for next block.
// Also returns a 2nd bool indicating if this is our initial sync
func (s *Service) IsSynchronizing() (synchronizing bool, initialSync bool) {
	synchronizing = atomic.LoadInt64(&s.syncStartNS) != 0
	initialSync = atomic.LoadUint32(&s.initialSyncNotified) == 0
	return
}

// SynchronizingTime returns the time we've been performing a catchup operation (0 if not currently catching up)
func (s *Service) SynchronizingTime() time.Duration {
	startNS := atomic.LoadInt64(&s.syncStartNS)
	if startNS == 0 {
		return time.Duration(0)
	}
	timeInNS := time.Now().UnixNano()
	return time.Duration(timeInNS - startNS)
}

// function scope to make a bunch of defer statements better
func (s *Service) innerFetch(fetcher rpcs.Fetcher, r basics.Round) (blk *bookkeeping.Block, cert *agreement.Certificate, rpcc rpcs.FetcherClient, err error) {
	ctx, cf := context.WithTimeout(s.ctx, rpcs.DefaultFetchTimeout)
	defer cf()
	stopWaitingForLedgerRound := make(chan struct{})
	defer close(stopWaitingForLedgerRound)
	go func() {
		select {
		case <-stopWaitingForLedgerRound:
		case <-s.ledger.Wait(r):
			cf()
		}
	}()
	return fetcher.FetchBlock(ctx, r)
}

// fetchAndWrite fetches a block, checks the cert, and writes it to the ledger. Cert checking and ledger writing both wait for the ledger to advance if necessary.
// Returns false if we couldn't fetch or write (i.e., if we failed even after a given number of retries or if we were told to abort.)
func (s *Service) fetchAndWrite(fetcher rpcs.Fetcher, r basics.Round, prevFetchCompleteChan chan bool, lookbackComplete chan bool) bool {
	i := 0
	hasLookback := false
	for !fetcher.OutOfPeers(r) {
		i++
		select {
		case <-s.ctx.Done():
			s.log.Debugf("fetchAndWrite(%v): Aborted", r)
			return false
		default:
		}

		// Try to fetch, timing out after retryInterval

		block, cert, client, err := s.innerFetch(fetcher, r)

		if err != nil {
			s.log.Debugf("fetchAndWrite(%v): Could not fetch: %v (attempt %d)", r, err, i)
			// we've just failed to retrieve a block; wait until the previous block is fetched before trying again
			// to avoid the usecase where the first block doesn't exists and we're making many requests down the chain
			// for no reason.
			if !hasLookback {
				select {
				case <-s.ctx.Done():
					s.log.Debugf("fetchAndWrite(%v): Aborted while waiting for lookback block to ledger after failing once", r)
					return false
				case hasLookback = <-lookbackComplete:
					if !hasLookback {
						s.log.Debugf("fetchAndWrite(%v): lookback block doesn't exist, won't try to retrieve block again", r)
						return false
					}
				}
			}
			continue // retry the fetch
		} else if block == nil || cert == nil {
			// someone already wrote the block to the ledger, we should stop syncing
			return false
		}
		s.log.Debugf("fetchAndWrite(%v): Got block and cert contents: %v %v", r, block, cert)

		// Check that the block's contents match the block header (necessary with an untrusted block because b.Hash() only hashes the header)
		if !block.ContentsMatchHeader() {
			s.log.Warnf("fetchAndWrite(%v): block contents do not match header (attempt %d)", r, i)
			client.Close()
			continue // retry the fetch
		}

		// make sure that we have the lookBack block that's required for authenticating this block
		if !hasLookback {
			select {
			case <-s.ctx.Done():
				s.log.Debugf("fetchAndWrite(%v): Aborted while waiting for lookback block to ledger", r)
				return false
			case hasLookback = <-lookbackComplete:
				if !hasLookback {
					s.log.Warnf("fetchAndWrite(%v): lookback block doesn't exist, cannot authenticate new block", r)
					return false
				}
			}
		}

		err = s.auth.Authenticate(block, cert)
		if err != nil {
			s.log.Warnf("fetchAndWrite(%v): cert did not authenticate block (attempt %d): %v", r, i, err)
			client.Close()
			continue // retry the fetch
		}

		// Write to ledger, noting that ledger writes must be in order
		select {
		case <-s.ctx.Done():
			s.log.Debugf("fetchAndWrite(%v): Aborted while waiting to write to ledger", r)
			return false
		case prevFetchSuccess := <-prevFetchCompleteChan:
			if prevFetchSuccess {
				err := s.ledger.AddBlock(*block, *cert)
				if err != nil {
					switch err.(type) {
					case ledger.BlockInLedgerError:
						s.log.Debugf("fetchAndWrite(%v): block already in ledger", r)
						return true
					case ledger.ProtocolError:
						if !s.protocolErrorLogged {
							logging.Base().Errorf("fetchAndWrite(%v): unrecoverable protocol error detected: %v", r, err)
							s.protocolErrorLogged = true
						}
					default:
						s.log.Errorf("fetchAndWrite(%v): ledger write failed: %v", r, err)
					}

					return false
				}
				s.log.Debugf("fetchAndWrite(%v): Wrote block to ledger", r)
				return true
			}
			s.log.Warnf("fetchAndWrite(%v): previous block doesn't exist (perhaps fetching block %v failed)", r, r-1)
			return false
		}
	}
	return false
}

type task func() basics.Round

func (s *Service) pipelineCallback(fetcher rpcs.Fetcher, r basics.Round, thisFetchComplete chan bool, prevFetchCompleteChan chan bool, lookbackChan chan bool) func() basics.Round {
	return func() basics.Round {
		fetchResult := s.fetchAndWrite(fetcher, r, prevFetchCompleteChan, lookbackChan)

		// the fetch result will be read at most twice (once as the lookback block and once as the prev block, so we write the result twice)
		thisFetchComplete <- fetchResult
		thisFetchComplete <- fetchResult

		if !fetchResult {
			s.log.Infof("failed to fetch block %v", r)
			return 0
		}
		return r
	}
}

// TODO the following code does not handle the following case: seedLookback upgrades during fetch
func (s *Service) pipelinedFetch(seedLookback uint64) {
	fetcher := s.fetcherFactory.NewOverGossip(protocol.UniCatchupReqTag)
	defer fetcher.Close()

	// make sure that we have at least one peer
	if fetcher.NumPeers() == 0 {
		return
	}

	parallelRequests := s.parallelBlocks
	if parallelRequests < seedLookback {
		parallelRequests = seedLookback
	}

	completed := make(chan basics.Round, parallelRequests)
	taskCh := make(chan task, parallelRequests)
	var wg sync.WaitGroup

	defer func() {
		close(taskCh)
		wg.Wait()
		close(completed)
	}()

	// Invariant: len(taskCh) + (# pending writes to completed) <= N
	wg.Add(int(parallelRequests))
	for i := uint64(0); i < parallelRequests; i++ {
		go func() {
			defer wg.Done()
			for t := range taskCh {
				completed <- t() // This write to completed comes after a read from taskCh, so the invariant is preserved.
			}
		}()
	}

	recentReqs := make([]chan bool, 0)
	for i := 0; i < int(seedLookback); i++ {
		// the fetch result will be read at most twice (once as the lookback block and once as the prev block, so we write the result twice)
		reqComplete := make(chan bool, 2)
		reqComplete <- true
		reqComplete <- true
		recentReqs = append(recentReqs, reqComplete)
	}

	from := s.ledger.NextRound()
	nextRound := from
	for ; nextRound < from+basics.Round(parallelRequests); nextRound++ {
		currentRoundComplete := make(chan bool, 2)
		// len(taskCh) + (# pending writes to completed) increases by 1
		taskCh <- s.pipelineCallback(fetcher, nextRound, currentRoundComplete, recentReqs[len(recentReqs)-1], recentReqs[len(recentReqs)-int(seedLookback)])
		recentReqs = append(recentReqs[1:], currentRoundComplete)
	}

	completedRounds := make(map[basics.Round]bool)
	// the rest
	for {
		select {
		case round := <-completed:
			if round == 0 {
				// there was an error
				return
			}
			completedRounds[round] = true
			// fetch rounds we can validate
			for completedRounds[nextRound-basics.Round(parallelRequests)] {
				delete(completedRounds, nextRound)
				currentRoundComplete := make(chan bool, 2)
				// len(taskCh) + (# pending writes to completed) increases by 1
				taskCh <- s.pipelineCallback(fetcher, nextRound, currentRoundComplete, recentReqs[len(recentReqs)-1], recentReqs[0])
				recentReqs = append(recentReqs[1:], currentRoundComplete)
				nextRound++
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// periodicSync periodically asks the network for its latest round and syncs if we've fallen behind (also if our ledger stops advancing)
func (s *Service) periodicSync() {
	defer close(s.done)

	// wait until network is ready, or until we're told to quit
	select {
	case <-s.net.Ready():
		s.log.Info("network ready")
	case <-s.ctx.Done():
		return
	}
	s.sync()
	stuckInARow := 0
	sleepDuration := s.deadlineTimeout
	for {
		currBlock := s.ledger.LastRound()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ledger.Wait(currBlock + 1):
			// Ledger moved forward; likely to be by the agreement service.
			stuckInARow = 0
			// go to sleep for a short while, for a random duration.
			// we want to sleep for a random duration since it would "de-syncronize" us from the ledger advance sync
			sleepDuration = time.Duration(crypto.RandUint63()) % s.deadlineTimeout
			continue
		case <-time.After(sleepDuration):
			if sleepDuration < s.deadlineTimeout {
				sleepDuration = s.deadlineTimeout
				continue
			}
			s.log.Info("It's been too long since our ledger advanced; resyncing")
			s.sync()
		}

		if currBlock == s.ledger.LastRound() {
			stuckInARow++
		} else {
			stuckInARow = 0
		}
		if stuckInARow == s.cfg.CatchupFailurePeerRefreshRate {
			stuckInARow = 0
			// TODO: RequestConnectOutgoing in terms of Context
			s.net.RequestConnectOutgoing(true, s.ctx.Done())
		}
	}
}

// Syncs the client with the network. sync asks the network for last known block and tries to sync the system
// up the to the highest number it gets
func (s *Service) sync() {
	// Only run sync once at a time
	// Store start time of sync - in NS so we can compute time.Duration (which is based on NS)
	start := time.Now()
	timeInNS := start.UnixNano()
	if !atomic.CompareAndSwapInt64(&s.syncStartNS, 0, timeInNS) {
		s.log.Infof("previous sync from %d still running (now=%d)", atomic.LoadInt64(&s.syncStartNS), timeInNS)
		return
	}
	defer atomic.StoreInt64(&s.syncStartNS, 0)

	pr := s.ledger.LastRound()

	s.log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.CatchupStartEvent, telemetryspec.CatchupStartEventDetails{
		StartRound: uint64(pr),
	})

	seedLookback := uint64(2)
	proto, err := s.ledger.ConsensusParams(pr)
	if err != nil {
		s.log.Errorf("catchup: could not get consensus parameters for round %v: $%v", pr, err)
	} else {
		seedLookback = proto.SeedLookback
	}
	s.pipelinedFetch(seedLookback)

	initSync := false

	// close the initial sync channel if not already close
	if atomic.CompareAndSwapUint32(&s.initialSyncNotified, 0, 1) {
		close(s.InitialSyncDone)
		initSync = true
	}

	elapsedTime := time.Now().Sub(start)
	s.log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.CatchupStopEvent, telemetryspec.CatchupStopEventDetails{
		StartRound: uint64(pr),
		EndRound:   uint64(s.ledger.LastRound()),
		Time:       elapsedTime,
		InitSync:   initSync,
	})

	s.log.Infof("Catchup Service: finished catching up, now at round %v (previously %v). Total time catching up %v.", s.ledger.LastRound(), pr, elapsedTime)
}

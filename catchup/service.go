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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

// uncapParallelDownloadRate is a simple threshold to detect whether the node is caught up.
// If a block is downloaded in less than this duration, it's assumed that the node is not caught up
// and allow the block downloader to start N=parallelBlocks concurrent fetches.
const uncapParallelDownloadRate = time.Second

// this should be at least the number of relays
const catchupRetryLimit = 500

const followLatestBackoff = 100 * time.Millisecond

// ErrSyncRoundInvalid is returned when the sync round requested is behind the current ledger round
var ErrSyncRoundInvalid = errors.New("requested sync round cannot be less than the latest round")

// PendingUnmatchedCertificate is a single certificate that is being waited upon to have its corresponding block fetched.
type PendingUnmatchedCertificate struct {
	Cert         agreement.Certificate
	VoteVerifier *agreement.AsyncVoteVerifier
}

// Ledger represents the interface of a block database which the
// catchup server should interact with.
type Ledger interface {
	agreement.LedgerReader
	AddBlock(bookkeeping.Block, agreement.Certificate) error
	EnsureBlock(block *bookkeeping.Block, c agreement.Certificate)
	LastRound() basics.Round
	Block(basics.Round) (bookkeeping.Block, error)
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	IsWritingCatchpointDataFile() bool
	IsBehindCommittingDeltas() bool
	Validate(ctx context.Context, blk bookkeeping.Block, executionPool execpool.BacklogPool) (*ledgercore.ValidatedBlock, error)
	AddValidatedBlock(vb ledgercore.ValidatedBlock, cert agreement.Certificate) error
	WaitMem(r basics.Round) chan struct{}
}

// Service represents the catchup service. Once started and until it is stopped, it ensures that the ledger is up-to-date with network.
type Service struct {
	// disableSyncRound, provided externally, is the first round we will _not_ fetch from the network
	// any round >= disableSyncRound will not be fetched. If set to 0, it will be disregarded.
	disableSyncRound    atomic.Uint64
	syncStartNS         atomic.Int64
	cfg                 config.Local
	ledger              Ledger
	ctx                 context.Context
	cancel              func()
	workers             sync.WaitGroup
	log                 logging.Logger
	net                 network.GossipNode
	auth                BlockAuthenticator
	parallelBlocks      uint64
	roundTimeEstimate   time.Duration
	prevBlockFetchTime  time.Time
	blockValidationPool execpool.BacklogPool

	// followLatest is set to true if this is a follower node: meaning there is no
	// agreement service to follow the latest round, so catchup continuously runs,
	// polling for new blocks as they appear. This enables a different behavior
	// to avoid aborting the catchup service once you get to the tip of the chain.
	followLatest bool

	// suspendForLedgerOps defines whether we've run into a state where the ledger is currently busy writing the
	// catchpoint file or flushing accounts. If so, we want to suspend the catchup process until the catchpoint file writing is complete,
	// and resume from there without stopping the catchup timer.
	suspendForLedgerOps bool

	// The channel gets closed when the initial sync is complete. This allows for other services to avoid
	// the overhead of starting prematurely (before this node is caught-up and can validate messages for example).
	InitialSyncDone              chan struct{}
	initialSyncNotified          atomic.Uint32
	protocolErrorLogged          bool
	unmatchedPendingCertificates <-chan PendingUnmatchedCertificate
	// This channel signals periodSync to attempt catchup immediately. This allows us to start fetching rounds from
	// the network as soon as disableSyncRound is modified.
	syncNow chan struct{}

	// onceUnsupportedRound ensures that we start just one
	// unsupportedRoundMonitor goroutine, after detecting
	// an unsupported block.
	onceUnsupportedRound sync.Once
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
func MakeService(log logging.Logger, config config.Local, net network.GossipNode, ledger Ledger, auth BlockAuthenticator, unmatchedPendingCertificates <-chan PendingUnmatchedCertificate, blockValidationPool execpool.BacklogPool) (s *Service) {
	s = &Service{}

	s.cfg = config
	s.followLatest = s.cfg.EnableFollowMode
	s.ledger = ledger
	s.net = net
	s.auth = auth
	s.unmatchedPendingCertificates = unmatchedPendingCertificates
	s.log = log.With("Context", "sync")
	s.parallelBlocks = config.CatchupParallelBlocks
	s.roundTimeEstimate = agreement.DefaultDeadlineTimeout()
	s.blockValidationPool = blockValidationPool
	s.syncNow = make(chan struct{}, 1)

	return s
}

// Start the catchup service
func (s *Service) Start() {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.initialSyncNotified.Store(0)
	s.InitialSyncDone = make(chan struct{})
	s.workers.Add(1)
	go s.periodicSync()
}

// Stop informs the catchup service that it should stop, and waits for it to stop (when periodicSync() exits)
func (s *Service) Stop() {
	s.log.Debug("catchup service is stopping")
	defer s.log.Debug("catchup service has stopped")

	s.cancel()
	s.workers.Wait()
	if s.initialSyncNotified.CompareAndSwap(0, 1) {
		close(s.InitialSyncDone)
	}
}

// IsSynchronizing returns true if we're currently executing a sync() call - either initial catchup
// or attempting to catchup after too-long waiting for next block.
// Also returns a 2nd bool indicating if this is our initial sync
func (s *Service) IsSynchronizing() (synchronizing bool, initialSync bool) {
	synchronizing = s.syncStartNS.Load() != 0
	initialSync = s.initialSyncNotified.Load() == 0
	return
}

// triggerSync attempts to wake up the sync loop.
func (s *Service) triggerSync() {
	// Prevents deadlock if periodic sync isn't running
	// when catchup is setting the sync round.
	select {
	case s.syncNow <- struct{}{}:
	default:
	}
}

// SetDisableSyncRound attempts to set the first round we _do_not_ want to fetch from the network
// Blocks from disableSyncRound or any round after disableSyncRound will not be fetched while this is set
func (s *Service) SetDisableSyncRound(rnd basics.Round) error {
	if rnd < s.ledger.LastRound() {
		return ErrSyncRoundInvalid
	}
	s.disableSyncRound.Store(uint64(rnd))
	s.triggerSync()
	return nil
}

// UnsetDisableSyncRound removes any previously set disabled sync round
func (s *Service) UnsetDisableSyncRound() {
	s.disableSyncRound.Store(0)
	s.triggerSync()
}

// GetDisableSyncRound returns the disabled sync round
func (s *Service) GetDisableSyncRound() basics.Round {
	return basics.Round(s.disableSyncRound.Load())
}

// SynchronizingTime returns the time we've been performing a catchup operation (0 if not currently catching up)
func (s *Service) SynchronizingTime() time.Duration {
	startNS := s.syncStartNS.Load()
	if startNS == 0 {
		return time.Duration(0)
	}
	timeInNS := time.Now().UnixNano()
	return time.Duration(timeInNS - startNS)
}

// errLedgerAlreadyHasBlock is returned by innerFetch in case the local ledger already has the requested block.
var errLedgerAlreadyHasBlock = errors.New("ledger already has block")

// function scope to make a bunch of defer statements better
func (s *Service) innerFetch(ctx context.Context, r basics.Round, peer network.Peer) (blk *bookkeeping.Block, cert *agreement.Certificate, ddur time.Duration, err error) {
	ledgerWaitCh := s.ledger.WaitMem(r)
	select {
	case <-ledgerWaitCh:
		// if our ledger already have this block, no need to attempt to fetch it.
		return nil, nil, time.Duration(0), errLedgerAlreadyHasBlock
	default:
	}

	ctx, cf := context.WithCancel(ctx)
	fetcher := makeUniversalBlockFetcher(s.log, s.net, s.cfg)
	defer cf()
	go func() {
		select {
		case <-ctx.Done():
		case <-ledgerWaitCh:
			cf()
		}
	}()
	blk, cert, ddur, err = fetcher.fetchBlock(ctx, r, peer)
	// check to see if we aborted due to ledger.
	if err != nil {
		select {
		case <-ledgerWaitCh:
			// yes, we aborted since the ledger received this round.
			err = errLedgerAlreadyHasBlock
		default:
		}
	}
	return
}

const errNoBlockForRoundThreshold = 5

// fetchAndWrite fetches a block, checks the cert, and writes it to the ledger. Cert checking and ledger writing both wait for the ledger to advance if necessary.
// Returns false if we should stop trying to catch up.  This may occur for several reasons:
//   - If the context is canceled (e.g. if the node is shutting down)
//   - If we couldn't fetch the block (e.g. if there are no peers available, or we've reached the catchupRetryLimit)
//   - If the block is already in the ledger (e.g. if agreement service has already written it)
//   - If the retrieval of the previous block was unsuccessful
func (s *Service) fetchAndWrite(ctx context.Context, r basics.Round, prevFetchCompleteChan chan struct{}, lookbackComplete chan struct{}, peerSelector peerSelector) bool {
	// If sync-ing this round is not intended, don't fetch it
	if dontSyncRound := s.GetDisableSyncRound(); dontSyncRound != 0 && r >= basics.Round(dontSyncRound) {
		return false
	}

	// peerErrors tracks occurrences of errNoBlockForRound in order to quit earlier without making
	// repeated requests for a block that most likely does not exist yet
	peerErrors := map[network.Peer]int{}

	i := 0
	for {
		i++
		select {
		case <-ctx.Done():
			s.log.Debugf("fetchAndWrite(%d): Aborted", r)
			return false
		default:
		}

		// Stop retrying after a while.
		if i > catchupRetryLimit {
			loggedMessage := fmt.Sprintf("fetchAndWrite(%d): block retrieval exceeded retry limit", r)
			if _, initialSync := s.IsSynchronizing(); initialSync {
				// on the initial sync, it's completly expected that we won't be able to get all the "next" blocks.
				// Therefore, info should suffice.
				s.log.Info(loggedMessage)
			} else {
				// On any subsequent sync, we might be looking for multiple rounds into the future, so it's completely
				// reasonable that we would fail retrieving the future block.
				// Generate a warning here only if we're failing to retrieve X+1 or below.
				// All other block retrievals should not generate a warning.
				if r > s.ledger.NextRound() {
					s.log.Info(loggedMessage)
				} else {
					s.log.Warn(loggedMessage)
				}
			}
			return false
		}

		psp, getPeerErr := peerSelector.getNextPeer()
		if getPeerErr != nil {
			s.log.Debugf("fetchAndWrite(%d): was unable to obtain a peer to retrieve the block from: %v", r, getPeerErr)
			return false
		}
		peer := psp.Peer
		s.log.Debugf("fetchAndWrite(%d): got %s peer: %s", r, psp.peerClass, peerAddress(peer))

		// Try to fetch, timing out after retryInterval
		block, cert, blockDownloadDuration, err := s.innerFetch(ctx, r, peer)

		if err != nil {
			if errors.Is(err, errLedgerAlreadyHasBlock) {
				// ledger already has the block, no need to request this block.
				// only the agreement could have added this block into the ledger, catchup is complete
				s.log.Infof("fetchAndWrite(%d): the block is already in the ledger. The catchup is complete", r)
				return false
			}
			failureRank := peerRankDownloadFailed
			var nbfe noBlockForRoundError
			if errors.As(err, &nbfe) {
				failureRank = peerRankNoBlockForRound
				// remote peer doesn't have the block, try another peer
				// quit if the same peer encountered errNoBlockForRound more than errNoBlockForRoundThreshold times
				if s.followLatest {
					// back off between retries to allow time for the next block to appear;
					// this will provide 50s (catchupRetryLimit * followLatestBackoff) of
					// polling when continuously running catchup instead of agreement.
					time.Sleep(followLatestBackoff)
				} else {
					if count := peerErrors[peer]; count > errNoBlockForRoundThreshold {
						s.log.Infof("fetchAndWrite(%d): remote peers do not have the block. Quitting", r)
						return false
					}
					peerErrors[peer]++
				}
			}
			s.log.Debugf("fetchAndWrite(%d): Could not fetch: %v (attempt %d), peer %s", r, err, i, peerAddress(psp.Peer))
			o, n := peerSelector.rankPeer(psp, failureRank)
			s.log.Debugf("fetchAndWrite(%d): Could not fetch: ranked peer %s with %d from %d to %d", r, peerAddress(psp.Peer), failureRank, o, n)

			// we've just failed to retrieve a block; wait until the previous block is fetched before trying again
			// to avoid the usecase where the first block doesn't exist, and we're making many requests down the chain
			// for no reason.
			select {
			case <-ctx.Done():
				s.log.Infof("fetchAndWrite(%d): Aborted while waiting for lookback block to ledger", r)
				return false
			case <-lookbackComplete:
			}
			continue // retry the fetch
		} else if block == nil || cert == nil {
			// someone already wrote the block to the ledger, we should stop syncing
			return false
		}
		s.log.Debugf("fetchAndWrite(%d): Got block and cert contents: %v %v", r, block, cert)

		// Check that the block's contents match the block header (necessary with an untrusted block because b.Hash() only hashes the header)
		if s.cfg.CatchupVerifyPaysetHash() {
			if !block.ContentsMatchHeader() {
				peerSelector.rankPeer(psp, peerRankInvalidDownload)
				// Check if this mismatch is due to an unsupported protocol version
				if _, ok := config.Consensus[block.BlockHeader.CurrentProtocol]; !ok {
					s.log.Errorf("fetchAndWrite(%d): unsupported protocol version detected: '%v'", r, block.BlockHeader.CurrentProtocol)
					return false
				}

				s.log.Warnf("fetchAndWrite(%d): block contents do not match header (attempt %d)", r, i)
				continue // retry the fetch
			}
		}

		// make sure that we have the lookBack block that's required for authenticating this block
		select {
		case <-ctx.Done():
			s.log.Debugf("fetchAndWrite(%d): Aborted while waiting for lookback block to ledger", r)
			return false
		case <-lookbackComplete:
		}

		if s.cfg.CatchupVerifyCertificate() {
			err = s.auth.Authenticate(block, cert)
			if err != nil {
				s.log.Warnf("fetchAndWrite(%d): cert did not authenticate block (attempt %d): %v", r, i, err)
				peerSelector.rankPeer(psp, peerRankInvalidDownload)
				continue // retry the fetch
			}
		}

		peerRank := peerSelector.peerDownloadDurationToRank(psp, blockDownloadDuration)
		r1, r2 := peerSelector.rankPeer(psp, peerRank)
		s.log.Debugf("fetchAndWrite(%d): ranked peer %s with %d from %d to %d", r, peerAddress(psp.Peer), peerRank, r1, r2)

		// Write to ledger, noting that ledger writes must be in order
		select {
		case <-ctx.Done():
			s.log.Debugf("fetchAndWrite(%d): Aborted while waiting to write to ledger", r)
			return false
		case <-prevFetchCompleteChan:
			// make sure the ledger wrote enough of the account data to disk, since we don't want the ledger to hold a large amount of data in memory.
			proto, err := s.ledger.ConsensusParams(r.SubSaturate(1))
			if err != nil {
				s.log.Errorf("fetchAndWrite(%d): Unable to determine consensus params for round %d: %v", r, r-1, err)
				return false
			}
			ledgerBacklogRound := r.SubSaturate(basics.Round(proto.MaxBalLookback))
			select {
			case <-s.ledger.Wait(ledgerBacklogRound):
				// i.e. round r-320 is no longer in the blockqueue, so it's account data is either being currently written, or it was already written.
			case <-s.ctx.Done():
				s.log.Debugf("fetchAndWrite(%d): Aborted while waiting for ledger to complete writing up to round %d", r, ledgerBacklogRound)
				return false
			}

			if s.cfg.CatchupVerifyTransactionSignatures() || s.cfg.CatchupVerifyApplyData() {
				var vb *ledgercore.ValidatedBlock
				vb, err = s.ledger.Validate(s.ctx, *block, s.blockValidationPool)
				if err != nil {
					if s.ctx.Err() != nil {
						// if the context expired, just exit.
						return false
					}
					var errNSBE ledgercore.ErrNonSequentialBlockEval
					if errors.As(err, &errNSBE) && errNSBE.EvaluatorRound <= errNSBE.LatestRound {
						// the block was added to the ledger from elsewhere after fetching it here
						// only the agreement could have added this block into the ledger, catchup is complete
						s.log.Infof("fetchAndWrite(%d): after fetching the block, it is already in the ledger. The catchup is complete", r)
						return false
					}
					s.log.Warnf("fetchAndWrite(%d): failed to validate block : %v", r, err)
					return false
				}
				err = s.ledger.AddValidatedBlock(*vb, *cert)
			} else {
				err = s.ledger.AddBlock(*block, *cert)
			}

			if err != nil {
				var errNonSequentialBlockEval ledgercore.ErrNonSequentialBlockEval
				var blockInLedgerError ledgercore.BlockInLedgerError
				var protocolErr protocol.Error
				switch {
				case errors.As(err, &errNonSequentialBlockEval):
					s.log.Infof("fetchAndWrite(%d): no need to re-evaluate historical block", r)
					return true
				case errors.As(err, &blockInLedgerError):
					// the block was added to the ledger from elsewhere after fetching it here
					// only the agreement could have added this block into the ledger, catchup is complete
					s.log.Infof("fetchAndWrite(%d): after fetching the block, it is already in the ledger. The catchup is complete", r)
					return false
				case errors.As(err, &protocolErr):
					if !s.protocolErrorLogged {
						logging.Base().Errorf("fetchAndWrite(%d): unrecoverable protocol error detected: %v", r, err)
						s.protocolErrorLogged = true
					}
				default:
					s.log.Errorf("fetchAndWrite(%d): ledger write failed: %v", r, err)
				}

				return false
			}
			s.log.Debugf("fetchAndWrite(%d): Wrote block to ledger", r)
			return true
		}
	}
}

// TODO the following code does not handle the following case: seedLookback upgrades during fetch
func (s *Service) pipelinedFetch(seedLookback uint64) {
	maxParallelRequests := max(s.parallelBlocks, seedLookback)
	minParallelRequests := seedLookback

	// Start the limited requests at max(1, 'seedLookback')
	limitedParallelRequests := max(1, seedLookback)

	completed := make(map[basics.Round]chan bool)
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		for _, ch := range completed {
			close(ch)
		}
	}()

	ps := createPeerSelector(s.net)
	if _, err := ps.getNextPeer(); err != nil {
		s.log.Debugf("pipelinedFetch: was unable to obtain a peer to retrieve the block from: %v", err)
		return
	}

	// Create a new context for canceling the pipeline if some block
	// fetch fails along the way.
	ctx, cancelCtx := context.WithCancel(s.ctx)
	defer cancelCtx()

	// firstRound is the first round we're waiting to fetch.
	firstRound := s.ledger.NextRound()

	// nextRound is the next round that we will issue a fetch for.
	nextRound := firstRound

	for {
		// launch N=parallelRequests block download go routines.
		for nextRound < firstRound+basics.Round(limitedParallelRequests) {
			if s.roundIsNotSupported(nextRound) {
				// Break out of the loop to avoid fetching
				// blocks that we don't support.  If there
				// are no more supported blocks to fetch,
				// s.unsupportedRoundMonitor() will cancel
				// s.ctx and cause this function to return.
				break
			}

			done := make(chan bool, 1)
			completed[nextRound] = done

			wg.Add(1)
			go func(r basics.Round) {
				prev := s.ledger.WaitMem(r - 1)
				seed := s.ledger.WaitMem(r.SubSaturate(basics.Round(seedLookback)))
				done <- s.fetchAndWrite(ctx, r, prev, seed, ps)
				wg.Done()
			}(nextRound)

			nextRound++
		}

		// wait for the first round to complete before starting the next download.
		select {
		case completedOK := <-completed[firstRound]:
			delete(completed, firstRound)
			firstRound++

			if !completedOK {
				// there was an error; defer will cancel the pipeline
				s.log.Debugf("pipelinedFetch: quitting on fetchAndWrite error (firstRound=%d, nextRound=%d)", firstRound-1, nextRound)
				return
			}

			fetchTime := time.Now()
			fetchDur := fetchTime.Sub(s.prevBlockFetchTime)
			s.prevBlockFetchTime = fetchTime
			if fetchDur < uncapParallelDownloadRate {
				limitedParallelRequests = maxParallelRequests
			} else {
				limitedParallelRequests = minParallelRequests
			}

			// if ledger is busy, pause for some time to let the fetchAndWrite goroutines to finish fetching in-flight blocks.
			start := time.Now()
			for (s.ledger.IsWritingCatchpointDataFile() || s.ledger.IsBehindCommittingDeltas()) && time.Since(start) < s.roundTimeEstimate {
				time.Sleep(100 * time.Millisecond)
			}

			// if ledger is still busy after s.roundTimeEstimate timeout then abort the current pipelinedFetch invocation.

			// if we're writing a catchpoint file, stop catching up to reduce the memory pressure. Once we finish writing the file we
			// could resume with the catchup.
			if s.ledger.IsWritingCatchpointDataFile() {
				s.log.Info("Catchup is stopping due to catchpoint file being written")
				s.suspendForLedgerOps = true
				return
			}

			// if the ledger has too many non-flushed account changes, stop catching up to reduce the memory pressure.
			if s.ledger.IsBehindCommittingDeltas() {
				s.log.Info("Catchup is stopping due to too many non-flushed account changes")
				s.suspendForLedgerOps = true
				return
			}

		case <-s.ctx.Done():
			s.log.Debugf("pipelinedFetch: Aborted (firstRound=%d, nextRound=%d)", firstRound, nextRound)
			return
		}
	}
}

// unsupportedRoundMonitor waits for the ledger to get stuck at an unsupported
// protocol upgrade (i.e., the next block requires upgrading to a protocol that
// the current node does not support), and stops the catchup service when that
// happens.
func (s *Service) unsupportedRoundMonitor() {
	defer s.workers.Done()
	for {
		nextRound := s.ledger.NextRound()
		if s.roundIsNotSupported(nextRound) {
			s.log.Infof("Catchup Service: finished catching up to the last supported round %d. The subsequent rounds are not supported. Service is stopping.",
				nextRound-1)
			s.cancel()
		}

		select {
		case <-s.ctx.Done():
			return
		case <-s.ledger.WaitMem(nextRound):
		}
	}
}

// periodicSync periodically asks the network for its latest round and syncs if we've fallen behind (also if our ledger stops advancing)
func (s *Service) periodicSync() {
	defer s.workers.Done()
	// if the catchup is disabled in the config file, just skip it.
	if s.parallelBlocks != 0 && !s.cfg.DisableNetworking {
		// The following request might be redundant, but it ensures we wait long enough for the DNS records to be loaded,
		// which are required for the sync operation.
		s.net.RequestConnectOutgoing(false, s.ctx.Done())
		s.sync()
	}
	stuckInARow := 0
	sleepDuration := s.roundTimeEstimate
	for {
		currBlock := s.ledger.LastRound()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ledger.WaitMem(currBlock + 1):
			// Ledger moved forward; likely to be by the agreement service.
			stuckInARow = 0
			// go to sleep for a short while, for a random duration.
			// we want to sleep for a random duration since it would "de-syncronize" us from the ledger advance sync
			sleepDuration = time.Duration(crypto.RandUint63()) % s.roundTimeEstimate
			continue
		case <-s.syncNow:
			if s.parallelBlocks == 0 || s.ledger.IsWritingCatchpointDataFile() || s.ledger.IsBehindCommittingDeltas() {
				continue
			}
			s.suspendForLedgerOps = false
			s.log.Info("Immediate resync triggered; resyncing")
			s.sync()
		case <-time.After(sleepDuration):
			if sleepDuration < s.roundTimeEstimate || s.cfg.DisableNetworking {
				sleepDuration = s.roundTimeEstimate
				continue
			}
			// if the catchup is disabled in the config file, just skip it.
			if s.parallelBlocks == 0 {
				continue
			}
			// check to see if we're currently writing a catchpoint file. If so, wait longer before attempting again.
			if s.ledger.IsWritingCatchpointDataFile() {
				// keep the existing sleep duration and try again later.
				continue
			}
			// if the ledger has too many non-flushed account changes, skip
			if s.ledger.IsBehindCommittingDeltas() {
				continue
			}

			s.suspendForLedgerOps = false
			s.log.Info("It's been too long since our ledger advanced; resyncing")
			s.sync()
		case cert := <-s.unmatchedPendingCertificates:
			// the agreement service has a valid certificate for a block, but not the block itself.
			if s.cfg.DisableNetworking {
				s.log.Warnf("the local node is missing block %d, however, the catchup would not be able to provide it when the network is disabled.", cert.Cert.Round)
				continue
			}
			s.syncCert(&cert)
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
// up to the highest number it gets.
func (s *Service) sync() {
	// Only run sync once at a time
	// Store start time of sync - in NS, so we can compute time.Duration (which is based on NS)
	start := time.Now()

	timeInNS := start.UnixNano()
	if !s.syncStartNS.CompareAndSwap(0, timeInNS) {
		s.log.Infof("resuming previous sync from %d (now=%d)", s.syncStartNS.Load(), timeInNS)
	}

	pr := s.ledger.LastRound()

	s.log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.CatchupStartEvent, telemetryspec.CatchupStartEventDetails{
		StartRound: uint64(pr),
	})

	seedLookback := uint64(2)
	proto, err := s.ledger.ConsensusParams(pr)
	if err != nil {
		s.log.Errorf("catchup: could not get consensus parameters for round %v: %v", pr, err)
	} else {
		seedLookback = proto.SeedLookback
	}
	s.pipelinedFetch(seedLookback)

	initSync := false

	// if the catchupWriting flag is set, it means that we aborted the sync due to the ledger writing the catchup file.
	if !s.suspendForLedgerOps {
		// in that case, don't change the timer so that the "timer" would keep running.
		s.syncStartNS.Store(0)

		// close the initial sync channel if not already close
		if s.initialSyncNotified.CompareAndSwap(0, 1) {
			close(s.InitialSyncDone)
			initSync = true
		}
	}

	elapsedTime := time.Since(start)
	s.log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.CatchupStopEvent, telemetryspec.CatchupStopEventDetails{
		StartRound: uint64(pr),
		EndRound:   uint64(s.ledger.LastRound()),
		Time:       elapsedTime,
		InitSync:   initSync,
	})
	s.log.Infof("Catchup Service: finished catching up, now at round %v (previously %v). Total time catching up %v.", s.ledger.LastRound(), pr, elapsedTime)
}

// syncCert retrieving a single round identified by the provided certificate and adds it to the ledger.
// The sync function attempts to keep trying to fetch the matching block or abort when the catchup service exits.
func (s *Service) syncCert(cert *PendingUnmatchedCertificate) {
	// we want to fetch a single round. no need to be concerned about lookback.
	s.fetchRound(cert.Cert, cert.VoteVerifier)
}

// TODO this doesn't actually use the digest from cert!
func (s *Service) fetchRound(cert agreement.Certificate, verifier *agreement.AsyncVoteVerifier) {
	// is there any point attempting to retrieve the block ?
	if s.roundIsNotSupported(cert.Round) {
		// we might get here if the agreement service was seeing the certs votes for the next
		// block, without seeing the actual block. Since it hasn't seen the block, it couldn't
		// tell that it's an unsupported protocol, and would try to request it from the catchup.
		return
	}

	peerErrors := map[network.Peer]int{}

	blockHash := bookkeeping.BlockHash(cert.Proposal.BlockDigest) // semantic digest (i.e., hash of the block header), not byte-for-byte digest
	ps := createPeerSelector(s.net)
	for s.ledger.LastRound() < cert.Round {
		psp, getPeerErr := ps.getNextPeer()
		if getPeerErr != nil {
			s.log.Debugf("fetchRound: was unable to obtain a peer to retrieve the block from: %s", getPeerErr)
			select {
			case <-s.ctx.Done():
				logging.Base().Debugf("fetchRound was asked to quit while collecting peers")
				return
			default:
			}

			s.net.RequestConnectOutgoing(true, s.ctx.Done())
			continue
		}
		peer := psp.Peer

		// Ask the fetcher to get the block somehow
		block, fetchedCert, _, err := s.innerFetch(s.ctx, cert.Round, peer)

		if err != nil {
			select {
			case <-s.ctx.Done():
				logging.Base().Debugf("fetchRound was asked to quit before we could acquire the block")
				return
			default:
			}
			failureRank := peerRankDownloadFailed
			var nbfe noBlockForRoundError
			if errors.As(err, &nbfe) {
				failureRank = peerRankNoBlockForRound
				// If a peer does not have the block after few attempts it probably has not persisted the block yet.
				// Give it some time to persist the block and try again.
				// Note, there is no exit condition on too many retries as per the function contract.
				if count, ok := peerErrors[peer]; ok {
					if count > errNoBlockForRoundThreshold {
						time.Sleep(50 * time.Millisecond)
					}
					if count > errNoBlockForRoundThreshold*10 {
						// for the low number of connected peers (like 2) the following scenario is possible:
						// - both peers do not have the block
						// - peer selector punishes one of the peers more than the other
						// - the punished peer gets the block, and the less punished peer stuck.
						// It this case reset the peer selector to let it re-learn priorities.
						ps = createPeerSelector(s.net)
					}
				}
				peerErrors[peer]++
			}
			// remote peer doesn't have the block, try another peer
			logging.Base().Warnf("fetchRound could not acquire block, fetcher errored out: %v", err)
			ps.rankPeer(psp, failureRank)
			continue
		}

		if block.Hash() == blockHash && block.ContentsMatchHeader() {
			s.ledger.EnsureBlock(block, cert)
			return
		}
		// Otherwise, fetcher gave us the wrong block
		logging.Base().Warnf("fetcher gave us bad/wrong block (for round %d): fetched hash %v; want hash %v", cert.Round, block.Hash(), blockHash)
		ps.rankPeer(psp, peerRankInvalidDownload)

		// As a failsafe, if the cert we fetched is valid but for the wrong block, panic as loudly as possible
		if cert.Round == fetchedCert.Round &&
			cert.Proposal.BlockDigest != fetchedCert.Proposal.BlockDigest &&
			fetchedCert.Authenticate(*block, s.ledger, verifier) == nil {
			var builder strings.Builder
			builder.WriteString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
			builder.WriteString("!!!!!!!!!! FORK DETECTED !!!!!!!!!!!\n")
			builder.WriteString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
			builder.WriteString("fetchRound called with a cert authenticating block with hash %v.\n")
			builder.WriteString("We fetched a valid cert authenticating a different block, %v. This indicates a fork.\n\n")
			builder.WriteString("Cert from our agreement service:\n%#v\n\n")
			builder.WriteString("Cert from the fetcher:\n%#v\n\n")
			builder.WriteString("Block from the fetcher:\n%#v\n\n")
			builder.WriteString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
			builder.WriteString("!!!!!!!!!! FORK DETECTED !!!!!!!!!!!\n")
			builder.WriteString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
			s := builder.String()
			s = fmt.Sprintf(s, cert.Proposal.BlockDigest, fetchedCert.Proposal.BlockDigest, cert, fetchedCert, block)
			fmt.Println(s)
			logging.Base().Error(s)
		}
	}
}

// roundIsNotSupported returns whether, according to the ledger's
// latest block, nextRound requires upgrading to a protocol version
// that the current node does not support.
func (s *Service) roundIsNotSupported(nextRound basics.Round) bool {
	lastLedgerRound := s.ledger.LastRound()
	bh, err := s.ledger.BlockHdr(lastLedgerRound)
	if err != nil {
		s.log.Errorf("roundIsNotSupported: could not retrieve last block (%d) from the ledger : %v", lastLedgerRound, err)
		return false
	}

	if bh.NextProtocolSwitchOn == 0 {
		return false
	}

	supportedUpgrades := config.Consensus
	_, isSupportedUpgrade := supportedUpgrades[bh.NextProtocol]
	if isSupportedUpgrade {
		return false
	}

	if nextRound < bh.NextProtocolSwitchOn {
		return false
	}

	s.log.Infof("Catchup Service: round %d is not approved, requires upgrading to unsupported %s in round %d. Service will stop once the last supported round is added to the ledger.", nextRound, bh.NextProtocol, bh.NextProtocolSwitchOn)

	s.onceUnsupportedRound.Do(func() {
		s.workers.Add(1)
		go s.unsupportedRoundMonitor()
	})

	return true
}

func createPeerSelector(net peersRetriever) peerSelector {
	wrappedPeerSelectors := []*wrappedPeerSelector{
		{
			peerClass: network.PeersConnectedOut,
			peerSelector: makeRankPooledPeerSelector(net,
				[]peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut}}),
			toleranceFactor: 3,
		},
		{
			peerClass: network.PeersPhonebookRelays,
			peerSelector: makeRankPooledPeerSelector(net,
				[]peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookRelays}}),
			toleranceFactor: 3,
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: makeRankPooledPeerSelector(net,
				[]peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes}}),
			toleranceFactor: 10,
		},
		{
			peerClass: network.PeersConnectedIn,
			peerSelector: makeRankPooledPeerSelector(net,
				[]peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedIn}}),
			toleranceFactor: 3,
		},
	}

	return makeClassBasedPeerSelector(wrappedPeerSelectors)
}
